-- SYSOP-AI: esquema SQLite (motor relacional primário).
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- 1. Eventos brutos (alto volume, retenção de 60 dias; purge agrega antes de apagar)
CREATE TABLE IF NOT EXISTS raw_events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,                 -- epoch UTC
    source      TEXT    NOT NULL CHECK (source IN ('auditd','journald','fail2ban','ufw','aide')),
    host        TEXT    NOT NULL DEFAULT '',
    unit        TEXT    NOT NULL DEFAULT '',
    event_type  TEXT    NOT NULL DEFAULT '',
    src_ip      TEXT,                             -- dado pessoal (LGPD)
    user        TEXT,                             -- controlado pelo atacante!
    raw         TEXT    NOT NULL CHECK (length(raw) <= 2000),
    label       TEXT    NOT NULL DEFAULT 'normal'
                CHECK (label IN ('normal','minor','bruteforce','critical')),
    label_score REAL,
    labeler     TEXT    NOT NULL DEFAULT 'rule',  -- rule | bert | manual
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS ix_raw_ip_ts    ON raw_events (src_ip, ts);
CREATE INDEX IF NOT EXISTS ix_raw_ts       ON raw_events (ts);
CREATE INDEX IF NOT EXISTS ix_raw_label_ts ON raw_events (label, ts) WHERE label <> 'normal';
CREATE INDEX IF NOT EXISTS ix_raw_incident ON raw_events (incident_id) WHERE incident_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS collector_cursor (
    source TEXT PRIMARY KEY,
    cursor TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 2. Incidentes (agregação DETERMINÍSTICA por código, não por LLM)
CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY,
    opened_at    INTEGER NOT NULL,
    closed_at    INTEGER,
    kind         TEXT    NOT NULL,
    severity     TEXT    NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    src_ip       TEXT,
    n_events     INTEGER NOT NULL DEFAULT 0,
    first_ts     INTEGER,
    last_ts      INTEGER,
    status       TEXT    NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open','analyzed','pending_approval','mitigated','failed','closed')),
    summary      TEXT,
    UNIQUE (kind, src_ip, opened_at)
);
CREATE INDEX IF NOT EXISTS ix_inc_status ON incidents (status, opened_at);

-- 3. Ações do agente: auditoria + fila de aprovação humana
CREATE TABLE IF NOT EXISTS agent_actions (
    id           INTEGER PRIMARY KEY,
    ts           INTEGER NOT NULL,
    incident_id  INTEGER REFERENCES incidents(id),
    tool         TEXT    NOT NULL,
    args_json    TEXT    NOT NULL,
    confidence   REAL,
    reason       TEXT,                            -- texto do LLM: NÃO confiável na UI
    status       TEXT    NOT NULL DEFAULT 'proposed'
                 CHECK (status IN ('proposed','pending','approved','rejected','executed','verified','failed')),
    approved_by  TEXT,
    approved_at  INTEGER,
    result       TEXT,
    verified     INTEGER CHECK (verified IN (0,1)),
    CHECK (status NOT IN ('approved','executed','verified') OR approved_by IS NOT NULL OR tool NOT IN ('ban_ip_fail2ban'))
);
CREATE INDEX IF NOT EXISTS ix_act_status ON agent_actions (status, ts);

-- Trilha append-only
CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    actor   TEXT    NOT NULL,                     -- agent | collector | admin:<nome>
    event   TEXT    NOT NULL,
    detail  TEXT    NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log é append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log é append-only'); END;

-- Redes que NUNCA podem ser bloqueadas (o master é o gateway da LAN)
CREATE TABLE IF NOT EXISTS protected_networks (
    cidr TEXT PRIMARY KEY,
    note TEXT
);
INSERT OR IGNORE INTO protected_networks VALUES
    ('10.10.0.0/24',   'LAN do cluster (D4)'),
    ('192.168.0.1/32', 'roteador'),
    ('127.0.0.0/8',    'loopback'),
    ('::1/128',        'loopback v6');

-- 4. Registro de tools (inclusive as geradas pelo agente) com aprovação humana
CREATE TABLE IF NOT EXISTS tool_registry (
    name          TEXT    NOT NULL,
    version       INTEGER NOT NULL,
    source        TEXT    NOT NULL,
    source_sha256 TEXT    NOT NULL,
    origin        TEXT    NOT NULL DEFAULT 'agent' CHECK (origin IN ('builtin','agent','human')),
    status        TEXT    NOT NULL DEFAULT 'proposed'
                  CHECK (status IN ('proposed','ast_rejected','sandbox_failed','sandbox_ok','approved','rejected','revoked')),
    ast_report    TEXT,
    sandbox_report TEXT,
    proposed_at   INTEGER NOT NULL,
    approved_by   TEXT,
    approved_at   INTEGER,
    PRIMARY KEY (name, version)
);
CREATE TRIGGER IF NOT EXISTS tool_needs_human BEFORE UPDATE OF status ON tool_registry
WHEN NEW.status = 'approved' AND (NEW.approved_by IS NULL OR NEW.approved_by IN ('','agent') OR OLD.status <> 'sandbox_ok')
BEGIN SELECT RAISE(ABORT, 'aprovação exige humano e sandbox_ok'); END;
CREATE TRIGGER IF NOT EXISTS tool_source_immutable BEFORE UPDATE OF source, source_sha256 ON tool_registry
BEGIN SELECT RAISE(ABORT, 'código da tool é imutável; crie nova versão'); END;

-- 5. Resumos em lote, custo de LLM e agregados (retenção)
CREATE TABLE IF NOT EXISTS summaries (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL,
    window_start INTEGER NOT NULL, window_end INTEGER NOT NULL,
    n_incidents INTEGER NOT NULL, text TEXT NOT NULL, model TEXT
);
CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, purpose TEXT NOT NULL,
    tokens_in INTEGER, tokens_out INTEGER, seconds REAL, ok INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_aggregates (
    day TEXT NOT NULL, src_ip TEXT NOT NULL DEFAULT '', event_type TEXT NOT NULL, label TEXT NOT NULL,
    n INTEGER NOT NULL, PRIMARY KEY (day, src_ip, event_type, label)
);

-- Purge diário (systemd timer, passo de deploy): agrega e depois apaga brutos > 60 dias.
--   INSERT INTO daily_aggregates SELECT date(ts,'unixepoch'), coalesce(src_ip,''), event_type, label, count(*)
--     FROM raw_events WHERE ts < strftime('%s','now','-60 day') GROUP BY 1,2,3,4
--     ON CONFLICT(day,src_ip,event_type,label) DO UPDATE SET n = n + excluded.n;
--   DELETE FROM raw_events WHERE ts < strftime('%s','now','-60 day');
--   PRAGMA wal_checkpoint(TRUNCATE);

-- 6. Memória semântica: texto curado; os vetores ficam em mem_vec (criada em db.py, 1024 dim = bge-m3)
CREATE TABLE IF NOT EXISTS mem_docs (
    id          INTEGER PRIMARY KEY,                -- = rowid em mem_vec
    kind        TEXT NOT NULL CHECK (kind IN ('incident','resolution','kb')),
    incident_id INTEGER REFERENCES incidents(id),
    text        TEXT NOT NULL CHECK (length(text) <= 1200),
    content_sha TEXT NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
);
