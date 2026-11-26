#!/usr/bin/env python3
"""collector.py: o coletor passa a RETOMAR de onde parou (defeito encontrado no deploy, passo 14).

Defeito: `journalctl --cursor-file` só grava o cursor ao TERMINAR; o coletor é parado por sinal e o arquivo nunca
aparecia, então tudo que acontecia com o coletor fora do ar (reinício, reboot) se perdia.

Correção: o cursor (campo __CURSOR de cada entrada) é guardado no banco (tabela collector_cursor, que já existia no
esquema e não era usada), na MESMA transação do lote de eventos; ao iniciar, `--after-cursor`. Também: SIGTERM
confirma o lote em andamento; cursor inválido é ignorado; se o journalctl recusar o cursor, recomeça sem ele (1x).
Cria tests/test_collector_cursor.py.

  * seguro: texto exato, senão NADA é alterado; idempotente; cópia em sysopai/collector.py.bak-cursor.

    python portscan/apply_collector_cursor.py        # na raiz do projeto (ou com o script em uma subpasta)
"""
from __future__ import annotations

import py_compile
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COL = ROOT / "sysopai" / "collector.py"
TEST = ROOT / "tests" / "test_collector_cursor.py"
MARK = "def valid_cursor("

DOC_OLD = "`journalctl -f -o json --cursor-file=...` é um processo filho: o coletor só lê o pipe (nunca bloqueia o\nsistema), retoma do cursor após reinício e confirma em lote (menos fsync)."
DOC_NEW = ("`journalctl -f -o json` é um processo filho: o coletor só lê o pipe (nunca bloqueia o\nsistema), retoma do cursor "
           "após reinício (gravado no banco, na mesma transação dos eventos) e confirma em lote (menos fsync).")
IMP_OLD = "import json\nimport subprocess\nimport time\n"
IMP_NEW = "import json\nimport re\nimport signal\nimport sqlite3\nimport subprocess\nimport time\n"
RUN_START = "def run("
MAIN_OLD = '\n\nif __name__ == "__main__":\n    run()\n'

NEW_CODE = '''CURSOR_SOURCE = "journald"
IDLE_S = 30.0          # sem eventos relevantes, o cursor avança mesmo assim a cada tanto
_CURSOR_RX = re.compile(r"^[a-z]=[0-9a-f]+(;[a-z]=[0-9a-f]+)*$")


def valid_cursor(c) -> bool:
    """Formato do cursor do journald (s=...;i=...;b=...;m=...;t=...;x=...). Valida antes de virar argumento de comando."""
    return isinstance(c, str) and len(c) <= 300 and bool(_CURSOR_RX.match(c))


def get_cursor(con) -> str | None:
    try:
        row = con.execute("SELECT cursor FROM collector_cursor WHERE source=?", (CURSOR_SOURCE,)).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row and valid_cursor(row[0]) else None


def set_cursor(con, cursor: str) -> None:
    con.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES (?,?,?) "
                "ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at",
                (CURSOR_SOURCE, cursor, int(time.time())))


def clear_cursor(con) -> None:
    con.execute("DELETE FROM collector_cursor WHERE source=?", (CURSOR_SOURCE,))


def journal_cmd(cursor: str | None) -> list[str]:
    base = ["journalctl", "-f", "-o", "json", "--no-pager"]
    return base + ([f"--after-cursor={cursor}"] if cursor else ["-n", "0"])


def _line_cursor(line: str) -> str | None:
    try:
        c = json.loads(line).get("__CURSOR")
    except (ValueError, AttributeError):
        return None
    return c if valid_cursor(c) else None


def _flush(con, n: int, last: str | None) -> None:
    """Confirma o lote: eventos e cursor na MESMA transação (nunca um sem o outro)."""
    if n:
        triage.open_incidents(con)
    if last:
        set_cursor(con, last)
    if n or last:
        con.commit()


def run(db_path: str | None = None, host: str = "opad-master", popen=subprocess.Popen):
    con = dbm.connect(db_path)
    con.execute("CREATE TABLE IF NOT EXISTS collector_cursor "
                "(source TEXT PRIMARY KEY, cursor TEXT NOT NULL, updated_at INTEGER NOT NULL)")
    cursor = get_cursor(con)
    while True:
        p = popen(journal_cmd(cursor), stdout=subprocess.PIPE, text=True, bufsize=1)
        n, t0, last, got = 0, time.time(), None, False
        try:
            for line in p.stdout:  # bloqueia só aqui, no pipe
                got = True
                n += process(con, line, host)
                last = _line_cursor(line) or last
                dt = time.time() - t0
                if n >= BATCH_N or (n and dt >= BATCH_S) or (not n and last and dt >= IDLE_S):
                    _flush(con, n, last)
                    n, t0, last = 0, time.time(), None
        finally:  # SIGTERM (SystemExit) ou fim do pipe: não perde o lote em andamento
            _flush(con, n, last)
            if p.poll() is None:
                p.terminate()
        rc = p.wait()
        if cursor and not got and rc > 0:  # o journalctl recusou o cursor (rc<0 é sinal: não é recusa)
            clear_cursor(con)
            con.commit()
            cursor = None
            continue
        return


def _term(*_):
    raise SystemExit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _term)   # `systemctl stop`: confirma o lote e o cursor antes de sair
    run()
'''

TEST_SRC = r'''import json

import pytest

import collector
import db

C1 = "s=aaa;i=1;b=bbb;m=1;t=1;x=1"
C2 = "s=aaa;i=2;b=bbb;m=2;t=2;x=2"
C3 = "s=aaa;i=3;b=bbb;m=3;t=3;x=3"


def linha(ident, msg, cursor, ts_us=1700000000000000):
    return json.dumps({"__CURSOR": cursor, "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg, "__REALTIME_TIMESTAMP": str(ts_us)})


FALHA = "Failed password for root from 203.0.113.9 port 22 ssh2"


class FakeProc:
    def __init__(self, linhas, rc=0, explode=None):
        self._linhas, self.returncode, self._explode = list(linhas), rc, explode
        self.terminated = False
        self.stdout = self._gen()

    def _gen(self):
        for ln in self._linhas:
            yield ln
        if self._explode:
            raise self._explode

    def poll(self):
        return self.returncode if self.terminated or not self._linhas else None

    def wait(self):
        return self.returncode

    def terminate(self):
        self.terminated = True


def fabrica(*procs):
    chamadas = []
    fila = list(procs)

    def popen(cmd, **kw):
        chamadas.append(list(cmd))
        return fila.pop(0)

    return popen, chamadas


@pytest.fixture
def dbp(tmp_path):
    p = str(tmp_path / "c.db")
    db.init(p).close()
    return p


def cursor_gravado(dbp):
    c = db.connect(dbp)
    try:
        r = c.execute("SELECT cursor FROM collector_cursor WHERE source='journald'").fetchone()
        return r[0] if r else None
    finally:
        c.close()


def eventos(dbp):
    c = db.connect(dbp)
    try:
        return c.execute("SELECT count(*) FROM raw_events").fetchone()[0]
    finally:
        c.close()


def test_sem_cursor_comeca_do_agora(dbp):
    popen, chamadas = fabrica(FakeProc([]))
    collector.run(dbp, popen=popen)
    assert chamadas == [["journalctl", "-f", "-o", "json", "--no-pager", "-n", "0"]]


def test_grava_eventos_e_cursor_juntos(dbp):
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1), linha("sshd", FALHA, C2)]))
    collector.run(dbp, popen=popen)
    assert eventos(dbp) == 2 and cursor_gravado(dbp) == C2


def test_retoma_do_cursor_gravado(dbp):
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1)]))
    collector.run(dbp, popen=popen)
    popen2, chamadas = fabrica(FakeProc([]))
    collector.run(dbp, popen=popen2)
    assert chamadas == [["journalctl", "-f", "-o", "json", "--no-pager", f"--after-cursor={C1}"]]
    assert "-n" not in chamadas[0]


@pytest.mark.parametrize("lixo", ["--exec=evil", "s=aaa; rm -rf /", "", "s=XYZ", "x" * 400, "$(id)", "s=1\ni=2"])
def test_cursor_invalido_no_banco_e_ignorado(dbp, lixo):
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (lixo,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([]))
    collector.run(dbp, popen=popen)
    assert chamadas == [["journalctl", "-f", "-o", "json", "--no-pager", "-n", "0"]]


def test_cursor_invalido_vindo_do_journal_nao_e_gravado(dbp):
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, "--exec=evil")]))
    collector.run(dbp, popen=popen)
    assert eventos(dbp) == 1 and cursor_gravado(dbp) is None


def test_journalctl_recusa_o_cursor_recomeca_sem_ele(dbp):
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (C1,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([], rc=1), FakeProc([linha("sshd", FALHA, C2)]))
    collector.run(dbp, popen=popen)
    assert len(chamadas) == 2 and f"--after-cursor={C1}" in chamadas[0] and chamadas[1][-2:] == ["-n", "0"]
    assert cursor_gravado(dbp) == C2 and eventos(dbp) == 1


def test_parada_por_sinal_nao_apaga_o_cursor(dbp):
    """rc negativo = morto por sinal (systemctl stop): NÃO é recusa de cursor."""
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (C1,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([], rc=-15))
    collector.run(dbp, popen=popen)
    assert len(chamadas) == 1 and cursor_gravado(dbp) == C1


def test_recusa_de_cursor_so_tenta_uma_vez(dbp):
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (C1,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([], rc=1), FakeProc([], rc=1))
    collector.run(dbp, popen=popen)
    assert len(chamadas) == 2


def test_sigterm_confirma_o_lote_em_andamento(dbp):
    """SystemExit (o que o handler de SIGTERM levanta) no meio da leitura: o lote parcial e o cursor são gravados."""
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1), linha("sshd", FALHA, C2)], explode=SystemExit(0)))
    with pytest.raises(SystemExit):
        collector.run(dbp, popen=popen)
    assert eventos(dbp) == 2 and cursor_gravado(dbp) == C2


def test_linhas_irrelevantes_tambem_avancam_o_cursor(dbp, monkeypatch):
    relogio = {"t": 1000.0}
    monkeypatch.setattr(collector.time, "time", lambda: relogio["t"])

    def gen():
        yield linha("cron", "tarefa", C1)
        relogio["t"] += collector.IDLE_S + 1
        yield linha("cron", "tarefa", C2)

    class P(FakeProc):
        def _gen(self):
            return gen()

    popen, _ = fabrica(P([]))
    collector.run(dbp, popen=popen)
    assert eventos(dbp) == 0 and cursor_gravado(dbp) == C2


def test_evento_e_cursor_sao_a_mesma_transacao(dbp, monkeypatch):
    """Se gravar o cursor falha, os eventos do lote NÃO persistem (e vice-versa): reprocessa na volta, sem furo."""
    import sqlite3
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1)]))

    def quebrado(con, cursor):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(collector, "set_cursor", quebrado)
    with pytest.raises(sqlite3.OperationalError):
        collector.run(dbp, popen=popen)
    assert eventos(dbp) == 0 and cursor_gravado(dbp) is None
'''


def main() -> int:
    if not COL.exists():
        print(f"ERRO: {COL} não existe. Nada foi alterado.")
        return 1
    s = COL.read_text()
    if MARK in s:
        print("já aplicado, nada a fazer")
        return 0
    if (s.count(DOC_OLD), s.count(IMP_OLD), s.count(RUN_START), s.count(MAIN_OLD)) != (1, 1, 1, 1) or "--cursor-file" not in s:
        print("ERRO: o collector.py não tem a forma esperada. Nada foi alterado.")
        return 1
    if TEST.exists():
        print(f"ERRO: {TEST} já existe. Nada foi alterado.")
        return 1
    i = s.index(RUN_START)
    j = s.index(MAIN_OLD)
    if j < i:
        print("ERRO: ordem inesperada no collector.py. Nada foi alterado.")
        return 1
    new = s.replace(DOC_OLD, DOC_NEW).replace(IMP_OLD, IMP_NEW)
    i = new.index(RUN_START)
    j = new.index(MAIN_OLD)
    new = new[:i] + NEW_CODE.rstrip("\n") + "\n"
    shutil.copy2(COL, str(COL) + ".bak-cursor")
    COL.write_text(new)
    try:
        py_compile.compile(str(COL), doraise=True)
    except py_compile.PyCompileError as exc:
        shutil.copy2(str(COL) + ".bak-cursor", COL)
        print("ERRO de sintaxe; collector.py restaurado:", exc)
        return 1
    TEST.write_text(TEST_SRC)
    print(f"ok: {COL} atualizado (backup .bak-cursor) e {TEST} criado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
