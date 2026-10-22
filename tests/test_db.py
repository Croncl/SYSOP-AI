import sqlite3
import pytest
import db


@pytest.fixture
def con(tmp_path):
    c = db.init(str(tmp_path / "t.db"))
    yield c
    c.close()


def _emb(text):  # embedding falso e determinístico (1024 dim)
    v = [0.0] * db.EMBED_DIM
    v[sum(map(ord, text)) % db.EMBED_DIM] = 1.0
    return v


def test_wal_e_tabelas(con):
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    n = con.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='mem_vec'").fetchone()[0]
    assert n == 1  # tabela vetorial criada


def test_audit_log_append_only(con):
    db.audit(con, "agent", "teste", {"a": 1})
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("UPDATE audit_log SET event='x'")
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("DELETE FROM audit_log")


def test_conexao_readonly_nao_escreve(con, tmp_path):
    ro = db.connect(str(tmp_path / "t.db"), readonly=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("INSERT INTO audit_log(ts,actor,event,detail) VALUES (1,'a','b','c')")
    ro.close()


def test_ban_aprovado_exige_humano(con):
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO agent_actions(ts,tool,args_json,status) "
                    "VALUES (1,'ban_ip_fail2ban','{}','approved')")


def test_tool_precisa_de_humano_e_sandbox(con):
    con.execute("INSERT INTO tool_registry(name,version,source,source_sha256,proposed_at,status) "
                "VALUES ('t',1,'x','h',1,'sandbox_ok')")
    with pytest.raises(sqlite3.IntegrityError):  # o agente não se auto-aprova
        con.execute("UPDATE tool_registry SET status='approved', approved_by='agent' WHERE name='t'")
    with pytest.raises(sqlite3.IntegrityError):  # código é imutável
        con.execute("UPDATE tool_registry SET source='y' WHERE name='t'")
    con.execute("UPDATE tool_registry SET status='approved', approved_by='maria' WHERE name='t'")  # humano: ok


def test_memoria_vetorial(con):
    a = db.mem_add(con, _emb, "resolution", "banir ip com muitas falhas ssh")
    assert a is not None
    assert db.mem_add(con, _emb, "resolution", "banir ip com muitas falhas ssh") is None  # idempotente
    db.mem_add(con, _emb, "kb", "procedimento totalmente diferente")
    r = db.mem_search(con, _emb, "banir ip com muitas falhas ssh", k=1)
    assert r and r[0]["id"] == a and r[0]["distance"] < 0.01
