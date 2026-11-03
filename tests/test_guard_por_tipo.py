"""Ações permitidas por tipo de incidente (validate_decision com kind=...) e efeito de ponta a ponta."""
import json
import time

import pytest

import db as dbm
import graph as G

IP = "198.51.100.7"


@pytest.fixture()
def path(tmp_path):
    p = str(tmp_path / "t.db")
    dbm.init(p).close()
    return p


@pytest.fixture()
def con(path):
    c = dbm.connect(path)
    yield c
    c.close()


def _d(action, target="", conf=0.95):
    return G.Decision(action=action, target=target, confidence=conf, reason="x")


def _v(con, d, kind, n=50):
    return G.validate_decision(d, con=con, evidence_ids=set(), evidence_ips={IP}, n_events=n, kind=kind)


@pytest.mark.parametrize("kind", ["ssh_bruteforce", "port_scan"])
def test_bloqueio_permitido_em_forca_bruta_e_port_scan(con, kind):
    assert _v(con, _d("block_ip", IP), kind) is None


@pytest.mark.parametrize("action", ["none", "run_aide_check"])
@pytest.mark.parametrize("kind", ["ssh_bruteforce", "port_scan"])
def test_none_e_aide_proibidos_em_forca_bruta_e_port_scan(con, kind, action):
    assert "não permitida" in _v(con, _d(action), kind)


def test_post_login_proibe_bloqueio_none_e_aide(con):
    for action in ("block_ip", "none", "run_aide_check"):
        target = IP if action == "block_ip" else ""
        assert "não permitida" in _v(con, _d(action, target), "post_login_activity")


@pytest.mark.parametrize("action", ["notify_only", "investigate_journal"])
def test_post_login_permite_notificar_e_investigar(con, action):
    assert _v(con, _d(action), "post_login_activity") is None


def test_integridade_permite_aide_e_proibe_bloqueio(con):
    assert _v(con, _d("run_aide_check"), "integrity_change") is None
    assert "não permitida" in _v(con, _d("block_ip", IP), "integrity_change")


def test_tipo_desconhecido_nunca_bloqueia(con):
    assert "não permitida" in _v(con, _d("block_ip", IP), "tipo_novo")
    assert _v(con, _d("notify_only"), "tipo_novo") is None


def test_sem_kind_mantem_comportamento_anterior(con):
    d = _d("block_ip", IP)
    assert G.validate_decision(d, con=con, evidence_ids=set(), evidence_ips={IP}, n_events=50) is None


def test_regras_antigas_continuam_valendo_com_kind(con):
    assert "fora da evidência" in _v(con, _d("block_ip", "203.0.113.99"), "ssh_bruteforce")
    assert "poucos eventos" in _v(con, _d("block_ip", IP), "ssh_bruteforce", n=3)
    assert "confiança" in _v(con, _d("block_ip", IP, conf=0.5), "ssh_bruteforce")


def test_grafo_nao_bane_ip_do_admin_em_post_login(path):
    """Ponta a ponta: LLM insiste em block_ip num incidente pós-login; nada de ban nasce."""
    con, ro, now = dbm.connect(path), dbm.connect(path, readonly=True), int(time.time())
    iid = con.execute(
        "INSERT INTO incidents(opened_at,kind,severity,src_ip,n_events,first_ts,last_ts,status,summary)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (now, "post_login_activity", "medium", IP, 12, now - 60, now, "open", "teste")).lastrowid
    con.execute(
        "INSERT INTO raw_events(ts,source,host,unit,event_type,src_ip,user,raw,label,label_score,labeler,incident_id)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (now - 30, "journald", "t", "sshd", "ssh_ok", IP, "admin",
         f"sshd: Accepted password for admin from {IP} port 5000 ssh2", "normal", 1.0, "rule", iid))
    con.commit()
    chamadas = []

    def llm(messages, schema):
        chamadas.append(1)
        return json.dumps({"action": "block_ip", "target": IP, "confidence": 0.99, "reason": "x", "cites": []})

    g = G.build_graph(con, llm, ro_con=ro, caller=lambda *a, **k: pytest.fail("nada deveria executar"))
    out = g.invoke({"incident_id": iid})
    con.commit()
    assert len(chamadas) == 2                      # 1ª proposta + 1 reprompt
    assert out["decision"]["action"] == "notify_only"
    assert con.execute("SELECT count(*) FROM agent_actions WHERE tool='ban_ip_fail2ban'").fetchone()[0] == 0
