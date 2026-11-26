"""Força bruta SSH vira UM incidente enquanto o ataque durar (triage.open_incidents).

Antes, cada lote de >= 10 falhas ainda sem incidente abria outro (o coletor chama open_incidents a cada 2 s ou 50
eventos), e cada incidente custava uma chamada de LLM de ~50 s na placa."""
import json

import pytest

import db
import triage

IP = "203.0.113.9"


@pytest.fixture
def con(tmp_path):
    c = db.init(str(tmp_path / "t.db"))
    yield c
    c.close()


def _fail(con, ip, n, ts):
    for i in range(n):
        triage.ingest(con, "journald", "h", ts, f"sshd[1]: Failed password for root from {ip} port {1000 + i} ssh2")
    con.commit()


def _ssh(con):
    return con.execute("SELECT * FROM incidents WHERE kind='ssh_bruteforce' ORDER BY id").fetchall()


def test_ataque_longo_vira_um_incidente(con):
    t0, novos = 10_000, []
    for k in range(6):                                  # 6 lotes de 20 falhas, 30 s entre lotes
        _fail(con, IP, 20, t0 + 30 * k)
        novos += triage.open_incidents(con, now=t0 + 30 * k)
    incs = _ssh(con)
    assert len(incs) == 1 and novos == [incs[0]["id"]]
    inc = incs[0]
    assert (inc["n_events"], inc["severity"], inc["first_ts"], inc["last_ts"]) == (120, "high", t0, t0 + 150)
    assert con.execute("SELECT count(*) FROM raw_events WHERE incident_id=?", (inc["id"],)).fetchone()[0] == 120
    upd = [json.loads(r["detail"]) for r in con.execute(
        "SELECT detail FROM audit_log WHERE event='incident_updated'")]
    assert len(upd) == 5 and upd[-1]["n"] == 120


def test_severidade_escala_ate_critical(con):
    t0 = 10_000
    _fail(con, IP, 12, t0)
    triage.open_incidents(con, now=t0)
    _fail(con, IP, 190, t0 + 60)
    assert triage.open_incidents(con, now=t0 + 60) == []
    inc = _ssh(con)[0]
    assert (inc["n_events"], inc["severity"]) == (202, "critical")


def test_poucas_falhas_novas_anexam_ao_ataque_em_andamento(con):
    t0 = 10_000
    _fail(con, IP, 12, t0)
    triage.open_incidents(con, now=t0)
    _fail(con, IP, 3, t0 + 60)                          # abaixo do limiar, mas é o mesmo ataque
    triage.open_incidents(con, now=t0 + 60)
    assert [i["n_events"] for i in _ssh(con)] == [15]


def test_depois_da_janela_abre_outro(con):
    t0 = 10_000
    _fail(con, IP, 12, t0)
    triage.open_incidents(con, now=t0)
    _fail(con, IP, 12, t0 + 700)                        # último evento do 1º incidente saiu da janela de 600 s
    assert len(triage.open_incidents(con, now=t0 + 700)) == 1
    assert [i["n_events"] for i in _ssh(con)] == [12, 12]


@pytest.mark.parametrize("status", ["mitigated", "failed", "closed"])
def test_incidente_encerrado_nao_absorve(con, status):
    t0 = 10_000
    _fail(con, IP, 12, t0)
    triage.open_incidents(con, now=t0)
    con.execute("UPDATE incidents SET status=?", (status,))
    _fail(con, IP, 12, t0 + 60)
    assert len(triage.open_incidents(con, now=t0 + 60)) == 1
    assert len(_ssh(con)) == 2


@pytest.mark.parametrize("status", ["open", "analyzed", "pending_approval"])
def test_incidente_ativo_absorve(con, status):
    t0 = 10_000
    _fail(con, IP, 12, t0)
    triage.open_incidents(con, now=t0)
    con.execute("UPDATE incidents SET status=?", (status,))
    _fail(con, IP, 12, t0 + 60)
    assert triage.open_incidents(con, now=t0 + 60) == []
    inc = _ssh(con)[0]
    assert (inc["n_events"], inc["status"]) == (24, status)


def test_nao_mistura_com_port_scan_nem_com_outro_ip(con):
    t0 = 10_000
    for p in range(20, 35):
        triage.ingest(con, "journald", "h", t0, f"[UFW BLOCK] IN=wlan0 OUT= MAC=aa SRC={IP} DST=192.168.0.4 "
                                               f"LEN=44 PROTO=TCP SPT=40000 DPT={p} SYN")
    _fail(con, IP, 12, t0)
    _fail(con, "198.51.100.7", 12, t0)
    triage.open_incidents(con, now=t0)
    _fail(con, IP, 5, t0 + 30)
    triage.open_incidents(con, now=t0 + 30)
    kinds = [(r["kind"], r["src_ip"], r["n_events"]) for r in con.execute(
        "SELECT kind, src_ip, n_events FROM incidents ORDER BY kind, src_ip")]
    assert kinds == [("port_scan", IP, 15), ("ssh_bruteforce", "198.51.100.7", 12), ("ssh_bruteforce", IP, 17)]
