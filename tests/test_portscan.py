"""Detecção de port scan (triage.open_port_scan_incidents / open_incidents)."""
import pytest

import db
import triage


@pytest.fixture
def con(tmp_path):
    c = db.init(str(tmp_path / "t.db"))
    yield c
    c.close()


def _ufw(ip, port, proto="TCP"):
    return (f"[UFW BLOCK] IN=wlan0 OUT= MAC=aa:bb SRC={ip} DST=192.168.0.4 LEN=44 TOS=0x00 "
            f"PROTO={proto} SPT=40000 DPT={port} WINDOW=1024 SYN")


def _feed(con, ip, ports, ts, src="ufw"):
    for p in ports:
        triage.ingest(con, src, "h", ts, _ufw(ip, p))
    con.commit()


def _kinds(con):
    return [(r["kind"], r["src_ip"]) for r in con.execute("SELECT kind, src_ip FROM incidents ORDER BY id")]


def test_dpt_nao_casa_spt():
    assert triage.DPT.search("SPT=22 DPT=8080 X").group(1) == "8080"
    assert triage.DPT.search("SPT=22 X") is None


def test_varredura_abre_incidente(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(20, 32), now - 60)          # 12 portas
    ids = triage.open_incidents(con, now=now)
    assert len(ids) == 1
    inc = con.execute("SELECT * FROM incidents WHERE id=?", (ids[0],)).fetchone()
    assert inc["kind"] == "port_scan" and inc["src_ip"] == "198.51.100.7"
    assert inc["n_events"] == 12 and inc["severity"] == "medium"
    assert "12 portas distintas" in inc["summary"]
    n = con.execute("SELECT count(*) FROM raw_events WHERE incident_id=?", (ids[0],)).fetchone()[0]
    assert n == 12


def test_limiar_exato(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 10), now - 60)           # 9 portas: abaixo
    assert triage.open_incidents(con, now=now) == []
    _feed(con, "198.51.100.7", [10], now - 50)                   # 10ª porta: abre
    assert len(triage.open_incidents(con, now=now)) == 1


def test_mesma_porta_nao_e_varredura(con):
    now = 10_000
    _feed(con, "198.51.100.7", [22] * 300, now - 60)
    assert triage.open_incidents(con, now=now) == []


def test_idempotente(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 21), now - 60)
    assert len(triage.open_incidents(con, now=now)) == 1
    assert triage.open_incidents(con, now=now) == []
    assert triage.open_incidents(con, now=now + 5) == []


def test_fora_da_janela_nao_conta(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 21), now - 3600)
    assert triage.open_incidents(con, now=now) == []


def test_ips_independentes(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 21), now - 60)
    _feed(con, "198.51.100.8", range(1, 6), now - 60)            # poucas portas
    _feed(con, "203.0.113.9", range(1, 31), now - 60)
    got = sorted(ip for k, ip in (triage.open_incidents(con, now=now) and _kinds(con)))
    assert got == ["198.51.100.7", "203.0.113.9"]


def test_porta_invalida_ou_ausente_ignorada(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 6), now - 60)            # 5 válidas
    for _ in range(20):                                          # sem DPT (ICMP) e DPT > 65535
        triage.ingest(con, "ufw", "h", now - 60, "[UFW BLOCK] IN=wlan0 SRC=198.51.100.7 DST=192.168.0.4 PROTO=ICMP")
        triage.ingest(con, "ufw", "h", now - 60, _ufw("198.51.100.7", 99999))
    con.commit()
    assert triage.open_incidents(con, now=now) == []


def test_severidade_por_portas_distintas(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 151), now - 60)
    ids = triage.open_incidents(con, now=now)
    assert con.execute("SELECT severity FROM incidents WHERE id=?", (ids[0],)).fetchone()[0] == "high"


def test_convive_com_bruteforce_no_mesmo_ip(con):
    now = 10_000
    for i in range(12):
        triage.ingest(con, "journald", "h", now - 60, f"Failed password for root from 198.51.100.7 port {i} ssh2")
    _feed(con, "198.51.100.7", range(1, 21), now - 60)
    ids = triage.open_incidents(con, now=now)
    assert len(ids) == 2
    assert sorted(k for k, _ in _kinds(con)) == ["port_scan", "ssh_bruteforce"]
    # nenhum evento é contado nos dois incidentes
    assert con.execute("SELECT count(*) FROM raw_events WHERE incident_id IS NOT NULL").fetchone()[0] == 32


def test_auditoria_registra_incidente(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 21), now - 60)
    triage.open_incidents(con, now=now)
    ev = con.execute("SELECT detail FROM audit_log WHERE event='incident_opened'").fetchall()
    assert len(ev) == 1 and '"port_scan"' in ev[0][0]

# --- varredura em andamento = UM incidente (achado no teste real na placa) -----------------------------------
def test_varredura_em_lotes_vira_um_incidente(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 13), now - 60)                 # 12 portas: abre
    ids = triage.open_incidents(con, now=now)
    assert len(ids) == 1
    _feed(con, "198.51.100.7", range(13, 40), now - 30)                # a varredura continua
    assert triage.open_incidents(con, now=now) == []                   # nada de incidente novo
    _feed(con, "198.51.100.7", range(40, 160), now - 10)
    assert triage.open_incidents(con, now=now) == []
    assert _kinds(con) == [("port_scan", "198.51.100.7")]
    inc = con.execute("SELECT * FROM incidents").fetchone()
    assert inc["n_events"] == 159 and inc["severity"] == "high"       # 159 portas distintas
    assert "159 portas distintas" in inc["summary"] and inc["last_ts"] == now - 10
    assert con.execute("SELECT count(*) FROM raw_events WHERE incident_id IS NULL").fetchone()[0] == 0


def test_poucos_eventos_novos_tambem_sao_anexados(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 13), now - 60)
    triage.open_incidents(con, now=now)
    _feed(con, "198.51.100.7", [500, 501], now - 5)                    # só 2 portas novas: abaixo do limiar
    assert triage.open_incidents(con, now=now) == []
    assert con.execute("SELECT n_events FROM incidents").fetchone()[0] == 14


def test_incidente_encerrado_nao_recebe_eventos_novos(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 13), now - 60)
    triage.open_incidents(con, now=now)
    con.execute("UPDATE incidents SET status = 'mitigated'")
    _feed(con, "198.51.100.7", range(100, 115), now - 5)
    assert len(triage.open_incidents(con, now=now + 1)) == 1           # varredura nova, incidente novo
    assert len(_kinds(con)) == 2


def test_incidente_antigo_fora_da_janela_nao_recebe(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 13), now - 1000)
    triage.open_incidents(con, now=now - 900)
    _feed(con, "198.51.100.7", range(100, 115), now - 5)
    assert len(triage.open_incidents(con, now=now)) == 1
    assert len(_kinds(con)) == 2


def test_anexar_nao_mistura_ips(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 13), now - 60)
    triage.open_incidents(con, now=now)
    _feed(con, "198.51.100.8", range(1, 6), now - 5)                   # outro IP, poucos eventos
    assert triage.open_incidents(con, now=now) == []
    assert con.execute("SELECT n_events FROM incidents").fetchone()[0] == 12
    assert con.execute("SELECT count(*) FROM raw_events WHERE src_ip='198.51.100.8' AND incident_id IS NOT NULL").fetchone()[0] == 0


def test_atualizacao_e_auditada(con):
    now = 10_000
    _feed(con, "198.51.100.7", range(1, 13), now - 60)
    triage.open_incidents(con, now=now)
    _feed(con, "198.51.100.7", range(13, 20), now - 5)
    triage.open_incidents(con, now=now)
    ev = [r[0] for r in con.execute("SELECT detail FROM audit_log WHERE event='incident_updated'")]
    assert len(ev) == 1 and '"port_scan"' in ev[0]
