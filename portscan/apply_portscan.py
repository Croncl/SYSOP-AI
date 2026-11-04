#!/usr/bin/env python3
"""Detecção de port scan no triage.py (código puro, sem LLM) + tests/test_portscan.py.

Regra: um IP com >= PORT_THRESHOLD portas DISTINTAS (DPT=) bloqueadas pelo UFW na janela abre um
incidente `port_scan`. Mesma porta repetida não conta (é insistência, não varredura).
Sem coluna nova no banco: a porta é lida do `raw`, só dos IPs que já passam do limiar em eventos.

  * seguro: cada trecho é procurado por texto exato; se algum não bater, NADA é alterado;
  * idempotente: se já aplicado, não faz nada;
  * guarda cópia em triage.py.bak-portscan.

    python portscan/apply_portscan.py                    # usa sysopai/triage.py e tests/
    python portscan/apply_portscan.py --triage X --tests-dir Y
"""
from __future__ import annotations

import argparse
import py_compile
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK = "def open_port_scan_incidents("

OLD_CTRL = '_CTRL = re.compile('
NEW_CTRL = ('# porta de destino em linhas [UFW BLOCK]; \\b evita casar SPT=\n'
            'DPT = re.compile(r"\\bDPT=(\\d{1,5})\\b")\n'
            '_CTRL = re.compile(')

OLD_SIG = ('def open_incidents(con: sqlite3.Connection, now: int | None = None, window_s: int = 600,\n'
           '                   threshold: int = 10) -> list[int]:')
NEW_SIG = ('def open_incidents(con: sqlite3.Connection, now: int | None = None, window_s: int = 600,\n'
           '                   threshold: int = 10, port_threshold: int = 10) -> list[int]:')

OLD_END = '            ids.append(iid)\n    return ids\n'
NEW_END = ('            ids.append(iid)\n'
           '    ids += open_port_scan_incidents(con, now, window_s, port_threshold)\n'
           '    return ids\n')

NEW_FUNC = '''

def open_port_scan_incidents(con: sqlite3.Connection, now: int | None = None, window_s: int = 600,
                             port_threshold: int = 10) -> list[int]:
    """port_scan: um IP que bate em >= port_threshold portas DISTINTAS bloqueadas pelo UFW na janela.
    Conta portas distintas, não eventos: 500 bloqueios na mesma porta é insistência, não varredura.
    Severidade e contagens vêm do SQL/código, nunca do modelo."""
    now = now or int(time.time())
    ids: list[int] = []
    cands = con.execute(
        "SELECT src_ip, count(*) n FROM raw_events "
        "WHERE ts >= ? AND event_type = 'ufw_block' AND src_ip IS NOT NULL AND incident_id IS NULL "
        "GROUP BY src_ip HAVING n >= ?", (now - window_s, port_threshold)).fetchall()
    for c in cands:  # só os IPs com eventos suficientes: o parse do raw fica barato
        ev: list[tuple[int, int]] = []
        ports: set[int] = set()
        for r in con.execute(
                "SELECT id, ts, raw FROM raw_events WHERE src_ip = ? AND ts >= ? "
                "AND event_type = 'ufw_block' AND incident_id IS NULL", (c["src_ip"], now - window_s)):
            m = DPT.search(r["raw"])
            if m and int(m.group(1)) <= 65535:
                ports.add(int(m.group(1)))
                ev.append((r["id"], r["ts"]))
        if len(ports) < port_threshold:
            continue
        np_, n = len(ports), len(ev)
        sev = "critical" if np_ >= 1000 else "high" if np_ >= 100 else "medium"
        cur = con.execute(
            "INSERT OR IGNORE INTO incidents(opened_at,kind,severity,src_ip,n_events,first_ts,last_ts,summary)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now, "port_scan", sev, c["src_ip"], n, min(t for _, t in ev), max(t for _, t in ev),
             f"{n} bloqueios UFW de {c['src_ip']} em {np_} portas distintas em {window_s // 60} min"))
        if cur.rowcount:
            iid = cur.lastrowid
            db.audit(con, "collector", "incident_opened",
                     {"id": iid, "kind": "port_scan", "severity": sev, "ip": c["src_ip"], "n": n, "ports": np_})
            con.executemany("UPDATE raw_events SET incident_id = ? WHERE id = ?", [(iid, i) for i, _ in ev])
            ids.append(iid)
    return ids
'''

TEST = r'''"""Detecção de port scan (triage.open_port_scan_incidents / open_incidents)."""
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
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", default=str(ROOT / "sysopai" / "triage.py"))
    ap.add_argument("--tests-dir", default=str(ROOT / "tests"))
    a = ap.parse_args()
    tp, td = Path(a.triage), Path(a.tests_dir)
    src = tp.read_text()
    tfile = td / "test_portscan.py"

    if MARK in src:
        print("triage.py: já aplicado, nada a fazer")
        if not tfile.exists():
            tfile.write_text(TEST)
            print(f"criado {tfile}")
        return 0

    for name, old in (("_CTRL", OLD_CTRL), ("assinatura", OLD_SIG), ("fim de open_incidents", OLD_END)):
        if src.count(old) != 1:
            print(f"ERRO: trecho '{name}' não bate exatamente (achei {src.count(old)}x). Nada foi alterado.")
            return 1
    if not src.endswith(OLD_END):
        print("ERRO: open_incidents não é a última função do arquivo. Nada foi alterado.")
        return 1

    new = src.replace(OLD_CTRL, NEW_CTRL).replace(OLD_SIG, NEW_SIG).replace(OLD_END, NEW_END) + NEW_FUNC
    shutil.copy2(tp, str(tp) + ".bak-portscan")
    tp.write_text(new)
    try:
        py_compile.compile(str(tp), doraise=True)
    except py_compile.PyCompileError as e:
        shutil.copy2(str(tp) + ".bak-portscan", tp)
        print(f"ERRO de sintaxe, restaurado o original: {e}")
        return 1
    if tfile.exists() and tfile.read_text() != TEST:
        print(f"AVISO: {tfile} já existe e é diferente; não sobrescrevi")
    else:
        tfile.write_text(TEST)
    print(f"ok: {tp} atualizado (backup .bak-portscan); testes em {tfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
