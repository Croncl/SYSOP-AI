#!/usr/bin/env python3
"""Consolida a varredura em UM incidente `port_scan` (triage.py) + 6 testes em tests/test_portscan.py.

Defeito achado no teste real na placa (04/11): depois que o 1º incidente abre, os eventos seguintes da MESMA
varredura ficavam sem incidente e, a cada 10 portas novas, abriam outro (5 incidentes para 1 varredura = 5
chamadas de LLM e até 5 propostas de ban). Agora, se o IP já tem um port_scan ativo (open/analyzed/
pending_approval) com último evento na janela, os eventos novos são anexados a ele e contagem/severidade
são recalculadas. Só o incidente NOVO é devolvido por open_incidents.

  * seguro: o trecho antigo é procurado por texto exato; se não bater, NADA é alterado;
  * idempotente: se já aplicado, não faz nada;
  * guarda cópia em triage.py.bak-consolida.

    python portscan/apply_portscan_consolida.py          # usa sysopai/triage.py e tests/
"""
from __future__ import annotations

import argparse
import py_compile
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MARK_NEW = "def _port_stats("
OLD_FUNC = 'def open_port_scan_incidents(con: sqlite3.Connection, now: int | None = None, window_s: int = 600,\n                             port_threshold: int = 10) -> list[int]:\n    """port_scan: um IP que bate em >= port_threshold portas DISTINTAS bloqueadas pelo UFW na janela.\n    Conta portas distintas, não eventos: 500 bloqueios na mesma porta é insistência, não varredura.\n    Severidade e contagens vêm do SQL/código, nunca do modelo."""\n    now = now or int(time.time())\n    ids: list[int] = []\n    cands = con.execute(\n        "SELECT src_ip, count(*) n FROM raw_events "\n        "WHERE ts >= ? AND event_type = \'ufw_block\' AND src_ip IS NOT NULL AND incident_id IS NULL "\n        "GROUP BY src_ip HAVING n >= ?", (now - window_s, port_threshold)).fetchall()\n    for c in cands:  # só os IPs com eventos suficientes: o parse do raw fica barato\n        ev: list[tuple[int, int]] = []\n        ports: set[int] = set()\n        for r in con.execute(\n                "SELECT id, ts, raw FROM raw_events WHERE src_ip = ? AND ts >= ? "\n                "AND event_type = \'ufw_block\' AND incident_id IS NULL", (c["src_ip"], now - window_s)):\n            m = DPT.search(r["raw"])\n            if m and int(m.group(1)) <= 65535:\n                ports.add(int(m.group(1)))\n                ev.append((r["id"], r["ts"]))\n        if len(ports) < port_threshold:\n            continue\n        np_, n = len(ports), len(ev)\n        sev = "critical" if np_ >= 1000 else "high" if np_ >= 100 else "medium"\n        cur = con.execute(\n            "INSERT OR IGNORE INTO incidents(opened_at,kind,severity,src_ip,n_events,first_ts,last_ts,summary)"\n            " VALUES (?,?,?,?,?,?,?,?)",\n            (now, "port_scan", sev, c["src_ip"], n, min(t for _, t in ev), max(t for _, t in ev),\n             f"{n} bloqueios UFW de {c[\'src_ip\']} em {np_} portas distintas em {window_s // 60} min"))\n        if cur.rowcount:\n            iid = cur.lastrowid\n            db.audit(con, "collector", "incident_opened",\n                     {"id": iid, "kind": "port_scan", "severity": sev, "ip": c["src_ip"], "n": n, "ports": np_})\n            con.executemany("UPDATE raw_events SET incident_id = ? WHERE id = ?", [(iid, i) for i, _ in ev])\n            ids.append(iid)\n    return ids\n'
NEW_FUNC = 'def _port_stats(con: sqlite3.Connection, incident_id: int) -> tuple[int, int, int, int]:\n    """(portas distintas, eventos, primeiro ts, último ts) de TODOS os eventos já ligados ao incidente."""\n    ports: set[int] = set()\n    n, f, l = 0, None, None\n    for r in con.execute("SELECT ts, raw FROM raw_events WHERE incident_id = ?", (incident_id,)):\n        m = DPT.search(r["raw"])\n        if m and int(m.group(1)) <= 65535:\n            ports.add(int(m.group(1)))\n            n += 1\n            f = r["ts"] if f is None else min(f, r["ts"])\n            l = r["ts"] if l is None else max(l, r["ts"])\n    return len(ports), n, f or 0, l or 0\n\n\ndef _scan_severity(n_ports: int) -> str:\n    return "critical" if n_ports >= 1000 else "high" if n_ports >= 100 else "medium"\n\n\ndef open_port_scan_incidents(con: sqlite3.Connection, now: int | None = None, window_s: int = 600,\n                             port_threshold: int = 10) -> list[int]:\n    """port_scan: um IP que bate em >= port_threshold portas DISTINTAS bloqueadas pelo UFW na janela.\n    Conta portas distintas, não eventos: 500 bloqueios na mesma porta é insistência, não varredura.\n    Uma varredura é UM incidente: se o IP já tem um port_scan ativo (open/analyzed/pending_approval) cujo\n    último evento está na janela, os eventos novos são ANEXADOS a ele (e contagem/severidade recalculadas),\n    em vez de abrir outro a cada 10 portas. Retorna só os ids dos incidentes NOVOS.\n    Severidade e contagens vêm do SQL/código, nunca do modelo."""\n    now = now or int(time.time())\n    ids: list[int] = []\n    cands = con.execute(\n        "SELECT src_ip, count(*) n FROM raw_events "\n        "WHERE ts >= ? AND event_type = \'ufw_block\' AND src_ip IS NOT NULL AND incident_id IS NULL "\n        "GROUP BY src_ip", (now - window_s,)).fetchall()\n    for c in cands:\n        ip = c["src_ip"]\n        existing = con.execute(\n            "SELECT id FROM incidents WHERE kind = \'port_scan\' AND src_ip = ? "\n            "AND status IN (\'open\',\'analyzed\',\'pending_approval\') AND last_ts >= ? ORDER BY id DESC LIMIT 1",\n            (ip, now - window_s)).fetchone()\n        if existing is None and c["n"] < port_threshold:\n            continue  # poucos eventos e nenhum incidente aberto: o parse do raw nem é feito\n        ev: list[tuple[int, int]] = []\n        ports: set[int] = set()\n        for r in con.execute(\n                "SELECT id, ts, raw FROM raw_events WHERE src_ip = ? AND ts >= ? "\n                "AND event_type = \'ufw_block\' AND incident_id IS NULL", (ip, now - window_s)):\n            m = DPT.search(r["raw"])\n            if m and int(m.group(1)) <= 65535:\n                ports.add(int(m.group(1)))\n                ev.append((r["id"], r["ts"]))\n        if not ev:\n            continue\n        if existing is not None:  # mesma varredura em andamento: anexa e recalcula\n            iid = existing["id"]\n            con.executemany("UPDATE raw_events SET incident_id = ? WHERE id = ?", [(iid, i) for i, _ in ev])\n            np_, n, first, last = _port_stats(con, iid)\n            sev = _scan_severity(np_)\n            con.execute("UPDATE incidents SET n_events = ?, first_ts = ?, last_ts = ?, severity = ?, summary = ? "\n                        "WHERE id = ?",\n                        (n, first, last, sev,\n                         f"{n} bloqueios UFW de {ip} em {np_} portas distintas", iid))\n            db.audit(con, "collector", "incident_updated",\n                     {"id": iid, "kind": "port_scan", "severity": sev, "ip": ip, "n": n, "ports": np_})\n            continue\n        if len(ports) < port_threshold:\n            continue\n        np_, n = len(ports), len(ev)\n        sev = _scan_severity(np_)\n        cur = con.execute(\n            "INSERT OR IGNORE INTO incidents(opened_at,kind,severity,src_ip,n_events,first_ts,last_ts,summary)"\n            " VALUES (?,?,?,?,?,?,?,?)",\n            (now, "port_scan", sev, ip, n, min(t for _, t in ev), max(t for _, t in ev),\n             f"{n} bloqueios UFW de {ip} em {np_} portas distintas em {window_s // 60} min"))\n        if cur.rowcount:\n            iid = cur.lastrowid\n            db.audit(con, "collector", "incident_opened",\n                     {"id": iid, "kind": "port_scan", "severity": sev, "ip": ip, "n": n, "ports": np_})\n            con.executemany("UPDATE raw_events SET incident_id = ? WHERE id = ?", [(iid, i) for i, _ in ev])\n            ids.append(iid)\n    return ids\n'
TESTS_ADD = '\n\n# --- varredura em andamento = UM incidente (achado no teste real na placa) -----------------------------------\ndef test_varredura_em_lotes_vira_um_incidente(con):\n    now = 10_000\n    _feed(con, "198.51.100.7", range(1, 13), now - 60)                 # 12 portas: abre\n    ids = triage.open_incidents(con, now=now)\n    assert len(ids) == 1\n    _feed(con, "198.51.100.7", range(13, 40), now - 30)                # a varredura continua\n    assert triage.open_incidents(con, now=now) == []                   # nada de incidente novo\n    _feed(con, "198.51.100.7", range(40, 160), now - 10)\n    assert triage.open_incidents(con, now=now) == []\n    assert _kinds(con) == [("port_scan", "198.51.100.7")]\n    inc = con.execute("SELECT * FROM incidents").fetchone()\n    assert inc["n_events"] == 159 and inc["severity"] == "high"       # 159 portas distintas\n    assert "159 portas distintas" in inc["summary"] and inc["last_ts"] == now - 10\n    assert con.execute("SELECT count(*) FROM raw_events WHERE incident_id IS NULL").fetchone()[0] == 0\n\n\ndef test_poucos_eventos_novos_tambem_sao_anexados(con):\n    now = 10_000\n    _feed(con, "198.51.100.7", range(1, 13), now - 60)\n    triage.open_incidents(con, now=now)\n    _feed(con, "198.51.100.7", [500, 501], now - 5)                    # só 2 portas novas: abaixo do limiar\n    assert triage.open_incidents(con, now=now) == []\n    assert con.execute("SELECT n_events FROM incidents").fetchone()[0] == 14\n\n\ndef test_incidente_encerrado_nao_recebe_eventos_novos(con):\n    now = 10_000\n    _feed(con, "198.51.100.7", range(1, 13), now - 60)\n    triage.open_incidents(con, now=now)\n    con.execute("UPDATE incidents SET status = \'mitigated\'")\n    _feed(con, "198.51.100.7", range(100, 115), now - 5)\n    assert len(triage.open_incidents(con, now=now + 1)) == 1           # varredura nova, incidente novo\n    assert len(_kinds(con)) == 2\n\n\ndef test_incidente_antigo_fora_da_janela_nao_recebe(con):\n    now = 10_000\n    _feed(con, "198.51.100.7", range(1, 13), now - 1000)\n    triage.open_incidents(con, now=now - 900)\n    _feed(con, "198.51.100.7", range(100, 115), now - 5)\n    assert len(triage.open_incidents(con, now=now)) == 1\n    assert len(_kinds(con)) == 2\n\n\ndef test_anexar_nao_mistura_ips(con):\n    now = 10_000\n    _feed(con, "198.51.100.7", range(1, 13), now - 60)\n    triage.open_incidents(con, now=now)\n    _feed(con, "198.51.100.8", range(1, 6), now - 5)                   # outro IP, poucos eventos\n    assert triage.open_incidents(con, now=now) == []\n    assert con.execute("SELECT n_events FROM incidents").fetchone()[0] == 12\n    assert con.execute("SELECT count(*) FROM raw_events WHERE src_ip=\'198.51.100.8\' AND incident_id IS NOT NULL").fetchone()[0] == 0\n\n\ndef test_atualizacao_e_auditada(con):\n    now = 10_000\n    _feed(con, "198.51.100.7", range(1, 13), now - 60)\n    triage.open_incidents(con, now=now)\n    _feed(con, "198.51.100.7", range(13, 20), now - 5)\n    triage.open_incidents(con, now=now)\n    ev = [r[0] for r in con.execute("SELECT detail FROM audit_log WHERE event=\'incident_updated\'")]\n    assert len(ev) == 1 and \'"port_scan"\' in ev[0]\n'


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--triage", default=str(ROOT / "sysopai" / "triage.py"))
    ap.add_argument("--tests-dir", default=str(ROOT / "tests"))
    a = ap.parse_args()
    tp, tfile = Path(a.triage), Path(a.tests_dir) / "test_portscan.py"
    src = tp.read_text()

    if MARK_NEW in src:
        print("triage.py: já aplicado, nada a fazer")
    else:
        i = src.find("def open_port_scan_incidents(")
        if i < 0 or src[i:] != OLD_FUNC:
            print("ERRO: open_port_scan_incidents não está igual ao esperado (aplique antes apply_portscan.py, "
                  "ou me envie o trecho). Nada foi alterado.")
            return 1
        shutil.copy2(tp, str(tp) + ".bak-consolida")
        tp.write_text(src[:i] + NEW_FUNC)
        try:
            py_compile.compile(str(tp), doraise=True)
        except py_compile.PyCompileError as e:
            shutil.copy2(str(tp) + ".bak-consolida", tp)
            print(f"ERRO de sintaxe, restaurado o original: {e}")
            return 1
        print(f"ok: {tp} atualizado (backup .bak-consolida)")

    if not tfile.exists():
        print(f"ERRO: {tfile} não existe (aplique antes apply_portscan.py)")
        return 1
    t = tfile.read_text()
    if "test_varredura_em_lotes_vira_um_incidente" in t:
        print("testes: já presentes")
    else:
        tfile.write_text(t.rstrip("\n") + TESTS_ADD)
        print(f"ok: 6 testes acrescentados em {tfile}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
