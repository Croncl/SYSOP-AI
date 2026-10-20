"""Camada 1: triagem barata. Regras primeiro (µs); BERT só para linhas que as regras não resolvem.

Medida de projeto: classificar TODA linha com BERT em 6xA55 custa dezenas de ms/linha (~50-150 ms
[Estimativa], medir) e disputa a mesma banda de memória do LLM. Por isso: regras -> (opcional) BERT
-> LLM só em lote. Agregação de incidentes é SQL, não modelo.
"""
from __future__ import annotations

import re
import sqlite3
import time
from typing import Callable, Optional

IPV4 = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
RULES: list[tuple[re.Pattern, str, str, str]] = [
    # (regex, event_type, label, unit)
    (re.compile(rf"Failed password for (?:invalid user )?(?P<user>\S+) from {IPV4}"), "ssh_fail", "bruteforce", "sshd"),
    (re.compile(rf"Invalid user (?P<user>\S*) from {IPV4}"), "ssh_invalid_user", "bruteforce", "sshd"),
    (re.compile(rf"Accepted \S+ for (?P<user>\S+) from {IPV4}"), "ssh_ok", "normal", "sshd"),
    (re.compile(rf"\[UFW BLOCK\].*SRC={IPV4}"), "ufw_block", "minor", "ufw"),
    (re.compile(r"sudo: .*COMMAND=(?P<user>)"), "sudo", "minor", "sudo"),
    (re.compile(rf"\] Ban {IPV4}"), "f2b_ban", "minor", "fail2ban"),
    (re.compile(r"AIDE found differences|changed files:"), "aide_change", "critical", "aide"),
]
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]|\x1b\[[0-9;]*[A-Za-z]")


def sanitize(s: str, limit: int = 160) -> str:
    """Log é entrada do ATACANTE (usuário SSH, user-agent...). Sem controle/ANSI, sem '<' '>' (não fecham
    a tag <evidence>), colapsa espaços, trunca. Não é garantia contra injeção: é redução de superfície."""
    s = _CTRL.sub(" ", s).replace("<", "‹").replace(">", "›")
    return re.sub(r"\s+", " ", s).strip()[:limit]


def classify_line(raw: str, bert: Optional[Callable[[str], tuple[str, float]]] = None) -> dict:
    for rx, etype, label, unit in RULES:
        m = rx.search(raw)
        if m:
            gd = m.groupdict()
            return {"event_type": etype, "label": label, "score": 1.0, "labeler": "rule",
                    "src_ip": gd.get("ip"), "user": (gd.get("user") or None), "unit": unit}
    if bert:  # só o que as regras não cobrem
        label, score = bert(raw)
        return {"event_type": "other", "label": label, "score": score, "labeler": "bert",
                "src_ip": None, "user": None, "unit": ""}
    return {"event_type": "other", "label": "normal", "score": 0.5, "labeler": "rule",
            "src_ip": None, "user": None, "unit": ""}


def ingest(con: sqlite3.Connection, source: str, host: str, ts: int, raw: str, bert=None) -> int:
    c = classify_line(raw, bert)
    cur = con.execute(
        "INSERT INTO raw_events(ts,source,host,unit,event_type,src_ip,user,raw,label,label_score,labeler)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (ts, source, host, c["unit"], c["event_type"], c["src_ip"], c["user"], raw[:2000],
         c["label"], c["score"], c["labeler"]))
    return cur.lastrowid


def open_incidents(con: sqlite3.Connection, now: int | None = None, window_s: int = 600,
                   threshold: int = 10) -> list[int]:
    """Um incidente por (kind, IP) por janela. Severidade por contagem — decisão do CÓDIGO."""
    now = now or int(time.time())
    ids = []
    rows = con.execute(
        "SELECT src_ip, count(*) n, min(ts) f, max(ts) l FROM raw_events "
        "WHERE ts >= ? AND label IN ('bruteforce','critical') AND src_ip IS NOT NULL AND incident_id IS NULL "
        "GROUP BY src_ip HAVING n >= ?", (now - window_s, threshold)).fetchall()
    for r in rows:
        sev = "critical" if r["n"] >= 200 else "high" if r["n"] >= 50 else "medium"
        cur = con.execute(
            "INSERT OR IGNORE INTO incidents(opened_at,kind,severity,src_ip,n_events,first_ts,last_ts,summary)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now, "ssh_bruteforce", sev, r["src_ip"], r["n"], r["f"], r["l"],
             f"{r['n']} falhas de autenticação de {r['src_ip']} em {window_s // 60} min"))
        if cur.rowcount:
            iid = cur.lastrowid
            con.execute("UPDATE raw_events SET incident_id=? WHERE src_ip=? AND ts>=? AND incident_id IS NULL "
                        "AND label IN ('bruteforce','critical')", (iid, r["src_ip"], now - window_s))
            ids.append(iid)
    return ids
