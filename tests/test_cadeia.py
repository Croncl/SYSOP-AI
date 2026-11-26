"""Linha do tempo detecção -> decisão -> aprovação -> ban (eval_deteccao/cadeia.py) sobre um fluxo real do grafo."""
import json
import sys
from pathlib import Path

import approvals
import db
import graph
import tools as T
import triage

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eval_deteccao import cadeia as C  # noqa: E402

IP = "203.0.113.9"


def test_cadeia_completa(tmp_path, monkeypatch):
    path, apath = str(tmp_path / "s.db"), str(tmp_path / "a.db")
    con = db.init(path)
    approvals.init(apath)
    now = 1_700_000_000
    for i in range(30):
        triage.ingest(con, "journald", "h", now - 60 + i, f"Failed password for root from {IP} port {1000 + i} ssh2")
    iid = triage.open_incidents(con, now=now)[0]
    con.commit()
    llm = lambda m, s: json.dumps({"action": "block_ip", "target": IP, "confidence": 0.95, "reason": "r", "cites": []})
    calls = []
    g = graph.build_graph(con, llm, caller=lambda *a, **k: calls.append(a) or {"rc": 0}, approvals_path=apath)
    g.invoke({"incident_id": iid})
    act = con.execute("SELECT * FROM agent_actions").fetchone()
    approvals.grant(act, "maria", apath)
    monkeypatch.setattr(T, "is_banned", lambda ip, jail="sshd": True)
    g.invoke({"resume_action_id": act["id"]})
    con.commit()
    con.close()
    rows = C.chain(path, apath)
    assert len(rows) == 1
    r = rows[0]
    assert (r["kind"], r["ip"], r["action"], r["accepted"], r["llm_calls"]) == ("ssh_bruteforce", IP, "block_ip", True, 1)
    a = r["actions"][0]
    assert (a["status"], a["verified"], a["approved_by"], a["args"]["ip"]) == ("verified", 1, "maria", IP)
    assert a["approved_ts"] and a["executed_ts"] and r["first_ts"] == now - 60
    md = C.render(rows)
    assert "1 bans propostos, 1 aprovados por humano, 1 executados e confirmados" in md
