#!/usr/bin/env python3
"""Linha do tempo de cada incidente no banco do agente (O3, segunda metade): detecção -> decisão do LLM ->
aprovação humana -> execução -> verificação no fail2ban (Reflect).

Lê cópias (backup) do sysop.db e, se houver, do approvals.db da placa; nunca escreve nelas.

    python -m eval_deteccao.cadeia --sysop-db lab/sysop.db --approvals-db lab/approvals.db --out cadeia.md
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def _ro(path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def chain(sysop_db: str, approvals_db: str | None = None, since: float = 0) -> list[dict]:
    con = _ro(sysop_db)
    human = {}
    if approvals_db and Path(approvals_db).exists():
        a = _ro(approvals_db)
        human = {r["action_id"]: dict(r) for r in a.execute("SELECT action_id, approved_by, approved_at FROM approvals")}
        a.close()
    audit = [dict(r) for r in con.execute("SELECT ts, actor, event, detail FROM audit_log ORDER BY id")]
    for r in audit:
        try:
            r["d"] = json.loads(r["detail"])
        except ValueError:
            r["d"] = {}
    plans = [r for r in audit if r["event"] == "plan_decision"]
    llm = [dict(r) for r in con.execute("SELECT ts, seconds, ok FROM llm_calls WHERE purpose='plan' ORDER BY id")]
    out = []
    for inc in con.execute("SELECT * FROM incidents WHERE opened_at >= ? ORDER BY id", (int(since),)):
        inc = dict(inc)
        p = [x for x in plans if x["d"].get("incident") == inc["id"]]
        plan = p[-1] if p else None
        prev_ts = max((x["ts"] for x in plans if x["ts"] < (plan["ts"] if plan else 0)), default=0)
        calls = [c for c in llm if plan and prev_ts < c["ts"] <= plan["ts"]]
        row = {"incident": inc["id"], "kind": inc["kind"], "ip": inc["src_ip"], "n_events": inc["n_events"],
               "severity": inc["severity"], "status": inc["status"], "opened_at": inc["opened_at"],
               "first_ts": inc["first_ts"],
               "plan_ts": plan["ts"] if plan else None, "action": plan["d"].get("action") if plan else None,
               "proposed": plan["d"].get("model_proposed") if plan else None,
               "accepted": plan["d"].get("accepted") if plan else None,
               "confidence": plan["d"].get("confidence") if plan else None,
               "why": plan["d"].get("why") if plan else None,
               "llm_calls": len(calls), "llm_seconds": round(sum(c["seconds"] or 0 for c in calls), 1),
               "actions": []}
        for act in con.execute("SELECT * FROM agent_actions WHERE incident_id=? ORDER BY id", (inc["id"],)):
            act = dict(act)
            ex = [x["ts"] for x in audit if x["event"] == "action_executed" and x["d"].get("id") == act["id"]]
            h = human.get(act["id"], {})
            row["actions"].append({"id": act["id"], "tool": act["tool"], "args": json.loads(act["args_json"]),
                                   "proposed_ts": act["ts"], "status": act["status"], "verified": act["verified"],
                                   "approved_by": h.get("approved_by") or act["approved_by"],
                                   "approved_ts": h.get("approved_at"), "executed_ts": ex[-1] if ex else None})
        out.append(row)
    con.close()
    return out


def _hms(ts) -> str:
    return "–" if ts is None else datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


def _d(a, b) -> str:
    return "–" if a is None or b is None else f"{b - a:.0f}"


def render(rows: list[dict]) -> str:
    head = ["inc.", "tipo", "IP", "eventos", "aberto (UTC)", "1º evento→aberto (s)", "decisão", "proposta do modelo",
            "aceita", "conf.", "chamadas LLM", "LLM (s)", "ação", "status", "aberto→proposta (s)",
            "proposta→aprovação humana (s)", "aprovação→execução (s)", "verificado"]
    body = []
    for r in rows:
        acts = r["actions"] or [None]
        for a in acts:
            body.append([r["incident"], r["kind"], r["ip"], r["n_events"], _hms(r["opened_at"]),
                         _d(r["first_ts"], r["opened_at"]), r["action"] or "–", r["proposed"] or "–",
                         {True: "sim", False: "não", None: "–"}[r["accepted"]],
                         "–" if r["confidence"] is None else f"{r['confidence']:.2f}", r["llm_calls"], r["llm_seconds"],
                         f"#{a['id']} {a['tool']} {a['args'].get('ip', '')}" if a else "–", a["status"] if a else r["status"],
                         _d(r["opened_at"], a["proposed_ts"]) if a else "–",
                         _d(a["proposed_ts"], a["approved_ts"]) if a else "–",
                         _d(a["approved_ts"], a["executed_ts"]) if a else "–",
                         {1: "sim", 0: "NÃO", None: "–"}[a["verified"]] if a else "–"])
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    lines += ["| " + " | ".join(str(x) for x in b) + " |" for b in body]
    bans = [a for r in rows for a in r["actions"] if a["tool"] == "ban_ip_fail2ban"]
    resumo = (f"{len(rows)} incidentes; {sum(r['plan_ts'] is not None for r in rows)} com decisão do LLM; "
              f"{len(bans)} bans propostos, {sum(a['approved_ts'] is not None for a in bans)} aprovados por humano, "
              f"{sum(a['status'] == 'verified' for a in bans)} executados e confirmados no fail2ban.")
    return "\n".join(["# Cadeia detecção → decisão → aprovação → bloqueio", "", resumo, ""] + lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sysop-db", required=True)
    ap.add_argument("--approvals-db")
    ap.add_argument("--since", type=float, default=0, help="só incidentes abertos a partir deste epoch")
    ap.add_argument("--out", default="")
    ap.add_argument("--json", default="", help="grava também a cadeia completa em JSON")
    a = ap.parse_args(argv)
    rows = chain(a.sysop_db, a.approvals_db, a.since)
    md = render(rows)
    if a.out:
        Path(a.out).write_text(md + "\n")
        print(f"{a.out}: {len(rows)} incidentes")
    else:
        print(md)
    if a.json:
        Path(a.json).write_text(json.dumps(rows, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
