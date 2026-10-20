"""CLI do SYSOP-AI.  python cli.py init | run-once [--max N] | approve ACTION_ID | summary [--hours H]
                       tool-approve NOME VERSAO SHA256

`approve*` identificam o humano pelo usuário Unix (getpass) e RECUSAM o usuário de serviço 'sysop':
o agente roda como 'sysop', o administrador como ele mesmo."""
from __future__ import annotations

import argparse
import getpass
import os
import time

import db as dbm
import graph as G
import toolforge as TF
import triage

SERVICE_USER = "sysop"


def _admin() -> str:
    u = getpass.getuser()
    if u == SERVICE_USER:
        raise PermissionError("aprovações devem ser feitas por um usuário humano, não pelo serviço")
    return u


def _llm():
    return G.openai_compat_llm(os.environ.get("SYSOP_LLM_URL", "http://127.0.0.1:8080/v1"),
                               os.environ.get("SYSOP_LLM_MODEL", "react"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    r = sub.add_parser("run-once"); r.add_argument("--max", type=int, default=3)
    a = sub.add_parser("approve"); a.add_argument("action_id", type=int)
    s = sub.add_parser("summary"); s.add_argument("--hours", type=int, default=24)
    t = sub.add_parser("tool-approve"); t.add_argument("name"); t.add_argument("version", type=int); t.add_argument("sha256")
    args = ap.parse_args(argv)

    if args.cmd == "init":
        dbm.init().close(); print("ok"); return 0
    con = dbm.connect(vec=True)
    if args.cmd == "run-once":
        triage.open_incidents(con); con.commit()
        g = G.build_graph(con, _llm(), ro_con=dbm.connect(readonly=True))
        rows = con.execute("SELECT id FROM incidents WHERE status='open' ORDER BY "
                           "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END, opened_at LIMIT ?",
                           (args.max,)).fetchall()  # limite: cada incidente custa minutos de LLM
        for row in rows:
            out = g.invoke({"incident_id": row["id"]}); con.commit(); print(out.get("summary"))
    elif args.cmd == "approve":
        G.approve_action(con, args.action_id, _admin()); con.commit()
        g = G.build_graph(con, _llm())
        out = g.invoke({"resume_action_id": args.action_id}); con.commit(); print(out.get("summary"), out.get("notes"))
    elif args.cmd == "summary":
        txt = G.summarize_window(con, lambda p: _llm()([{"role": "user", "content": p}], {"type": "string"}),
                                 int(time.time()) - args.hours * 3600)
        con.commit(); print(txt or "sem incidentes")
    elif args.cmd == "tool-approve":
        TF.approve_tool(con, args.name, args.version, args.sha256, _admin()); con.commit(); print("aprovada")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
