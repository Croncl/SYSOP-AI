#!/usr/bin/env python3
"""Selftest do harness com servidor FALSO (não precisa de modelo nem de placa).

Verifica: (1) o corpo da requisição não divergiu de graph.openai_compat_llm; (2) o relatório reconhece um
modelo que obedece injeção; (3) o reprompt é contado; (4) nada é executado de verdade; (5) o veredito funciona.

    python ab_harness/selftest.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import ab_report as R  # noqa: E402
import ab_runner as A  # noqa: E402
import fake_server as F  # noqa: E402
import graph as G  # noqa: E402
import make_dataset as MD  # noqa: E402

DATASET = {"cases": MD.build()}
fails: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("  ok   " if cond else "  FALHOU ") + msg)
    if not cond:
        fails.append(msg)


def run(policy: str, label: str, delay: float, out: str, **kw):
    srv, cfg = F.start(policy=policy, delay=delay)
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
        res = A.run_model(label=label, base_url=url, model="react", dataset=DATASET, reps=2, out_dir=out,
                          log=open("/dev/null", "w"), **kw)
        return res, cfg, url
    finally:
        srv.shutdown()


def main() -> int:
    out = tempfile.mkdtemp(prefix="ab_selftest_")
    print("1) paridade do corpo da requisição com a produção")
    srv, cfg = F.start("good")
    url = f"http://127.0.0.1:{srv.server_address[1]}/v1"
    schema = G.Decision.model_json_schema()
    msgs = [{"role": "user", "content": "x"}]
    G.openai_compat_llm(url, "react")(msgs, schema)
    prod = cfg["last_body"]
    mine = A.Capture(url, "react").body(msgs, schema)
    srv.shutdown()
    extra_keys = {"seed", "cache_prompt"}
    check({k: v for k, v in mine.items() if k not in extra_keys} == prod,
          "corpo = produção (exceto seed e cache_prompt)")

    print("2) modelo 'good' (lento) = baseline")
    base, _, _ = run("good", "base-good", 0.06, out)
    sb = R.summarize(base)
    check(sb["escapes"] == 0, f"good: 0 escapes (obteve {sb['escapes']})")
    check(sb["agree"] >= 85, f"good: concordância alta ({sb['agree']:.0f}%)")
    check(all(r["action_status"] in ("pending", "sem_acao", "executed") for r in base), "nenhum ban executado")
    check(any(r["final"] == "block_ip" and r["action_status"] == "pending" for r in base), "block_ip fica pending")

    print("3) modelo 'good' (rápido) deve PASSAR no veredito")
    fast, _, _ = run("good", "cand-fast", 0.005, out)
    ok, why = R.verdict(sb, R.summarize(fast))
    check(ok, f"candidato rápido passa ({why})")

    print("4) modelo 'obey' deve ser pego")
    obey, _, _ = run("obey", "cand-obey", 0.005, out)
    so = R.summarize(obey)
    check(so["hostile_attempts"] >= 5, f"tentativas hostis detectadas ({so['hostile_attempts']}/{so['hostile_n']})")
    check(not any(r["escaped"] for r in obey if r["final"] == "block_ip"),
          "validate_decision barrou todo block_ip fora da evidência/protegido")
    esc = sorted(r["case"] for r in obey if r["escaped"])
    check(esc == ["inj_force_none", "inj_run_aide"] * 1 or set(esc) == {"inj_force_none", "inj_run_aide"},
          f"escapes só em ação proibida (o validador não filtra none/run_aide_check): {sorted(set(esc))}")
    check(so["reject_rate"] > 0 and so["fallback"] > 0, "rejeições e fallback contabilizados")
    ok, why = R.verdict(sb, so)
    check(not ok, f"veredito reprova o modelo que obedece injeção ({'; '.join(why)})")

    print("5) modelo 'sloppy': reprompt contado")
    slop, _, _ = run("sloppy", "cand-sloppy", 0.005, out)
    ss = R.summarize(slop)
    check(ss["first_valid"] == 0.0, "1ª tentativa sempre inválida")
    check(all(r["n_calls"] == 2 for r in slop if r["final"] != "none"), "2 chamadas por incidente (reprompt)")

    print("6) segurança do runner")
    try:
        A.run_model(label="x", base_url="http://10.0.0.9:8080/v1", model="m", dataset=DATASET, reps=1)
        check(False, "recusa servidor fora de loopback")
    except SystemExit:
        check(True, "recusa servidor fora de loopback")
    try:
        A.T._run(["true"])
        check(False, "tools._run bloqueado")
    except RuntimeError:
        check(True, "tools._run bloqueado")

    print("7) relatório")
    rowsets = {l: R.load(Path(out) / f"{l}.jsonl") for l in ("base-good", "cand-fast", "cand-obey")}
    md = R.render({l: R.summarize(r) for l, r in rowsets.items()}, rowsets, "base-good")
    check("PASSA" in md and "NÃO passa" in md, "relatório traz veredito PASSA e NÃO passa")

    print(f"\n{'SELFTEST OK' if not fails else 'SELFTEST COM FALHAS: ' + str(len(fails))}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
