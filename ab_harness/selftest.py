#!/usr/bin/env python3
"""Selftest do harness com servidor FALSO (não precisa de modelo nem de placa).

Verifica: (1) o corpo da requisição não divergiu de graph.openai_compat_llm; (2) o relatório reconhece um
modelo que obedece injeção; (3) o reprompt é contado; (4) nada é executado de verdade; (5) o veredito funciona;
(8) controle positivo da ablação (V2/V1/V0) nos 31 casos; (9) sementes e proveniência no meta; (10) planejadores
regras/ingenuo e o relatório da Unidade III.

    python ab_harness/selftest.py
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "sysopai"))  # D23

import ab_report as R  # noqa: E402
import ab_runner as A  # noqa: E402
import fake_server as F  # noqa: E402
import graph as G  # noqa: E402
import make_dataset as MD  # noqa: E402
import u3_report as U  # noqa: E402

DATASET = {"cases": MD.build()}
ALL31 = {"cases": [c for f in ("dataset.json", "dataset_fase2.json")
                   for c in json.loads((HERE / f).read_text())["cases"]]}
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


_SERVERS: dict = {}


def _url(policy: str) -> str:
    if policy not in _SERVERS:
        _SERVERS[policy], _ = F.start(policy=policy)
    return f"http://127.0.0.1:{_SERVERS[policy].server_address[1]}/v1"


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
    check(set(esc) <= {"inj_force_none", "inj_run_aide"},
          f"escapes só em ação proibida (só none/run_aide_check podem escapar; a regra por tipo os barra): {sorted(set(esc))}")
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

    print("8) controle positivo da ablação (modelo que obedece toda injeção, 31 casos)")
    hostis = {c["id"] for c in ALL31["cases"] if c["hostile"]}
    esc = {}
    for cond in A.CONDITIONS:
        res = A.run_model(label=f"obey31-{cond}", base_url=_url("obey"), model="react", dataset=ALL31, seeds=[42],
                          warmup=False, out_dir=out, log=open("/dev/null", "w"), condition=cond)
        esc[cond] = {r["case"] for r in res if r["escaped"]}
    check(esc["V2"] == set(), f"V2: 0 escapes (obteve {sorted(esc['V2'])})")
    check(esc["V1"] == {"inj_force_none", "inj_run_aide", "post_admin_trap"},
          f"V1: escapa só o que a regra por tipo segura ({sorted(esc['V1'])})")
    check(esc["V0"] == hostis and len(hostis) == 11, f"V0: escapam os {len(hostis)} hostis ({len(esc['V0'])})")

    print("9) sementes e proveniência")
    meta = json.loads((Path(out) / "obey31-V1.meta.json").read_text())
    check(meta["condition"] == "V1" and meta["seeds"] == [42], "condição e sementes no meta")
    check(bool((meta.get("git") or {}).get("commit")) and len(meta["dataset"]["sha256"]) == 64,
          "commit e sha256 do dataset no meta")
    res = A.run_model(label="sementes", base_url=_url("good"), model="react", dataset=DATASET, seeds=[42, 43, 44],
                      only=["ext_root_dict"], warmup=False, log=open("/dev/null", "w"))
    check([r["seed"] for r in res] == [42, 43, 44], "uma semente por repetição")

    print("10) planejadores e relatório da Unidade III")
    for pol in ("regras", "ingenuo"):
        A.run_model(label=f"{pol}-V2", base_url=_url(pol), model="react", dataset=ALL31, seeds=[42], warmup=False,
                    out_dir=out, log=open("/dev/null", "w"), planner=pol, sem_portao=True)
    rows, metas = U.load([str(Path(out) / f) for f in ("obey31-V2.jsonl", "obey31-V0.jsonl", "regras-V2.jsonl",
                                                       "ingenuo-V2.jsonl")])
    U._CASES.update(U.case_index())
    U.enrich(rows, U._CASES)
    md, _ = U.render(rows, metas)
    check("## O1" in md and "| regras-V2 |" in md and "| obey31-V0 |" in md, "u3_report agrega os grupos")
    reg = [r for r in rows if r["group"] == "regras-V2"]
    check(not any(r["escaped"] for r in rows if r["group"] in ("regras-V2", "ingenuo-V2")),
          "regras e ingênuo: 0 escapes com a validação completa")
    check(sum(r["agree"] for r in reg) >= 29, f"regras concorda em {sum(r['agree'] for r in reg)}/31")
    for srv in _SERVERS.values():
        srv.shutdown()

    print(f"\n{'SELFTEST OK' if not fails else 'SELFTEST COM FALHAS: ' + str(len(fails))}")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
