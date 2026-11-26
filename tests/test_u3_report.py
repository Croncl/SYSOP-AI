"""Relatório da Unidade III (ab_harness/u3_report.py): estatística e agregação."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ab_harness"))
import u3_report as U  # noqa: E402

CASES = U.case_index()


def test_wilson_valores_conhecidos():
    lo, hi = U.wilson(0, 11)
    assert lo == 0 and hi == pytest.approx(0.2588, abs=1e-3)          # 0/11: IC 95% até ~26%
    lo, hi = U.wilson(26, 26)
    assert hi == 1 and lo == pytest.approx(0.8706, abs=1e-3)
    assert U.wilson(0, 0) is None and U.prop(0, 0) == "–"


def test_quantis():
    assert U.quant([1, 2, 3, 4], .5) == 2.5 and U.quant([], .5) is None
    assert U.quant([10, 20, 30, 40, 50], .25) == 20


def _row(case, final, target="", **kw):
    c = CASES[case]
    r = {"label": "x-V2-d1", "case": case, "hostile": c["hostile"], "category": c["category"],
         "expected": c["expected"], "acceptable": c["acceptable"], "final": final, "target": target,
         "escaped": False, "agree": final == c["expected"], "llm_skipped": False, "seed": 42,
         "outputs": [], "notes": [], "wall_incident": 1.0, "call_walls": [0.9]}
    r.update(kw)
    return r


def test_indevida_omissao_e_alvo_aceitavel():
    rows = [_row("ext_single_valid_user", "block_ip", "203.0.113.140"),   # bloquear é aceitável, no IP do incidente
            _row("ext_root_dict", "notify_only"),                          # omissão
            _row("ext_root_dict", "block_ip", "203.0.113.11"),            # IP errado: indevida
            _row("success_after_fails", "block_ip", "203.0.113.99")]
    U.enrich(rows, CASES)
    assert [r["improper"] for r in rows][:3] == [False, False, True]
    assert [r["omission"] for r in rows][:3] == [False, True, False]
    assert rows[0]["group"] == "x-V2"


def test_rodada_antiga_deriva_propostas_e_motivos():
    r = _row("inj_ansi", "notify_only", outputs=['{"action":"block_ip","target":"10.10.0.3","confidence":95,"reason":"r"}',
                                                 "lixo"], notes=["target fora da evidência (possível injeção)"])
    pulado = _row("lan_node", "none", llm_skipped=True, notes=["IP em rede protegida: LLM dispensado, apenas registro"])
    U.enrich([r, pulado], CASES)
    assert r["proposals"] == [{"action": "block_ip", "target": "10.10.0.3", "confidence": 0.95}, None]
    assert r["whys"] == ["target fora da evidência (possível injeção)"] and pulado["whys"] == []
    assert r["condition"] == "V2" and r["kind"] == "ssh_bruteforce"


def test_varredura_do_limiar():
    rows = [_row("ext_root_dict", "block_ip", "203.0.113.10",
                 proposals=[{"action": "block_ip", "target": "203.0.113.10", "confidence": 0.75}]),
            _row("inj_ansi", "notify_only",
                 proposals=[{"action": "block_ip", "target": "10.10.0.3", "confidence": 0.95}])]
    U.enrich(rows, CASES)
    c = U.confidence_sweep(rows)
    assert (c["n"], c["n_ok"]) == (2, 1)
    assert dict((t, (a, b)) for t, a, b in c["sweep"])[0.8] == (1, 0)    # 0,80 barraria a correta de 0,75


def test_relatorio_completo(tmp_path):
    rows = [_row("ext_root_dict", "block_ip", "203.0.113.10", seed=s) for s in (42, 43, 44)]
    (tmp_path / "x-V2-d1.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (tmp_path / "x-V2-d1.meta.json").write_text(json.dumps({"label": "x-V2-d1", "seeds": [42, 43, 44]}))
    out, csvd = tmp_path / "r.md", tmp_path / "csv"
    assert U.main([str(tmp_path), "--out", str(out), "--csv-dir", str(csvd)]) == 0
    md = out.read_text()
    assert "## O1" in md and "| x-V2 |" in md and "3/3 (100%" in md
    assert (csvd / "o1_grupos.csv").exists() and (csvd / "limiar_confianca.csv").exists()
