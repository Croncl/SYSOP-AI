#!/usr/bin/env python3
"""Leva a dica do prompt (usada no A/B com --hint) para o graph.py de PRODUÇÃO e normaliza `confidence`.

Motivo [Medido]: o llama-server não impõe os limites numéricos do esquema JSON. O Qwen devolve confidence em
porcentagem (75, 95, 100) e o Pydantic rejeita (le=1.0): 2 chamadas e fallback em notify_only. Com a dica, 1 chamada.

  1. SYSTEM_PROMPT ganha a dica;
  2. parse_decision(): lê 1 < confidence <= 100 como porcentagem (fora disso o Pydantic continua rejeitando);
  3. o nó Plan usa parse_decision.
Seguro: texto exato (senão aborta sem alterar nada), idempotente, backup em graph.py.bak-hint, cria
tests/test_parse_decision.py.

    python ab_harness/apply_prompt_hint.py [--graph X] [--tests-dir Y]
"""
from __future__ import annotations

import argparse
import py_compile
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

HINT = (" confidence é um decimal entre 0 e 1 (ex.: 0.85), nunca porcentagem. "
        "Para block_ip, target é o IP do incidente.")

ANCHOR_PROMPT = "# ------------------------------ saída estruturada"
NEW_PROMPT = ('SYSTEM_PROMPT += (\n'
              '    " confidence é um decimal entre 0 e 1 (ex.: 0.85), nunca porcentagem. "\n'
              '    "Para block_ip, target é o IP do incidente."\n'
              ')\n\n\n' + ANCHOR_PROMPT)

ANCHOR_FUNC = "def _build_context("
NEW_FUNC = '''def parse_decision(txt: str) -> Decision:
    """Valida o JSON do modelo. O llama-server NÃO impõe os limites numéricos do esquema: modelos pequenos
    devolvem confidence em porcentagem (75, 95). 1 < x <= 100 é lido como porcentagem; fora disso o Pydantic
    rejeita (falha fechada). Erro de JSON vira ValueError; esquema inválido, ValidationError."""
    obj = json.loads(txt)
    if isinstance(obj, dict):
        c = obj.get("confidence")
        if isinstance(c, (int, float)) and not isinstance(c, bool) and 1 < c <= 100:
            obj["confidence"] = c / 100
    return Decision.model_validate(obj)


def _build_context('''

OLD_CALL = "Decision.model_validate_json(txt)"
NEW_CALL = "parse_decision(txt)"

TEST = '''"""parse_decision (confidence em porcentagem) e a dica no prompt de produção."""
import json
import time

import pytest
from pydantic import ValidationError

import db as dbm
import graph as G


def _j(**kw):
    base = {"action": "block_ip", "target": "203.0.113.10", "confidence": 0.9, "reason": "x"}
    base.update(kw)
    return json.dumps(base)


@pytest.mark.parametrize("valor,esperado", [(95, 0.95), (75, 0.75), (100, 1.0), (0.95, 0.95), (0, 0.0), (1, 1.0)])
def test_confidence_percentual_e_normalizada(valor, esperado):
    assert G.parse_decision(_j(confidence=valor)).confidence == pytest.approx(esperado)


@pytest.mark.parametrize("valor", [150, 1000, -5, "alta", None])
def test_confidence_fora_da_faixa_continua_rejeitada(valor):
    with pytest.raises(ValidationError):
        G.parse_decision(_j(confidence=valor))


def test_json_invalido_vira_valueerror():
    with pytest.raises(ValueError):
        G.parse_decision("isto não é json")


def test_json_que_nao_e_objeto_e_rejeitado():
    with pytest.raises(ValidationError):
        G.parse_decision("[1, 2]")


def test_prompt_de_producao_tem_a_dica():
    assert "decimal entre 0 e 1" in G.SYSTEM_PROMPT and "target é o IP do incidente" in G.SYSTEM_PROMPT


def test_grafo_aceita_confidence_em_porcentagem_com_uma_chamada(tmp_path):
    p = str(tmp_path / "t.db")
    dbm.init(p).close()
    con, ro, now = dbm.connect(p), dbm.connect(p, readonly=True), int(time.time())
    ip = "203.0.113.10"
    iid = con.execute(
        "INSERT INTO incidents(opened_at,kind,severity,src_ip,n_events,first_ts,last_ts,status,summary)"
        " VALUES (?,?,?,?,?,?,?,?,?)", (now, "ssh_bruteforce", "medium", ip, 24, now - 60, now, "open", "t")).lastrowid
    for i in range(12):
        con.execute(
            "INSERT INTO raw_events(ts,source,host,unit,event_type,src_ip,user,raw,label,label_score,labeler,incident_id)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (now - i, "journald", "t", "sshd", "ssh_fail", ip, "root",
             f"sshd: Failed password for root from {ip} port {4000 + i}", "bruteforce", 1.0, "rule", iid))
    con.commit()
    chamadas = []

    def llm(messages, schema):
        chamadas.append(1)
        return json.dumps({"action": "block_ip", "target": ip, "confidence": 95, "reason": "24 falhas"})

    g = G.build_graph(con, llm, ro_con=ro, caller=lambda *a, **k: pytest.fail("nada deveria executar"))
    g.invoke({"incident_id": iid})
    con.commit()
    assert len(chamadas) == 1
    row = con.execute("SELECT status,confidence FROM agent_actions WHERE tool='ban_ip_fail2ban'").fetchone()
    assert row["status"] == "pending" and row["confidence"] == pytest.approx(0.95)
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", default=str(ROOT / "sysopai" / "graph.py"))
    ap.add_argument("--tests-dir", default=str(ROOT / "tests"))
    a = ap.parse_args()
    gp, td = Path(a.graph), Path(a.tests_dir)
    text = gp.read_text()
    if "def parse_decision(" in text:
        print("já aplicado: nada a fazer")
        return 0
    for needle in (ANCHOR_PROMPT, ANCHOR_FUNC, OLD_CALL):
        n = text.count(needle)
        if n != 1:
            print(f"ABORTADO (nada foi alterado): esperava 1 ocorrência de:\n  {needle}\nmas achei {n}. "
                  "Cole esta mensagem para eu ajustar o patch.")
            return 1
    new = (text.replace(ANCHOR_PROMPT, NEW_PROMPT, 1).replace(ANCHOR_FUNC, NEW_FUNC, 1)
           .replace(OLD_CALL, NEW_CALL, 1))
    shutil.copy2(gp, str(gp) + ".bak-hint")
    gp.write_text(new)
    try:
        py_compile.compile(str(gp), doraise=True)
    except py_compile.PyCompileError as exc:
        shutil.copy2(str(gp) + ".bak-hint", gp)
        print(f"ABORTADO: o resultado não compila ({exc}); graph.py restaurado")
        return 1
    td.mkdir(parents=True, exist_ok=True)
    (td / "test_parse_decision.py").write_text(TEST)
    print(f"ok: {gp} alterado (backup em {gp}.bak-hint); teste criado em {td}/test_parse_decision.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
