"""parse_decision (confidence em porcentagem) e a dica no prompt de produção."""
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
