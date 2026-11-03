#!/usr/bin/env python3
"""Aplica a regra "ações permitidas por tipo de incidente" no graph.py e cria o teste correspondente.

  * seguro: cada trecho é procurado por texto exato; se algum não bater, NADA é alterado;
  * idempotente: se já aplicado, não faz nada;
  * guarda cópia em graph.py.bak-guard.

    python ab_harness/apply_guard.py                       # usa sysopai/graph.py e tests/
    python ab_harness/apply_guard.py --graph X --tests-dir Y
"""
from __future__ import annotations

import argparse
import py_compile
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CONST = '''MAX_REFLECT_RETRIES = 1

# Ações que o LLM PODE propor por tipo de incidente (o validador rejeita o resto; vale ao reprompt também).
# post_login_activity: o atacante (ou o admin) já está dentro; banir IP ali pode derrubar o próprio administrador.
# none e run_aide_check só fazem sentido onde o tipo os pede; fora disso viram vetor de injeção.
ALLOWED_ACTIONS_BY_KIND: dict[str, frozenset[str]] = {
    "ssh_bruteforce": frozenset({"block_ip", "notify_only", "investigate_journal"}),
    "port_scan": frozenset({"block_ip", "notify_only", "investigate_journal"}),
    "integrity_change": frozenset({"run_aide_check", "notify_only", "investigate_journal"}),
    "post_login_activity": frozenset({"notify_only", "investigate_journal"}),
}
DEFAULT_ALLOWED: frozenset[str] = frozenset({"notify_only", "investigate_journal"})  # tipo desconhecido: nunca escreve
'''

OLD_SIG = ('def validate_decision(d: Decision, *, con, evidence_ids: set[int], evidence_ips: set[str], '
           'n_events: int) -> Optional[str]:')
NEW_SIG = ('def validate_decision(d: Decision, *, con, evidence_ids: set[int], evidence_ips: set[str], '
           'n_events: int, kind: str = "") -> Optional[str]:')
OLD_BODY = '''    if d.cites and not set(d.cites) <= evidence_ids:
        return "cita evento inexistente"
'''
NEW_BODY = '''    if kind and d.action not in ALLOWED_ACTIONS_BY_KIND.get(kind, DEFAULT_ALLOWED):
        return f"ação {d.action} não permitida para incidente {kind}"
    if d.cites and not set(d.cites) <= evidence_ids:
        return "cita evento inexistente"
'''
OLD_CALL = 'n_events=inc["n_events"])'
NEW_CALL = 'n_events=inc["n_events"], kind=inc["kind"])'

TEST = '''"""Ações permitidas por tipo de incidente (validate_decision com kind=...) e efeito de ponta a ponta."""
import json
import time

import pytest

import db as dbm
import graph as G

IP = "198.51.100.7"


@pytest.fixture()
def path(tmp_path):
    p = str(tmp_path / "t.db")
    dbm.init(p).close()
    return p


@pytest.fixture()
def con(path):
    c = dbm.connect(path)
    yield c
    c.close()


def _d(action, target="", conf=0.95):
    return G.Decision(action=action, target=target, confidence=conf, reason="x")


def _v(con, d, kind, n=50):
    return G.validate_decision(d, con=con, evidence_ids=set(), evidence_ips={IP}, n_events=n, kind=kind)


@pytest.mark.parametrize("kind", ["ssh_bruteforce", "port_scan"])
def test_bloqueio_permitido_em_forca_bruta_e_port_scan(con, kind):
    assert _v(con, _d("block_ip", IP), kind) is None


@pytest.mark.parametrize("action", ["none", "run_aide_check"])
@pytest.mark.parametrize("kind", ["ssh_bruteforce", "port_scan"])
def test_none_e_aide_proibidos_em_forca_bruta_e_port_scan(con, kind, action):
    assert "não permitida" in _v(con, _d(action), kind)


def test_post_login_proibe_bloqueio_none_e_aide(con):
    for action in ("block_ip", "none", "run_aide_check"):
        target = IP if action == "block_ip" else ""
        assert "não permitida" in _v(con, _d(action, target), "post_login_activity")


@pytest.mark.parametrize("action", ["notify_only", "investigate_journal"])
def test_post_login_permite_notificar_e_investigar(con, action):
    assert _v(con, _d(action), "post_login_activity") is None


def test_integridade_permite_aide_e_proibe_bloqueio(con):
    assert _v(con, _d("run_aide_check"), "integrity_change") is None
    assert "não permitida" in _v(con, _d("block_ip", IP), "integrity_change")


def test_tipo_desconhecido_nunca_bloqueia(con):
    assert "não permitida" in _v(con, _d("block_ip", IP), "tipo_novo")
    assert _v(con, _d("notify_only"), "tipo_novo") is None


def test_sem_kind_mantem_comportamento_anterior(con):
    d = _d("block_ip", IP)
    assert G.validate_decision(d, con=con, evidence_ids=set(), evidence_ips={IP}, n_events=50) is None


def test_regras_antigas_continuam_valendo_com_kind(con):
    assert "fora da evidência" in _v(con, _d("block_ip", "203.0.113.99"), "ssh_bruteforce")
    assert "poucos eventos" in _v(con, _d("block_ip", IP), "ssh_bruteforce", n=3)
    assert "confiança" in _v(con, _d("block_ip", IP, conf=0.5), "ssh_bruteforce")


def test_grafo_nao_bane_ip_do_admin_em_post_login(path):
    """Ponta a ponta: LLM insiste em block_ip num incidente pós-login; nada de ban nasce."""
    con, ro, now = dbm.connect(path), dbm.connect(path, readonly=True), int(time.time())
    iid = con.execute(
        "INSERT INTO incidents(opened_at,kind,severity,src_ip,n_events,first_ts,last_ts,status,summary)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (now, "post_login_activity", "medium", IP, 12, now - 60, now, "open", "teste")).lastrowid
    con.execute(
        "INSERT INTO raw_events(ts,source,host,unit,event_type,src_ip,user,raw,label,label_score,labeler,incident_id)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (now - 30, "journald", "t", "sshd", "ssh_ok", IP, "admin",
         f"sshd: Accepted password for admin from {IP} port 5000 ssh2", "normal", 1.0, "rule", iid))
    con.commit()
    chamadas = []

    def llm(messages, schema):
        chamadas.append(1)
        return json.dumps({"action": "block_ip", "target": IP, "confidence": 0.99, "reason": "x", "cites": []})

    g = G.build_graph(con, llm, ro_con=ro, caller=lambda *a, **k: pytest.fail("nada deveria executar"))
    out = g.invoke({"incident_id": iid})
    con.commit()
    assert len(chamadas) == 2                      # 1ª proposta + 1 reprompt
    assert out["decision"]["action"] == "notify_only"
    assert con.execute("SELECT count(*) FROM agent_actions WHERE tool='ban_ip_fail2ban'").fetchone()[0] == 0
'''


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", default=str(ROOT / "sysopai" / "graph.py"))
    ap.add_argument("--tests-dir", default=str(ROOT / "tests"))
    a = ap.parse_args()
    gp, td = Path(a.graph), Path(a.tests_dir)
    text = gp.read_text()
    if "ALLOWED_ACTIONS_BY_KIND" in text:
        print("já aplicado: nada a fazer")
        return 0
    checks = [("MAX_REFLECT_RETRIES = 1\n", 1), (OLD_SIG, 1), (OLD_BODY, 1), (OLD_CALL, 1)]
    for needle, want in checks:
        n = text.count(needle)
        if n != want:
            print(f"ABORTADO (nada foi alterado): esperava {want} ocorrência(s) de:\n  {needle.strip()[:120]}\n"
                  f"mas achei {n}. Cole a saída deste erro para eu ajustar o patch.")
            return 1
    new = (text.replace("MAX_REFLECT_RETRIES = 1\n", CONST, 1).replace(OLD_SIG, NEW_SIG, 1)
           .replace(OLD_BODY, NEW_BODY, 1).replace(OLD_CALL, NEW_CALL, 1))
    shutil.copy2(gp, str(gp) + ".bak-guard")
    gp.write_text(new)
    try:
        py_compile.compile(str(gp), doraise=True)
    except py_compile.PyCompileError as exc:
        shutil.copy2(str(gp) + ".bak-guard", gp)
        print(f"ABORTADO: o resultado não compila ({exc}); graph.py restaurado")
        return 1
    td.mkdir(parents=True, exist_ok=True)
    (td / "test_guard_por_tipo.py").write_text(TEST)
    print(f"ok: {gp} alterado (backup em {gp}.bak-guard); teste criado em {td}/test_guard_por_tipo.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
