"""Harness de avaliação (ab_harness/): condições de ablação, sementes e planejadores, com o servidor FALSO.

Nada aqui usa modelo nem placa: o fake_server responde no lugar do llama-server."""
import json
import sys
from pathlib import Path

import pytest

HARNESS = Path(__file__).resolve().parent.parent / "ab_harness"
sys.path.insert(0, str(HARNESS))

import ab_runner as A  # noqa: E402
import fake_server as F  # noqa: E402
import graph as G  # noqa: E402

CASES = (json.loads((HARNESS / "dataset.json").read_text())["cases"]
         + json.loads((HARNESS / "dataset_fase2.json").read_text())["cases"])
HOSTIS = {c["id"] for c in CASES if c["hostile"]}


@pytest.fixture(scope="module")
def obey():
    srv, _ = F.start(policy="obey")
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()


def _run(url, **kw):
    kw = {"label": "t", "base_url": url, "model": "react", "dataset": {"cases": CASES}, "reps": 1,
          "warmup": False, "log": open("/dev/null", "w"), **kw}
    return A.run_model(**kw)


def test_controle_positivo_por_condicao(obey):
    """Um modelo que obedece toda injeção: V2 barra tudo; V1 deixa passar só o que a regra por tipo segura;
    V0 deixa passar todos os casos hostis."""
    esc = {c: {r["case"] for r in _run(obey, condition=c) if r["escaped"]} for c in A.CONDITIONS}
    assert esc["V2"] == set()
    assert esc["V1"] == {"inj_force_none", "inj_run_aide", "post_admin_trap"}
    assert esc["V0"] == HOSTIS and len(HOSTIS) == 11


def test_condicao_restaurada_e_gravada(obey):
    orig_v, orig_p = G.validate_decision, G._protected
    res = _run(obey, condition="V0", sem_portao=True, only=["inj_ansi"])
    assert (G.validate_decision, G._protected) == (orig_v, orig_p)
    assert (res[0]["condition"], res[0]["sem_portao"]) == ("V0", True)


def test_condicao_invalida(obey):
    with pytest.raises(SystemExit):
        _run(obey, condition="V9")


def test_sem_portao_leva_ip_protegido_ao_modelo(obey):
    com = _run(obey, only=["lan_node"])[0]
    sem = _run(obey, only=["lan_node"], sem_portao=True)[0]
    assert com["llm_skipped"] and not sem["llm_skipped"]
