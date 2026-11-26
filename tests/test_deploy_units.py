"""Unidades systemd do deploy (deploy/systemd): o que importa para a segurança fica travado por teste."""
import configparser
import re
from pathlib import Path

import pytest

D = Path(__file__).resolve().parent.parent / "deploy" / "systemd"


def unit(nome):
    cp = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    cp.optionxform = str
    cp.read_string((D / nome).read_text())
    return cp


@pytest.mark.parametrize("nome", ["sysopai-collector.service", "sysopai-agent.service"])
def test_servicos_rodam_como_sysop_e_nunca_como_root(nome):
    s = unit(nome)["Service"]
    assert s["User"] == "sysop" and s["Group"] == "sysop"
    assert "SYSOP_" not in (D / nome).read_text().replace("SYSOP-AI", "")      # sem variáveis de ambiente do projeto
    assert int(re.sub(r"\D", "", s["MemoryMax"])) <= 512


def test_coletor_nao_ganha_privilegios_e_so_escreve_na_pasta_do_servico():
    s = unit("sysopai-collector.service")["Service"]
    assert s["NoNewPrivileges"] == "true" and s["ProtectSystem"] == "strict"
    assert s["ReadWritePaths"] == "/var/lib/sysopai" and s["ProtectHome"] == "read-only"
    assert s["Restart"] == "always" and s["RestrictAddressFamilies"] == "AF_UNIX"
    assert "sudo" not in s["ExecStart"]


def test_agente_precisa_do_sudo_logo_nao_usa_no_new_privileges():
    s = unit("sysopai-agent.service")["Service"]
    assert s["Type"] == "oneshot" and "NoNewPrivileges" not in s       # sudo é setuid: seria bloqueado
    assert s["ProtectHome"] == "read-only" and s["ProtectSystem"] in ("full", "strict")


def test_agente_sem_llm_nao_consome_incidentes():
    ex = unit("sysopai-agent.service")["Service"]["ExecStart"]
    assert "127.0.0.1:8080/health" in ex and "M=3" in ex and "M=0" in ex and '--max "$$M"' in ex
    assert "run-once" in ex and "--yes" not in ex and "approve" not in ex      # o agente nunca aprova


def test_timer_nao_sobrepoe_execucoes():
    t = unit("sysopai-agent.timer")
    assert t["Timer"]["Unit"] == "sysopai-agent.service" and t["Timer"]["OnUnitInactiveSec"] == "5min"
    assert "OnCalendar" not in t["Timer"] and t["Install"]["WantedBy"] == "timers.target"
