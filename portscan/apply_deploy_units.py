#!/usr/bin/env python3
"""Cria as unidades systemd do coletor e do agente (passo 14.2, item 2) em deploy/systemd/ e um teste das que
importam para a segurança (tests/test_deploy_units.py). NÃO instala nada no sistema: a instalação é um passo à parte.

  * seguro: não sobrescreve arquivo existente; idempotente (se já existem iguais, diz "já aplicado").

    python portscan/apply_deploy_units.py        # na raiz do projeto (ou com o script em uma subpasta)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIR = ROOT / "deploy" / "systemd"

COLLECTOR = r"""# SYSOP-AI: coletor (journald -> SQLite). Roda como 'sysop', sem root e sem privilégios novos.
# Caminhos do código: hoje /home/projetos/SYSOP-AI; ao mover o código para uma pasta de dono root (passo 14.2, item 3),
# trocar nas duas linhas ExecStart e ProtectHome.
[Unit]
Description=SYSOP-AI coletor (journald para SQLite)
After=systemd-journald.service

[Service]
Type=simple
User=sysop
Group=sysop
WorkingDirectory=/var/lib/sysopai
Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ExecStart=/home/projetos/SYSOP-AI/venv/bin/python /home/projetos/SYSOP-AI/sysopai/collector.py
# o coletor encerra com código 0 se o journalctl terminar: reiniciar sempre
Restart=always
RestartSec=5

# endurecimento (o coletor só lê o journal e grava em /var/lib/sysopai)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/sysopai
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX
MemoryMax=512M

[Install]
WantedBy=multi-user.target
"""

AGENT = r"""# SYSOP-AI: agente. Cada execução analisa até 3 incidentes abertos (1 chamada ao LLM cada) e executa SÓ o que um
# humano aprovou no approvals.db. Sem NoNewPrivileges de propósito: o ban passa por 'sudo' (sudoers restrito).
# Se o LLM não responde, roda com --max 0: executa o aprovado e NÃO consome incidentes (evita fallback sem análise).
[Unit]
Description=SYSOP-AI agente (analisa incidentes e executa o que foi aprovado)
After=network.target

[Service]
Type=oneshot
User=sysop
Group=sysop
WorkingDirectory=/var/lib/sysopai
Environment=PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ExecStart=/bin/sh -c 'if curl -sf --max-time 5 http://127.0.0.1:8080/health >/dev/null; then M=3; else M=0; echo "LLM indisponivel: executa so o aprovado"; fi; exec /home/projetos/SYSOP-AI/venv/bin/python /home/projetos/SYSOP-AI/sysopai/cli.py run-once --max "$$M"'
TimeoutStartSec=30min

PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
MemoryMax=512M
"""

TIMER = r"""# SYSOP-AI: dispara o agente 3 min após o boot e, depois, 5 min após o FIM de cada execução (sem sobreposição).
[Unit]
Description=SYSOP-AI agente (periódico)

[Timer]
OnBootSec=3min
OnUnitInactiveSec=5min
AccuracySec=30s
Unit=sysopai-agent.service

[Install]
WantedBy=timers.target
"""

TEST = r'''"""Unidades systemd do deploy (deploy/systemd): o que importa para a segurança fica travado por teste."""
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
'''

FILES = {
    DIR / "sysopai-collector.service": COLLECTOR,
    DIR / "sysopai-agent.service": AGENT,
    DIR / "sysopai-agent.timer": TIMER,
    ROOT / "tests" / "test_deploy_units.py": TEST,
}


def main() -> int:
    estado = {p: (p.exists() and p.read_text() == c) for p, c in FILES.items()}
    if all(estado.values()):
        print("já aplicado, nada a fazer")
        return 0
    existe_diferente = [p for p, c in FILES.items() if p.exists() and p.read_text() != c]
    if existe_diferente:
        print("ERRO: já existem e são diferentes (não sobrescrevo):", *map(str, existe_diferente))
        return 1
    DIR.mkdir(parents=True, exist_ok=True)
    for p, c in FILES.items():
        if not p.exists():
            p.write_text(c)
            print("criado:", p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
