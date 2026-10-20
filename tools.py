"""Catálogo de tools nativas. Cada tool: modelo Pydantic dos argumentos + classe de risco (read|write).

Nunca shell=True; argumentos validados antes de virar argv; saída truncada; timeout sempre.
O serviço roda como usuário 'sysop' sem root: comandos privilegiados passam por sudoers restrito
(ver doc, seção Hardening). Tools 'write' só executam com approval=True vindo do banco (HITL).
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Literal

from pydantic import BaseModel, Field, field_validator

from triage import sanitize

MAX_OUT = 4000


def _run(argv: list[str], timeout: int = 20, sudo: bool = False) -> tuple[int, str]:
    if sudo:
        argv = ["sudo", "-n", *argv]
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        return p.returncode, (p.stdout + p.stderr)[:MAX_OUT]
    except FileNotFoundError:
        return 127, f"comando ausente: {argv[0]}"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def parse_ip(s: str) -> str:
    return str(ipaddress.ip_address(s.strip()))  # ValueError se inválido; normaliza


# ------------------------------- argumentos -------------------------------------
class NoArgs(BaseModel):
    pass


class BanArgs(BaseModel):
    ip: str
    jail: Literal["sshd"] = "sshd"  # lista fechada de jails

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str) -> str:
        return parse_ip(v)


class JournalArgs(BaseModel):
    unit: Literal["ssh", "sshd", "sudo", "fail2ban", "ufw", "k3s", "systemd-logind"] = "ssh"
    since: str = Field("30 min ago", pattern=r"^\d{1,4} (min|hour|day)s? ago$")
    limit: int = Field(50, ge=1, le=200)


# --------------------------------- tools ----------------------------------------
def check_ufw_status(_: NoArgs) -> dict:
    rc, out = _run(["ufw", "status", "numbered"], sudo=True)
    return {"rc": rc, "active": "Status: active" in out, "text": out}


def ban_ip_fail2ban(a: BanArgs) -> dict:
    rc, out = _run(["fail2ban-client", "set", a.jail, "banip", a.ip], sudo=True)
    return {"rc": rc, "ip": a.ip, "jail": a.jail, "text": out}


def is_banned(ip: str, jail: str = "sshd") -> bool:
    """Verificação INDEPENDENTE da chamada de ban (usada pelo nó Reflect): consulta o estado real."""
    rc, out = _run(["fail2ban-client", "get", jail, "banip"], sudo=True)
    if rc == 0 and re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", out):
        return True
    rc, out = _run(["ufw", "status"], sudo=True)  # fail2ban com banaction=ufw também aparece aqui
    return rc == 0 and re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", out) is not None


def run_aide_check(_: NoArgs) -> dict:
    # Pesado (I/O + CPU, minutos): rodar sob nice/ionice e só agendado ou aprovado.
    rc, out = _run(["nice", "-n", "19", "ionice", "-c3", "aide", "--check"], timeout=1800, sudo=True)
    keep = [l for l in out.splitlines() if re.match(r"^(Total number|Added|Removed|Changed|AIDE|Summary)", l.strip(), re.I)]
    return {"rc": rc, "clean": rc == 0, "summary": "\n".join(keep[:20])}


def query_journald(a: JournalArgs) -> dict:
    rc, out = _run(["journalctl", "-u", a.unit, "--since", a.since, "-n", str(a.limit), "-o", "cat", "--no-pager"])
    return {"rc": rc, "lines": [sanitize(l, 200) for l in out.splitlines()[-a.limit:]]}


@dataclass(frozen=True)
class Tool:
    name: str
    fn: Callable
    args: type[BaseModel]
    risk: Literal["read", "write"]
    doc: str


REGISTRY: dict[str, Tool] = {t.name: t for t in [
    Tool("check_ufw_status", check_ufw_status, NoArgs, "read", "Estado do UFW"),
    Tool("query_journald", query_journald, JournalArgs, "read", "Últimas linhas do journal de uma unidade"),
    Tool("run_aide_check", run_aide_check, NoArgs, "read", "Verificação de integridade AIDE (pesada)"),
    Tool("ban_ip_fail2ban", ban_ip_fail2ban, BanArgs, "write", "Bane um IP no jail sshd"),
]}


def call_tool(name: str, raw_args: dict, *, approved: bool = False, action_id: int | None = None) -> dict:
    """Único ponto de execução. Valida args (Pydantic) e bloqueia 'write' sem aprovação humana."""
    t = REGISTRY.get(name)
    if t is None:
        raise PermissionError(f"tool desconhecida: {name}")
    if t.risk == "write" and not approved:
        raise PermissionError(f"tool de escrita exige aprovação: {name}")
    return t.fn(t.args.model_validate(raw_args))


def is_protected(con, ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    for (cidr,) in con.execute("SELECT cidr FROM protected_networks"):
        if addr.version == ipaddress.ip_network(cidr, strict=False).version and addr in ipaddress.ip_network(cidr, strict=False):
            return True
    return False
