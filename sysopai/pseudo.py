"""Pseudonimização de IP (passo 12): HMAC-SHA256 com chave, 16 hex.

Não é anonimização: quem tem a chave pode VERIFICAR um IP (calcular o pseudônimo e comparar) ou enumerar o
espaço IPv4 por tentativa. Sem a chave não há como reverter. Apagar a chave torna os pseudônimos antigos
efetivamente anônimos. Sem chave disponível devolve 'ip:sem-chave' (nunca o IP). Só stdlib; não importa db.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets

_CACHE: dict = {}
_V4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
_V6 = re.compile(r"(?<![0-9A-Fa-f:])[0-9A-Fa-f:]{3,39}(?![0-9A-Fa-f:])")


def key_path() -> str:
    return os.environ.get("SYSOP_PSEUDONYM_KEY", "/etc/sysopai/pseudonym.key")


def reset_cache() -> None:
    _CACHE.clear()


def get_key() -> bytes | None:
    p = key_path()
    if p not in _CACHE:
        try:
            k = bytes.fromhex(open(p).read().strip())
            _CACHE[p] = k if len(k) >= 16 else None
        except (OSError, ValueError):
            _CACHE[p] = None
    return _CACHE[p]


def ensure_key(path: str | None = None) -> bool:
    """Cria a chave (32 bytes aleatórios, modo 0600) se não existir. Nunca sobrescreve."""
    p = path or key_path()
    if os.path.exists(p):
        return False
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32) + "\n")
    reset_cache()
    return True


def pseudonym(ip: str) -> str:
    try:
        norm = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return "ip:invalido"
    k = get_key()
    if k is None:
        return "ip:sem-chave"
    return "ip:" + hmac.new(k, norm.encode(), hashlib.sha256).hexdigest()[:16]


def _sub4(m: re.Match) -> str:
    try:
        ipaddress.IPv4Address(m.group(0))
    except ValueError:
        return m.group(0)
    return pseudonym(m.group(0))


def _sub6(m: re.Match) -> str:
    t = m.group(0)
    if t.count(":") < 2:
        return t
    try:
        ipaddress.IPv6Address(t)
    except ValueError:
        return t
    return pseudonym(t)


def scrub(text: str) -> str:
    """Troca todo IP (v4 e v6) do texto pelo pseudônimo. Idempotente; deixa horas, MACs e versões intactos."""
    return _V6.sub(_sub6, _V4.sub(_sub4, text))
