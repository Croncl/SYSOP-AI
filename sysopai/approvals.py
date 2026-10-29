"""Aprovações humanas em arquivo SEPARADO do banco do serviço (P36).

O serviço (usuário sysop) só LÊ este arquivo; quem escreve é o administrador, pela CLI. Assim, um agente
comprometido não consegue se auto-aprovar escrevendo 'approved' no próprio banco.
A aprovação amarra id + data da ação + ferramenta + argumentos (hash): alterar qualquer um invalida.
Falha fechada: arquivo ausente, corrompido, vencido ou divergente => sem aprovação.
Journal_mode=DELETE (e não WAL): um leitor somente-leitura não consegue abrir WAL sem escrever o -shm.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

APPROVALS_PATH = os.environ.get("SYSOP_APPROVALS_DB", "/var/lib/sysopai-approvals/approvals.db")
MAX_AGE_S = 24 * 3600          # aprovação velha não vale: o mundo muda
SERVICE_USER = "sysop"

SCHEMA = """
CREATE TABLE IF NOT EXISTS approvals (
    action_id   INTEGER PRIMARY KEY,
    action_ts   INTEGER NOT NULL,
    tool        TEXT    NOT NULL,
    digest      TEXT    NOT NULL,
    approved_by TEXT    NOT NULL CHECK (approved_by <> '' AND approved_by <> 'agent'
                                        AND approved_by <> 'sysop' AND approved_by NOT LIKE 'policy:%'),
    approved_at INTEGER NOT NULL
);
"""


def digest(action_id: int, ts: int, tool: str, args_json: str) -> str:
    payload = json.dumps({"id": int(action_id), "ts": int(ts), "tool": tool, "args": json.loads(args_json)},
                         sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def init(path: str | None = None) -> None:
    con = sqlite3.connect(path or APPROVALS_PATH, timeout=5)
    con.execute("PRAGMA journal_mode = DELETE")
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def grant(action_row, admin: str, path: str | None = None, now: int | None = None) -> None:
    """Registra a aprovação de um humano para ESTA ação (que deve estar 'pending')."""
    if not admin or admin in ("agent", SERVICE_USER) or admin.startswith("policy:"):
        raise PermissionError("aprovação exige humano")
    if action_row["status"] != "pending":
        raise ValueError("só ações pendentes podem ser aprovadas")
    d = digest(action_row["id"], action_row["ts"], action_row["tool"], action_row["args_json"])
    con = sqlite3.connect(path or APPROVALS_PATH, timeout=5)
    try:
        con.execute("INSERT INTO approvals VALUES (?,?,?,?,?,?)",
                    (action_row["id"], action_row["ts"], action_row["tool"], d, admin, now or int(time.time())))
        con.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError("ação já aprovada") from exc
    finally:
        con.close()


def approver(action_row, path: str | None = None, now: int | None = None) -> str | None:
    """Quem aprovou, se houver aprovação válida, fresca e idêntica para ESTA ação; senão None (falha fechada)."""
    path = path or APPROVALS_PATH
    now = now or int(time.time())
    try:
        if not Path(path).exists():
            return None
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        try:
            row = con.execute("SELECT digest, approved_by, approved_at FROM approvals WHERE action_id=?",
                              (action_row["id"],)).fetchone()
        finally:
            con.close()
        if row is None:
            return None
        d, by, at = row
        if d != digest(action_row["id"], action_row["ts"], action_row["tool"], action_row["args_json"]):
            return None
        if not (0 <= now - at <= MAX_AGE_S):
            return None
        if not by or by in ("agent", SERVICE_USER) or by.startswith("policy:"):
            return None
        return by
    except (sqlite3.Error, ValueError, KeyError, TypeError, OSError):
        return None
