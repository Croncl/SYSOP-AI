"""Acesso ao SQLite (WAL) e à memória vetorial (sqlite-vec). Sem dependências além de sqlite-vec."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import time
from pathlib import Path
from typing import Callable, Iterable

DB_PATH = os.environ.get("SYSOP_DB", "/var/lib/sysopai/sysop.db")
EMBED_DIM = 1024  # bge-m3
HERE = Path(__file__).resolve().parent


def _load_vec(con: sqlite3.Connection) -> bool:
    try:
        import sqlite_vec
        con.enable_load_extension(True)
        sqlite_vec.load(con)
        con.enable_load_extension(False)
        return True
    except Exception:
        return False


def connect(path: str | None = None, *, readonly: bool = False, vec: bool = False) -> sqlite3.Connection:
    """readonly=True abre com mode=ro: o agente/dashboard nunca escrevem por essa conexão."""
    path = path or DB_PATH
    if readonly:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        con.execute("PRAGMA query_only = ON")
    else:
        con = sqlite3.connect(path, timeout=5)
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA synchronous = NORMAL")  # seguro em WAL; reduz fsync no NVMe
        con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA busy_timeout = 5000")
    con.row_factory = sqlite3.Row
    if vec:
        _load_vec(con)
    return con


def init(path: str | None = None) -> sqlite3.Connection:
    con = connect(path, vec=True)
    con.executescript((HERE / "schema.sql").read_text())
    try:
        con.execute(
            f"CREATE VIRTUAL TABLE IF NOT EXISTS mem_vec USING vec0("
            f"embedding float[{EMBED_DIM}] distance_metric=cosine, kind text)"
        )
    except sqlite3.OperationalError:
        pass  # sem sqlite-vec: o agente funciona sem RAG (retriever devolve [])
    con.commit()
    return con


def audit(con: sqlite3.Connection, actor: str, event: str, detail: dict | str) -> None:
    con.execute("INSERT INTO audit_log(ts,actor,event,detail) VALUES (?,?,?,?)",
                (int(time.time()), actor, event, detail if isinstance(detail, str) else json.dumps(detail)[:4000]))


# ----------------------------- memória vetorial ----------------------------------
def _blob(v: Iterable[float]) -> bytes:
    v = list(v)
    return struct.pack(f"{len(v)}f", *v)


def mem_add(con: sqlite3.Connection, embed: Callable[[str], list[float]], kind: str, text: str,
            incident_id: int | None = None) -> int | None:
    """Idempotente (content_sha). Retorna id, ou None se já existia."""
    sha = hashlib.sha256(text.encode()).hexdigest()
    if con.execute("SELECT 1 FROM mem_docs WHERE content_sha=?", (sha,)).fetchone():
        return None
    cur = con.execute("INSERT INTO mem_docs(kind,incident_id,text,content_sha,created_at) VALUES (?,?,?,?,?)",
                      (kind, incident_id, text[:1200], sha, int(time.time())))
    rid = cur.lastrowid
    con.execute("INSERT INTO mem_vec(rowid, embedding, kind) VALUES (?,?,?)", (rid, _blob(embed(text)), kind))
    return rid


def mem_search(con: sqlite3.Connection, embed: Callable[[str], list[float]], query: str,
               k: int = 2, kinds: tuple[str, ...] = ("incident", "resolution", "kb")) -> list[dict]:
    """A distância ORDENA; não é limiar de acerto (lição do lab de RAG do consolidado)."""
    try:
        rows = con.execute(
            "SELECT rowid, distance FROM mem_vec WHERE embedding MATCH ? AND k = ? ORDER BY distance",
            (_blob(embed(query)), k * 3)).fetchall()
    except sqlite3.OperationalError:
        return []
    out = []
    for r in rows:
        d = con.execute("SELECT id, kind, incident_id, text FROM mem_docs WHERE id=?", (r["rowid"],)).fetchone()
        if d and d["kind"] in kinds:
            out.append({"id": d["id"], "kind": d["kind"], "incident_id": d["incident_id"],
                        "text": d["text"], "distance": round(r["distance"], 4)})
        if len(out) >= k:
            break
    return out
