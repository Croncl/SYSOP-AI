"""Pipeline RAG: curadoria -> chunks -> memória (sqlite-vec) -> recuperação.

Regras: só texto CURADO entra (kb e resolution, escritos por humanos); log bruto nunca entra.
O texto recuperado é dado não confiável: o grafo o coloca em <memory> e o sanitiza.
O embedder é injetado (passo 9); aqui nada depende do modelo.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Callable

import db

MAX_CHARS = 1000                      # abaixo do limite de 1200 do mem_docs
ALLOWED_KINDS = ("resolution", "kb")  # 'incident' só será gravado pelo código (resumo por template)
Embed = Callable[[str], list[float]]
# Corte EMPÍRICO (passo 10): relevantes ficaram em 0,35-0,46 e irrelevantes em 0,56-0,73 (12 consultas).
# Filtro grosseiro de ruído, não decisão de relevância; recalibrar quando a base crescer.
MAX_DISTANCE = float(os.environ.get("SYSOP_RAG_MAX_DISTANCE", "0.50"))


def chunk_text(text: str, max_chars: int = MAX_CHARS) -> list[str]:
    """Junta parágrafos até max_chars; parágrafo maior que o limite é cortado em fatias."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    out: list[str] = []
    cur = ""
    for p in paras:
        while len(p) > max_chars:
            if cur:
                out.append(cur)
                cur = ""
            out.append(p[:max_chars])
            p = p[max_chars:]
        if cur and len(cur) + 2 + len(p) > max_chars:
            out.append(cur)
            cur = p
        else:
            cur = f"{cur}\n\n{p}" if cur else p
    if cur:
        out.append(cur)
    return out


def split_sections(md: str) -> list[str]:
    """Cada seção '## Título' de um markdown vira um documento. O texto antes da primeira seção é ignorado."""
    parts = re.split(r"(?m)^## ", md)
    return [("## " + s).strip() for s in parts[1:] if s.strip()]


def ingest_text(con, embed: Embed, kind: str, text: str, incident_id: int | None = None) -> int:
    """Ingere texto curado. Retorna quantos chunks são novos (idempotente)."""
    if kind not in ALLOWED_KINDS:
        raise ValueError(f"tipo não permitido na ingestão: {kind}")
    return sum(db.mem_add(con, embed, kind, ch, incident_id) is not None for ch in chunk_text(text))


def ingest_kb_file(con, embed: Embed, path: str | Path) -> dict:
    md = Path(path).read_text(encoding="utf-8")
    total = novos = 0
    for sec in split_sections(md):
        for ch in chunk_text(sec):
            total += 1
            novos += db.mem_add(con, embed, "kb", ch) is not None
    con.commit()
    return {"chunks": total, "novos": novos}


def make_retriever(con, embed: Embed, k: int = 2, max_distance: float = MAX_DISTANCE):
    """Devolve a função que o grafo espera: consulta -> lista de trechos (a distância só ORDENA)."""
    def retrieve(query: str) -> list[dict]:
        try:
            res = db.mem_search(con, embed, query, k=k)
            return [r for r in res if r["distance"] <= max_distance]
        except Exception:  # embedder fora do ar: o agente segue sem memória, nunca para a análise
            return []
    return retrieve


_KIND_TEXT = {
    "ssh_bruteforce": "brute force SSH: várias falhas de autenticação de um mesmo IP",
    "port_scan": "varredura de portas (port scan)",
    "integrity_change": "alteração de integridade de arquivos",
}


def build_query(kind: str, severity: str, n_events: int, ip_protected: bool) -> str:
    """Consulta montada pelo CÓDIGO a partir de fatos do incidente (nunca de texto do log)."""
    kind = re.sub(r"[^a-z0-9_]", "", str(kind).lower())[:40]
    severity = re.sub(r"[^a-z]", "", str(severity).lower())[:10]
    base = _KIND_TEXT.get(kind, kind.replace("_", " "))
    q = f"{base}, {int(n_events)} eventos, severidade {severity}"
    if ip_protected:
        q += "; o IP de origem está em rede protegida e pode ser o administrador; posso bloquear?"
    return q
