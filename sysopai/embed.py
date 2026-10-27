"""Cliente de embeddings (llama-server, endpoint OpenAI-compatível). Só stdlib.

Valida o que volta do servidor: dimensão exata (o mem_vec é fixo em 1024) e números finitos.
Qualquer falha vira EmbedError; quem chama decide (ingestão aborta, consulta degrada para sem-RAG).
"""
from __future__ import annotations

import json
import math
import os
import urllib.error
import urllib.request

import db

EMBED_URL = os.environ.get("SYSOP_EMBED_URL", "http://127.0.0.1:8081/v1")
EMBED_MODEL = os.environ.get("SYSOP_EMBED_MODEL", "bge-m3")
MAX_INPUT = 4000  # caracteres; nossos chunks têm até 1.200


class EmbedError(RuntimeError):
    pass


def make_embedder(base_url: str = EMBED_URL, model: str = EMBED_MODEL, timeout: int = 30, dim: int = db.EMBED_DIM):
    def embed(text: str) -> list[float]:
        if not isinstance(text, str) or not text.strip():
            raise EmbedError("texto vazio")
        body = json.dumps({"input": text[:MAX_INPUT], "model": model}).encode()
        req = urllib.request.Request(base_url + "/embeddings", body, {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                v = json.load(r)["data"][0]["embedding"]
        except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:  # URLError e HTTPError são OSError
            raise EmbedError(f"falha no embedding: {type(exc).__name__}") from exc
        if not isinstance(v, list) or len(v) != dim or not all(isinstance(x, (int, float)) and math.isfinite(x) for x in v):
            raise EmbedError(f"vetor inválido (esperado {dim} números finitos)")
        return v

    return embed
