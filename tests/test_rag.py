import hashlib
import re
from pathlib import Path

import pytest

import db
import rag


@pytest.fixture
def con(tmp_path):
    c = db.init(str(tmp_path / "t.db"))
    yield c
    c.close()


def _emb(text):  # embedding falso, determinístico e distinto por texto
    v = [0.0] * db.EMBED_DIM
    v[int(hashlib.sha256(text.encode()).hexdigest()[:8], 16) % db.EMBED_DIM] = 1.0
    return v


def _squash(s):
    return re.sub(r"\s", "", s)


def test_chunk_respeita_limite_e_nao_perde_texto():
    texto = "A" * 2500 + "\n\n" + "curto um" + "\n\n" + "curto dois"
    chunks = rag.chunk_text(texto, max_chars=1000)
    assert all(len(c) <= 1000 for c in chunks)
    assert _squash("".join(chunks)) == _squash(texto)
    assert rag.chunk_text("   \n\n  ") == []


def test_split_sections():
    md = "# Título\npreâmbulo\n\n## Um\ntexto um\n\n## Dois\ntexto dois\n"
    assert rag.split_sections(md) == ["## Um\ntexto um", "## Dois\ntexto dois"]


def test_ingest_text_so_kinds_permitidos(con):
    with pytest.raises(ValueError):
        rag.ingest_text(con, _emb, "incident", "texto")
    assert rag.ingest_text(con, _emb, "resolution", "banimos o IP após 30 falhas") == 1


def test_ingest_kb_idempotente(con, tmp_path):
    f = tmp_path / "kb.md"
    f.write_text("## Um\ntexto um\n\n## Dois\ntexto dois\n", encoding="utf-8")
    assert rag.ingest_kb_file(con, _emb, f) == {"chunks": 2, "novos": 2}
    assert rag.ingest_kb_file(con, _emb, f) == {"chunks": 2, "novos": 0}


def test_kb_real_do_projeto(con):
    kb = Path(__file__).resolve().parent.parent / "kb" / "procedimentos.md"
    r = rag.ingest_kb_file(con, _emb, kb)
    assert r["chunks"] >= 4 and r["novos"] == r["chunks"]
    assert con.execute("SELECT max(length(text)) FROM mem_docs").fetchone()[0] <= 1200


def test_retriever(con, tmp_path):
    f = tmp_path / "kb.md"
    f.write_text("## Um\ntexto um\n\n## Dois\ntexto dois\n", encoding="utf-8")
    rag.ingest_kb_file(con, _emb, f)
    r = rag.make_retriever(con, _emb, k=1)("## Dois\ntexto dois")
    assert r[0]["text"] == "## Dois\ntexto dois" and r[0]["kind"] == "kb" and r[0]["distance"] < 0.01


def test_falha_de_embedding_nao_grava_nada(con):
    def boom(t):
        raise RuntimeError("embed fora")
    with pytest.raises(RuntimeError):
        db.mem_add(con, boom, "kb", "texto")
    assert con.execute("SELECT count(*) FROM mem_docs").fetchone()[0] == 0
