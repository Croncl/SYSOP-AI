import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import db
import embed
import rag


class _H(BaseHTTPRequestHandler):
    mode = "ok"
    seen: list = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, body))
        if self.mode == "500":
            self.send_response(500)
            self.end_headers()
            return
        if self.mode == "lixo":
            payload = b"isto nao e json"
        elif self.mode == "dim3":
            payload = json.dumps({"data": [{"embedding": [0.1, 0.2, 0.3]}]}).encode()
        else:  # vetor one-hot determinístico por texto
            v = [0.0] * db.EMBED_DIM
            v[int(hashlib.sha256(body["input"].encode()).hexdigest()[:8], 16) % db.EMBED_DIM] = 1.0
            payload = json.dumps({"data": [{"embedding": v}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


@pytest.fixture
def url():
    _H.mode, _H.seen = "ok", []
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}/v1"
    srv.shutdown()
    srv.server_close()


@pytest.fixture
def con(tmp_path):
    c = db.init(str(tmp_path / "t.db"))
    yield c
    c.close()


def test_ok_e_formato_da_requisicao(url):
    v = embed.make_embedder(url)("texto de teste")
    assert len(v) == db.EMBED_DIM
    path, body = _H.seen[0]
    assert path == "/v1/embeddings" and body == {"input": "texto de teste", "model": "bge-m3"}


@pytest.mark.parametrize("mode", ["dim3", "lixo", "500"])
def test_respostas_ruins_viram_embederror(url, mode):
    _H.mode = mode
    with pytest.raises(embed.EmbedError):
        embed.make_embedder(url)("texto")


def test_servidor_fora_e_texto_vazio():
    with pytest.raises(embed.EmbedError):
        embed.make_embedder("http://127.0.0.1:1/v1", timeout=2)("texto")
    with pytest.raises(embed.EmbedError):
        embed.make_embedder("http://127.0.0.1:1/v1")("   ")


def test_integracao_ingestao_e_busca(url, con):
    e = embed.make_embedder(url)
    assert rag.ingest_text(con, e, "kb", "procedimento para banir ip") == 1
    r = rag.make_retriever(con, e, k=1)("procedimento para banir ip")
    assert r and r[0]["text"] == "procedimento para banir ip" and r[0]["distance"] < 0.01


def test_retriever_degrada_para_vazio(url, con):
    _H.mode = "500"
    assert rag.make_retriever(con, embed.make_embedder(url), k=1)("qualquer consulta") == []
