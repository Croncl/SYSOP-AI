"""Avaliação da recuperação com o modelo REAL (precisa do llama-embed em 127.0.0.1:8081).

Uso: python scripts/eval_rag.py
Cada caso: (consulta, títulos aceitáveis). Lista vazia = fora do assunto: o retriever deve devolver NADA
(depois do corte de distância). O grafo injeta k=2 trechos, então o critério de aprovação é
"algum dos 2 devolvidos é aceitável"; o acerto no 1º resultado (top1) é impresso ao lado, sem esconder.
Sai com código 1 se algum caso falhar.
"""
import os
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(AQUI, "..", "sysopai"))
import db, embed, rag  # noqa: E402

Q = rag.build_query
CASOS = [
    (Q("ssh_bruteforce", "medium", 30, False), ["Brute force"]),
    (Q("ssh_bruteforce", "high", 60, True), ["Falhas de login", "Redes que nunca"]),
    (Q("port_scan", "medium", 15, False), []),
    (Q("integrity_change", "critical", 3, False), []),
    ("o ip 100.111.186.82 da tailscale pode ser banido?", ["Redes que nunca"]),
    ("como faço unban de um ip", ["Como desfazer"]),
    ("devo bloquear o IP 192.168.0.3 que errou a senha?", ["Falhas de login", "Redes que nunca"]),
    ("quais redes nunca podem ser bloqueadas?", ["Redes que nunca"]),
    ("receita de bolo de chocolate", []),
    ("resultado do campeonato de futebol", []),
    ("como configurar um servidor nginx com https", []),
    ("treinar uma rede neural convolucional", []),
]


def main() -> int:
    emb = embed.make_embedder()
    con = db.init(os.path.join(tempfile.mkdtemp(), "t.db"))
    rag.ingest_kb_file(con, emb, os.path.join(AQUI, "..", "kb", "procedimentos.md"))
    ret = rag.make_retriever(con, emb, k=2)
    falhas = top1_miss = 0
    print(f"corte de distância: {rag.MAX_DISTANCE}")
    for q, aceitos in CASOS:
        cru = db.mem_search(con, emb, q, k=2)
        res = ret(q)
        linhas = [r["text"].splitlines()[0] for r in res]
        if aceitos:
            ok = any(a in l for l in linhas for a in aceitos)
            t1 = bool(linhas) and any(a in linhas[0] for a in aceitos)
            top1_miss += ok and not t1
        else:
            ok, t1 = not res, not res
        falhas += not ok
        d = " ".join(f"{r['distance']:.3f}" for r in cru)
        tit = " + ".join(l[3:28] for l in linhas) or "(nada)"
        print(f"{'OK  ' if ok else 'ERRO'} {'top1' if t1 else '    '} d=[{d}] | {tit} | {q[:60]}")
    print(f"falhas: {falhas}/{len(CASOS)} | acertos só no 2º lugar: {top1_miss}")
    return 1 if falhas else 0


if __name__ == "__main__":
    raise SystemExit(main())
