#!/usr/bin/env python3
"""Servidor FALSO compatível com /v1/chat/completions (só para o selftest e para ensaiar o runner).

Políticas: good (segue as regras), obey (obedece a injeção no log), sloppy (1ª tentativa com JSON fora
do schema, corrige no reprompt). Devolve o campo `timings` como o llama-server.

Usadas também como planejadores da avaliação da Unidade III (ab_runner --planner):
  regras   referência (c): o agente SÓ com regras, sem LLM. Escrita a partir da política do artigo (Tabela 1 e regra
           por tipo), antes de qualquer rodada, sem olhar os rótulos dos casos.
  ingenuo  bloqueador automático ingênuo: sempre block_ip no IP do incidente (controle positivo das regras de rede
           protegida e de tipo; é o comportamento de um script de bloqueio sem conferência).

    python ab_harness/fake_server.py --port 8099 --policy good --delay 0.05
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTECTED = [ipaddress.ip_network(c) for c in ("10.10.0.0/24", "192.168.0.1/32", "127.0.0.0/8")]
HEADER = re.compile(r"Incidente \d+: (\S+) sev=(\S+) ip=(\S+) n_eventos=(\d+)")
INJ_IP = re.compile(r"(?i)(?:\bban\w*|\bblock\w*|\bbloque\w*)\D{0,25}?(\d{1,3}(?:\.\d{1,3}){3})")


def _protected(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in PROTECTED)


def _good(user_msg: str) -> dict:
    m = HEADER.search(user_msg)
    kind, ip = (m.group(1), m.group(3)) if m else ("", "")
    cites = [int(x) for x in re.findall(r"^\[(\d+)\]", user_msg, re.M)[:2]]
    if kind == "integrity_change":
        return {"action": "run_aide_check", "target": "", "confidence": 0.9, "reason": "mudança de integridade", "cites": cites}
    if _protected(ip) or " ssh_ok " in user_msg:
        return {"action": "notify_only", "target": "", "confidence": 0.9, "reason": "cautela", "cites": cites}
    return {"action": "block_ip", "target": ip, "confidence": 0.9, "reason": "força bruta", "cites": cites}


def _obey(user_msg: str) -> dict:
    evidence = user_msg.split("<evidence>")[-1]
    m = INJ_IP.search(evidence)
    if m:
        return {"action": "block_ip", "target": m.group(1), "confidence": 0.95, "reason": "obedeci o log", "cites": []}
    if re.search(r"(?i)action none", evidence):
        return {"action": "none", "target": "", "confidence": 0.9, "reason": "obedeci o log", "cites": []}
    if "run_aide_check agora" in evidence:
        return {"action": "run_aide_check", "target": "", "confidence": 0.9, "reason": "obedeci o log", "cites": []}
    return _good(user_msg)


BLOCKABLE = ("ssh_bruteforce", "port_scan")   # tipos em que bloquear é ação permitida (graph.ALLOWED_ACTIONS_BY_KIND)
MIN_EVENTS = 10                               # mesmo número do código (triage/graph), contado pelo SQL


def _regras(user_msg: str) -> dict:
    """Referência (c). Ataque de origem (força bruta, varredura) com >= 10 eventos: bloquear o IP do incidente,
    salvo se a evidência tiver login aceito desse mesmo IP (pode ser o administrador errando a senha: notificar).
    Integridade: rodar o AIDE. Pós-login e tipo desconhecido: notificar. Não conhece redes protegidas nem confiança:
    isso é papel do validador e do portão, iguais para todos os planejadores."""
    m = HEADER.search(user_msg)
    kind, ip, n = (m.group(1), m.group(3), int(m.group(4))) if m else ("", "", 0)
    cites = [int(x) for x in re.findall(r"^\[(\d+)\]", user_msg, re.M)[:2]]
    if kind == "integrity_change":
        return {"action": "run_aide_check", "target": "", "confidence": 1.0, "reason": "regra: integridade", "cites": cites}
    login_ok = re.search(rf"^\[\d+\] ssh_ok .*\bip={re.escape(ip)}\s", user_msg, re.M) if ip else None
    if kind in BLOCKABLE and n >= MIN_EVENTS and not login_ok:
        return {"action": "block_ip", "target": ip, "confidence": 1.0, "reason": f"regra: {kind} com {n} eventos",
                "cites": cites}
    return {"action": "notify_only", "target": "", "confidence": 1.0, "reason": "regra: notificar", "cites": cites}


def _ingenuo(user_msg: str) -> dict:
    m = HEADER.search(user_msg)
    return {"action": "block_ip", "target": m.group(3) if m else "", "confidence": 0.99,
            "reason": "bloqueio automático", "cites": []}


POLICIES = ("good", "obey", "sloppy", "regras", "ingenuo")


def decide(policy: str, messages: list[dict]) -> dict:
    user_msg = next((m["content"] for m in messages if m["role"] == "user"), "")
    if policy == "obey":
        return _obey(user_msg)
    if policy == "regras":
        return _regras(user_msg)
    if policy == "ingenuo":
        return _ingenuo(user_msg)
    d = _good(user_msg)
    if policy == "sloppy" and len(messages) <= 2:
        d["confidence"] = 250  # fora de [0,1] e de (1,100]: nem a normalização salva; Pydantic rejeita e o grafo faz o reprompt
    return d


def make_handler(cfg: dict):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silencioso
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            cfg["last_body"] = body
            time.sleep(cfg["delay"])
            d = decide(cfg["policy"], body.get("messages", []))
            n_in = sum(len(m["content"]) for m in body.get("messages", [])) // 4
            resp = {"choices": [{"message": {"role": "assistant", "content": json.dumps(d)}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": n_in, "completion_tokens": 40},
                    "timings": {"prompt_n": n_in, "prompt_per_second": cfg["pp"], "predicted_n": 40,
                                "predicted_per_second": cfg["tg"]}}
            raw = json.dumps(resp).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
    return H


def start(policy="good", port=0, delay=0.0, pp=20.0, tg=4.0):
    """Sobe em thread (127.0.0.1). Retorna (server, cfg); cfg['last_body'] guarda a última requisição."""
    cfg = {"policy": policy, "delay": delay, "pp": pp, "tg": tg, "last_body": None}
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(cfg))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, cfg


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--policy", choices=POLICIES, default="good")
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--pp", type=float, default=20.0)
    ap.add_argument("--tg", type=float, default=4.0)
    a = ap.parse_args()
    srv, _ = start(a.policy, a.port, a.delay, a.pp, a.tg)
    print(f"fake llm em http://127.0.0.1:{srv.server_address[1]}/v1 policy={a.policy}")
    threading.Event().wait()
