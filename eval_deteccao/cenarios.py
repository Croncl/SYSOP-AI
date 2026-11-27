#!/usr/bin/env python3
"""Cenários SINTÉTICOS de fronteira para a detecção (O3), com gabarito, rodando no PC sem a placa.

Não são medição de ataque real: servem para mostrar, de forma reproduzível, onde os limiares fixos do SYSOP-AI e do
fail2ban acertam e onde falham por projeto (ataque lento, distribuído, IPv6, poucas portas, digitação do admin).
O laboratório na placa (lab/) é a medição real. Cada cenário fica 30 min depois do anterior, com IPs próprios
(faixas de documentação), e o log do UFW passa por um limitador global igual ao da placa (3/min, rajada 10; E52).

    python -m eval_deteccao.cenarios --out-dir evidencias/u3/cenarios
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from eval_deteccao import metricas as M
from eval_deteccao import replay as RP

T0 = 1_800_000_000
GAP = 1800


def _j(ts: float, ident: str, msg: str) -> dict:
    return {"__REALTIME_TIMESTAMP": str(int(ts * 1e6)), "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg,
            "_HOSTNAME": "sintetico"}


def fail(ts, ip, user="root", port=40000):
    return _j(ts, "sshd", f"Failed password for {user} from {ip} port {port} ssh2")


def invalid(ts, ip, user="admin", port=40000):
    return _j(ts, "sshd", f"Invalid user {user} from {ip} port {port}")


def accepted(ts, ip, user="opad", how="password"):
    return _j(ts, "sshd", f"Accepted {how} for {user} from {ip} port 52000 ssh2")


def ufw(ts, ip, dpt):
    return _j(ts, "kernel", f"[UFW BLOCK] IN=wlan0 OUT= MAC=aa:bb SRC={ip} DST=192.168.0.4 LEN=44 TOS=0x00 PROTO=TCP "
                            f"SPT=40000 DPT={dpt} WINDOW=1024 SYN")


def ufw_rate_limit(entries: list[dict], per_min: float = 3, burst: int = 10) -> list[dict]:
    """Limitador GLOBAL do log do UFW (iptables --limit 3/min --limit-burst 10): o que passa dele é o que a placa
    registraria. Linhas que não são do UFW passam direto."""
    tokens, last, out = float(burst), None, []
    for e in sorted(entries, key=RP.ts_of):
        if e["SYSLOG_IDENTIFIER"] != "kernel":
            out.append(e)
            continue
        t = RP.ts_of(e)
        if last is not None:
            tokens = min(burst, tokens + (t - last) * per_min / 60)
        last = t
        if tokens >= 1:
            tokens -= 1
            out.append(e)
    return out


def build() -> tuple[list[dict], list[dict]]:
    """Devolve (entradas do journal, gabarito)."""
    J, G = [], []
    slot = [0]

    def ep(eid, tipo, ip, start, end, esperado, ferramenta, notas):
        G.append({"episodio": eid, "tipo": tipo, "ip": ip, "inicio": start, "fim": end, "esperado": esperado,
                  "ferramenta": ferramenta, "notas": notas})

    def t0():
        slot[0] += 1
        return T0 + slot[0] * GAP

    # ---------------- força bruta SSH ----------------
    t = t0(); ip = "203.0.113.21"
    J += [fail(t + 2 * i, ip, port=40000 + i) for i in range(60)]
    ep("S1-rapida", "ssh_bruteforce", ip, t, t + 120, "detectar", "sintético", "60 falhas em 2 min")
    t = t0(); ip = "203.0.113.22"
    J += [fail(t + 3 * i, ip, port=40000 + i) for i in range(10)]
    ep("S2-no-limiar", "ssh_bruteforce", ip, t, t + 30, "detectar", "sintético", "exatamente 10 falhas")
    t = t0(); ip = "203.0.113.23"
    J += [fail(t + 3 * i, ip, port=40000 + i) for i in range(9)]
    ep("S3-abaixo-do-limiar", "ssh_bruteforce", ip, t, t + 27, "nao_detectar", "sintético", "9 falhas em 30 s")
    t = t0(); ip = "203.0.113.24"
    J += [fail(t + 90 * i, ip, port=40000 + i) for i in range(20)]
    ep("S4-lenta-90s", "ssh_bruteforce", ip, t, t + 90 * 19, "nao_detectar", "sintético", "1 falha a cada 90 s, 30 min")
    t = t0(); ip = "203.0.113.25"
    J += [fail(t + 150 * i, ip, port=40000 + i) for i in range(20)]
    ep("S5-lenta-150s", "ssh_bruteforce", ip, t, t + 150 * 19, "nao_detectar", "sintético", "1 falha a cada 150 s, 50 min")
    t = t0()
    for k in range(4):
        ip = f"198.51.100.{101 + k}"
        J += [fail(t + 7 * i + k, ip, port=41000 + i) for i in range(4)]
        ep(f"S6-distribuida-{k + 1}", "ssh_bruteforce", ip, t, t + 30, "nao_detectar", "sintético",
           "4 IPs x 4 falhas no mesmo minuto")
    t = t0(); ip = "2001:db8::21"
    J += [fail(t + 2 * i, ip, port=40000 + i) for i in range(30)]
    ep("S7-ipv6", "ssh_bruteforce", ip, t, t + 60, "nao_detectar", "sintético", "IPv6: a triagem do SSH só lê IPv4")
    t = t0(); ip = "203.0.113.28"
    J += [invalid(t + 2 * i, ip, user=f"u{i}", port=40000 + i) for i in range(30)]
    ep("S8-invalid-user", "ssh_bruteforce", ip, t, t + 60, "detectar", "sintético",
       "só 'Invalid user' (senha desligada no sshd)")
    # ---------------- benignos (SSH) ----------------
    t = t0(); ip = "198.51.100.50"
    J += [fail(t, ip, "opad"), fail(t + 4, ip, "opad"), accepted(t + 9, ip)]
    ep("B1-admin-erra-2x", "benigno", ip, t, t + 9, "nao_detectar", "sintético", "2 erros e login")
    t = t0(); ip = "198.51.100.51"
    J += [fail(t + 8 * i, ip, "opad") for i in range(6)] + [accepted(t + 60, ip)]
    ep("B2-admin-erra-6x", "benigno", ip, t, t + 60, "nao_detectar", "sintético",
       "6 erros (gerenciador de senha antigo) e login")
    t = t0()
    J += [accepted(t + 30 * i, f"192.0.2.{10 + i}", how="publickey") for i in range(10)]
    for i in range(10):
        ep(f"B3-logins-chave-{i + 1}", "benigno", f"192.0.2.{10 + i}", t, t + 300, "nao_detectar", "sintético",
           "login por chave, sem falhas")
    # ---------------- port scan (o log do UFW passa pelo limitador) ----------------
    t = t0(); ip = "203.0.113.31"
    J += [ufw(t + 0.3 * i, ip, 1 + i) for i in range(100)]
    ep("P1-rapida-100", "port_scan", ip, t, t + 30, "detectar", "sintético", "100 portas em 30 s (o UFW registra ~11)")
    t = t0(); ip = "203.0.113.32"
    J += [ufw(t + 0.3 * i, ip, 1 + i) for i in range(1000)]
    ep("P2-rapida-1000", "port_scan", ip, t, t + 300, "detectar", "sintético", "1000 portas em 5 min")
    t = t0(); ip = "203.0.113.33"
    J += [ufw(t + 3 * i, ip, 2000 + i) for i in range(9)]
    ep("P3-9-portas", "port_scan", ip, t, t + 27, "nao_detectar", "sintético", "9 portas")
    t = t0(); ip = "203.0.113.34"
    J += [ufw(t + 120 * i, ip, 3000 + i) for i in range(20)]
    ep("P4-lenta", "port_scan", ip, t, t + 120 * 19, "nao_detectar", "sintético", "1 porta a cada 2 min, 40 min")
    t = t0(); ip = "203.0.113.35"
    J += [ufw(t + 2 * i, ip, 22) for i in range(300)]
    ep("P5-mesma-porta", "benigno", ip, t, t + 600, "nao_detectar", "sintético", "300 tentativas na porta 22")
    t = t0()
    J += [ufw(t + 20 * i, f"192.0.2.{100 + i}", 5353) for i in range(30)]
    for i in range(30):
        ep(f"P6-ruido-{i + 1}", "benigno", f"192.0.2.{100 + i}", t, t + 600, "nao_detectar", "sintético",
           "1 bloqueio por IP (mDNS)")
    t = t0(); ip = "2001:db8::31"
    J += [ufw(t + 3 * i, ip, 4000 + i) for i in range(15)]
    ep("P7-ipv6-15", "port_scan", ip, t, t + 45, "detectar", "sintético", "15 portas, IPv6 (o UFW aceita)")
    return ufw_rate_limit(J), G


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args(argv)
    out = Path(a.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    entries, gab = build()
    (out / "journal_sintetico.json").write_text("".join(json.dumps(e) + "\n" for e in entries))
    with open(out / "gabarito_sintetico.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(gab[0]))
        w.writeheader()
        w.writerows(gab)
    episodes = M.read_gabarito(out / "gabarito_sintetico.csv")
    entries = RP.load_journal(out / "journal_sintetico.json")
    sets = {"SYSOP-AI": M.sysop_detections(RP.incidents(RP.replay(entries)), "SYSOP-AI (replay)"),
            "fail2ban (simulado)": M.f2b_sim_detections(entries)}
    res, evs = M.evaluate(episodes, entries, sets)
    md, csvs = M.render(episodes, res, evs, sets)
    md = md.replace("# Detecção (O3)", "# Detecção (O3) em cenários SINTÉTICOS de fronteira", 1)
    md = md.replace("\n\n", "\n\n> Gerado por `eval_deteccao/cenarios.py`: não é medição de ataque real. Mostra onde os "
                    "limiares fixos acertam e onde falham por projeto. O log do UFW passa por um limitador global "
                    "igual ao da placa (3/min, rajada 10).\n\n", 1)
    (out / "deteccao_sintetica.md").write_text(md + "\n")
    (out / "csv").mkdir(exist_ok=True)
    for name, (head, body) in csvs.items():
        with open(out / "csv" / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(head)
            w.writerows(body)
    print(f"{out}: {len(episodes)} episódios, {len(entries)} linhas de journal")
    for name, by in res.items():
        print("  " + name + ": " + "; ".join(
            f"{k} VP={m['tp']} FN={m['fn']} FP={m['fp']}" for k, m in by.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
