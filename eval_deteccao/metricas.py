#!/usr/bin/env python3
"""Precisão, recall e F1 da detecção (O3), do SYSOP-AI e do fail2ban, contra um gabarito de episódios.

Unidade de contagem: o EPISÓDIO do gabarito (um ataque de um IP numa janela de tempo), não a linha de log.
  VP  episódio de ataque com ao menos uma detecção do mesmo tipo, do mesmo IP, entre o início e o fim + folga
  FN  episódio de ataque sem detecção (o motivo provável sai do próprio journal: abaixo do limiar, IPv6, ...)
  FP  detecção que não corresponde a nenhum episódio de ataque daquele tipo (ex.: o administrador errando a senha)
Detecções repetidas do mesmo episódio contam uma vez (ficam como "duplicatas").

Gabarito (CSV): episodio,tipo,ip,inicio,fim,esperado,ferramenta,notas
  tipo      ssh_bruteforce | port_scan | benigno
  inicio/fim  epoch em segundos (o lab/ataque.sh grava assim)
  esperado  detectar | nao_detectar (o que o projeto PREVÊ; o FN previsto continua sendo FN, mas fica explicado)

    python -m eval_deteccao.metricas --gabarito gabarito.csv --journal journal.json [--sysop-db sysop.db] \
        [--f2b-jail sshd-sombra] --out deteccao.md --csv-dir csv/
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sysopai"))
sys.path.insert(0, str(ROOT / "ab_harness"))

import collector  # noqa: E402
import triage  # noqa: E402
from u3_report import wilson  # noqa: E402

from eval_deteccao import fail2ban_sim, replay  # noqa: E402

KINDS = ("ssh_bruteforce", "port_scan")
WINDOW_S, SSH_THRESHOLD, PORT_THRESHOLD = 600, 10, 10
SSHD_IDS = ("sshd", "sshd-session")
F2B_BAN = re.compile(r"\[(?P<jail>[^\]]+)\]\s+Ban\s+(?P<ip>[0-9A-Fa-f.:]+)")
F2B_LOG_TS = re.compile(r"^(?P<dt>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)")


def norm(ip: str) -> str:
    try:
        return str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return (ip or "").strip()


# ------------------------------------ entradas ---------------------------------------
def read_gabarito(path: str | Path, skew: float = 0.0) -> list[dict]:
    """skew: segundos somados a inicio/fim (relógio da placa menos o da máquina atacante, se não estiverem em NTP)."""
    eps = []
    for r in csv.DictReader(open(path, newline="", encoding="utf-8")):
        r = {k.strip(): (v or "").strip() for k, v in r.items()}
        r["ip"], r["inicio"], r["fim"] = norm(r["ip"]), float(r["inicio"]) + skew, float(r["fim"]) + skew
        eps.append(r)
    return eps


def sysop_detections(incs: list[dict], detector: str) -> list[dict]:
    return [{"detector": detector, "kind": i["kind"], "ip": norm(i["src_ip"]), "ts": float(i["opened_at"]),
             "n": i["n_events"], "id": i["id"], "status": i.get("status")} for i in incs]


def f2b_sim_detections(entries: list[dict], **jail) -> list[dict]:
    ev = [(replay.ts_of(e), e["MESSAGE"]) for e in entries if e.get("SYSLOG_IDENTIFIER") in SSHD_IDS]
    return [{"detector": "fail2ban (simulado)", "kind": "ssh_bruteforce", "ip": b["ip"], "ts": b["ts"], "n": b["n"]}
            for b in fail2ban_sim.simulate(ev, **jail)]


def f2b_journal_detections(entries: list[dict], jail: str) -> list[dict]:
    out = []
    for e in entries:
        if e.get("SYSLOG_IDENTIFIER") == "fail2ban-server":
            m = F2B_BAN.search(e["MESSAGE"])
            if m and m.group("jail") == jail:
                out.append({"detector": f"fail2ban (real, {jail})", "kind": "ssh_bruteforce", "ip": norm(m.group("ip")),
                            "ts": replay.ts_of(e), "n": None})
    return out


def f2b_log_detections(path: str, jail: str, utc_offset_h: float) -> list[dict]:
    """/var/log/fail2ban.log (horário local da placa; informe o fuso, ex.: -3)."""
    tz, out = timezone(timedelta(hours=utc_offset_h)), []
    for line in Path(path).read_text(errors="replace").splitlines():
        m, t = F2B_BAN.search(line), F2B_LOG_TS.match(line)
        if m and t and m.group("jail") == jail:
            ts = datetime.strptime(t.group("dt"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz).timestamp()
            out.append({"detector": f"fail2ban (real, {jail})", "kind": "ssh_bruteforce", "ip": norm(m.group("ip")),
                        "ts": ts, "n": None})
    return out


# ------------------------------------ casamento --------------------------------------
def match(episodes: list[dict], dets: list[dict], grace: float = 60.0) -> tuple[dict, list[dict]]:
    """hits[episodio] = detecções que casam; fps = detecções sem episódio de ataque do mesmo tipo."""
    hits: dict[str, list[dict]] = defaultdict(list)
    fps = []
    for d in dets:
        cand = [e for e in episodes if e["tipo"] == d["kind"] and e["ip"] == d["ip"]
                and e["inicio"] - 2 <= d["ts"] <= e["fim"] + grace]
        if cand:
            hits[cand[0]["episodio"]].append(d)
        else:
            benign = [e for e in episodes if e["ip"] == d["ip"] and e["inicio"] - 2 <= d["ts"] <= e["fim"] + grace]
            fps.append({**d, "episodio": benign[0]["episodio"] if benign else "",
                        "tipo_episodio": benign[0]["tipo"] if benign else ""})
    return hits, fps


def metrics(episodes: list[dict], dets: list[dict], grace: float = 60.0) -> dict:
    hits, fps = match(episodes, dets, grace)
    out = {}
    for k in KINDS:
        eps = [e for e in episodes if e["tipo"] == k]
        tp = [e for e in eps if hits.get(e["episodio"])]
        fn = [e for e in eps if not hits.get(e["episodio"])]
        fp = [d for d in fps if d["kind"] == k]
        p = len(tp) / (len(tp) + len(fp)) if tp or fp else None
        r = len(tp) / len(eps) if eps else None
        f1 = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
        ttd = [min(d["ts"] for d in hits[e["episodio"]]) - e["inicio"] for e in tp]
        dup = sum(len(hits[e["episodio"]]) - 1 for e in tp)
        out[k] = {"episodes": len(eps), "tp": len(tp), "fn": len(fn), "fp": len(fp), "precision": p, "recall": r,
                  "f1": f1, "p_ci": wilson(len(tp), len(tp) + len(fp)), "r_ci": wilson(len(tp), len(eps)),
                  "ttd_med": statistics.median(ttd) if ttd else None, "ttd_max": max(ttd) if ttd else None,
                  "dup": dup, "fn_list": fn, "fp_list": fp}
    return out


# ------------------------------------ explicações -------------------------------------
def _max_in_window(ts: list[float], w: float = WINDOW_S) -> int:
    ts, best, j = sorted(ts), 0, 0
    for i, t in enumerate(ts):
        while ts[j] <= t - w:
            j += 1
        best = max(best, i - j + 1)
    return best


def evidence(ep: dict, entries: list[dict], grace: float = 60.0) -> dict:
    """O que o journal mostra daquele IP no episódio, pelas mesmas regras da triagem."""
    fails, ufw, ports_ts, raw_ssh_unparsed = [], [], [], 0
    ports: set[int] = set()
    for e in entries:
        t = replay.ts_of(e)
        if not (ep["inicio"] - 2 <= t <= ep["fim"] + grace):
            continue
        msg = collector.keep(e)
        if msg is None:
            continue
        c = triage.classify_line(msg)
        ip = norm(c["src_ip"] or "")
        if c["label"] == "bruteforce" and ip == ep["ip"]:
            fails.append(t)
        elif c["event_type"] == "ufw_block" and ip == ep["ip"]:
            ufw.append(t)
            m = triage.DPT.search(msg)
            if m and int(m.group(1)) <= 65535:
                ports.add(int(m.group(1)))
                ports_ts.append((t, int(m.group(1))))
        elif c["event_type"] == "other" and ep["ip"] in norm_all(msg) and re.search(
                r"Failed \S+ for|Invalid user", msg):
            raw_ssh_unparsed += 1
    win_ports = 0
    for t, _ in ports_ts:
        win_ports = max(win_ports, len({p for tt, p in ports_ts if t - WINDOW_S < tt <= t}))
    return {"ssh_fails": len(fails), "ssh_max_10min": _max_in_window(fails), "ufw_events": len(ufw),
            "ports": len(ports), "ports_max_10min": win_ports, "ssh_unparsed": raw_ssh_unparsed}


def norm_all(msg: str) -> set[str]:
    out = set()
    for tok in re.findall(r"[0-9A-Fa-f.:]{3,}", msg):
        try:
            out.add(str(ipaddress.ip_address(tok)))
        except ValueError:
            pass
    return out


def why_fn(ep: dict, ev: dict, detector: str) -> str:
    v6 = ":" in ep["ip"]
    if ep["tipo"] == "ssh_bruteforce":
        if detector.startswith("SYSOP") and v6 and ev["ssh_unparsed"]:
            return f"IPv6 no SSH: {ev['ssh_unparsed']} falhas no log, mas as regras da triagem só reconhecem IPv4"
        if ev["ssh_fails"] == 0 and not ev["ssh_unparsed"]:
            return "nenhuma falha de SSH no log (sshd não registrou falha contável: chave pública, senha desligada...)"
        if detector.startswith("SYSOP") and ev["ssh_max_10min"] < SSH_THRESHOLD:
            return f"abaixo do limiar: no máximo {ev['ssh_max_10min']} falhas em 10 min (limiar {SSH_THRESHOLD})"
        if detector.startswith("fail2ban"):
            return f"no máximo {ev['ssh_max_10min']} falhas contáveis em 10 min (maxretry do jail)"
    if ep["tipo"] == "port_scan":
        if detector.startswith("fail2ban"):
            return "a jail sshd não lê o UFW: o fail2ban da placa não tem jail de varredura"
        if ev["ufw_events"] == 0:
            return "nenhum bloqueio do UFW registrado (porta aberta, ICMP, ou o log do UFW descartou)"
        if ev["ports_max_10min"] < PORT_THRESHOLD:
            return (f"abaixo do limiar: no máximo {ev['ports_max_10min']} portas distintas registradas em 10 min "
                    f"(limiar {PORT_THRESHOLD}; o log do UFW tem limite de 3/min, rajada 10)")
    return "não explicado pelo journal: investigar"


def why_fp(d: dict, entries: list[dict]) -> str:
    if d.get("tipo_episodio") == "benigno":
        return f"episódio benigno {d['episodio']} gerou {d.get('n') or '?'} eventos contáveis na janela"
    return "detecção fora de qualquer episódio do gabarito (tráfego não planejado na rede?)"


# ------------------------------------ relatório -------------------------------------
def _pct(x, ci=None):
    if x is None:
        return "–"
    s = f"{100 * x:.0f}%"
    return s + (f" (IC {100 * ci[0]:.0f}–{100 * ci[1]:.0f})" if ci else "")


def evaluate(episodes: list[dict], entries: list[dict], detector_sets: dict[str, list[dict]], grace: float = 60.0):
    res = {name: metrics(episodes, dets, grace) for name, dets in detector_sets.items()}
    evs = {e["episodio"]: evidence(e, entries, grace) for e in episodes}
    return res, evs


def render(episodes, res, evs, detector_sets, grace=60.0) -> tuple[str, dict]:
    csvs = {}
    md = ["# Detecção (O3): SYSOP-AI e fail2ban contra o gabarito", "",
          f"{len(episodes)} episódios: " + ", ".join(f"{k}={sum(e['tipo'] == k for e in episodes)}"
                                                    for k in KINDS + ("benigno",)), ""]
    head = ["detector", "tipo", "episódios", "VP", "FN", "FP", "precisão", "recall", "F1", "tempo até detectar, mediana (s)",
            "máx (s)", "duplicatas"]
    body = []
    for name, by in res.items():
        for k, m in by.items():
            body.append([name, k, m["episodes"], m["tp"], m["fn"], m["fp"], _pct(m["precision"], m["p_ci"]),
                         _pct(m["recall"], m["r_ci"]), "–" if m["f1"] is None else f"{m['f1']:.2f}",
                         "–" if m["ttd_med"] is None else f"{m['ttd_med']:.0f}",
                         "–" if m["ttd_max"] is None else f"{m['ttd_max']:.0f}", m["dup"]])
    md += ["## Métricas por detector e tipo", "", _table(head, body), ""]
    csvs["deteccao"] = (head, body)

    head = ["episódio", "tipo", "IP", "duração (s)", "esperado", "falhas SSH (máx/10 min)", "portas (máx/10 min)"] + \
           list(detector_sets)
    body = []
    for e in episodes:
        ev = evs[e["episodio"]]
        row = [e["episodio"], e["tipo"], e["ip"], f"{e['fim'] - e['inicio']:.0f}", e.get("esperado", ""),
               f"{ev['ssh_fails']} ({ev['ssh_max_10min']})", f"{ev['ports']} ({ev['ports_max_10min']})"]
        for name, dets in detector_sets.items():
            hits, _ = match([e], dets, grace)
            n = len(hits.get(e["episodio"], []))
            row.append(("detectou" if e["tipo"] != "benigno" else "FP") if n else
                       ("—" if e["tipo"] == "benigno" else "FN"))
        body.append(row)
    md += ["## Episódios", "", _table(head, body), ""]
    csvs["episodios"] = (head, body)

    head = ["detector", "tipo", "episódio/IP", "resultado", "motivo provável", "esperado no gabarito"]
    body = []
    for name, by in res.items():
        for k, m in by.items():
            for e in m["fn_list"]:
                body.append([name, k, e["episodio"], "FN", why_fn(e, evs[e["episodio"]], name), e.get("esperado", "")])
            for d in m["fp_list"]:
                body.append([name, k, d.get("episodio") or d["ip"], "FP", why_fp(d, []), ""])
    md += ["## Falsos negativos e falsos positivos, com o motivo provável", "",
           _table(head, body) if body else "(nenhum)", ""]
    csvs["fn_fp"] = (head, body)
    return "\n".join(md), csvs


def _table(head, body):
    out = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    return "\n".join(out + ["| " + " | ".join(str(x) for x in r) + " |" for r in body])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gabarito", required=True)
    ap.add_argument("--journal", required=True, help="journalctl -o json da janela do laboratório")
    ap.add_argument("--sysop-db", help="backup do sysop.db da placa (incidentes abertos ao vivo)")
    ap.add_argument("--f2b-jail", default="sshd-sombra", help="jail cujos 'Ban' no journal são a referência real")
    ap.add_argument("--f2b-log", help="/var/log/fail2ban.log, se o fail2ban não loga no journal")
    ap.add_argument("--utc-offset", type=float, default=-3.0, help="fuso do fail2ban.log (padrão -3, Brasília)")
    ap.add_argument("--maxretry", type=int, default=5)
    ap.add_argument("--findtime", type=int, default=600)
    ap.add_argument("--grace", type=float, default=60.0, help="folga após o fim do episódio (s)")
    ap.add_argument("--skew", type=float, default=0.0,
                    help="relógio da placa menos o da máquina atacante, em s (o ataque.sh registra os dois)")
    ap.add_argument("--out", default="")
    ap.add_argument("--csv-dir", default="")
    a = ap.parse_args(argv)
    episodes = read_gabarito(a.gabarito, a.skew)
    entries = replay.load_journal(a.journal)
    sets = {"SYSOP-AI (replay do journal)": sysop_detections(replay.incidents(replay.replay(entries)),
                                                             "SYSOP-AI (replay)")}
    if a.sysop_db:
        sets["SYSOP-AI (banco da placa)"] = sysop_detections(replay.incidents_from_db(a.sysop_db), "SYSOP-AI (placa)")
    sets["fail2ban (simulado)"] = f2b_sim_detections(entries, maxretry=a.maxretry, findtime=a.findtime)
    real = f2b_log_detections(a.f2b_log, a.f2b_jail, a.utc_offset) if a.f2b_log else \
        f2b_journal_detections(entries, a.f2b_jail)
    if real or a.f2b_log:
        sets[f"fail2ban (real, {a.f2b_jail})"] = real
    res, evs = evaluate(episodes, entries, sets, a.grace)
    md, csvs = render(episodes, res, evs, sets, a.grace)
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(md + "\n")
        print(f"{a.out}: {len(episodes)} episódios, detectores: {', '.join(sets)}")
    else:
        print(md)
    if a.csv_dir:
        Path(a.csv_dir).mkdir(parents=True, exist_ok=True)
        for name, (head, body) in csvs.items():
            with open(Path(a.csv_dir) / f"{name}.csv", "w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(head)
                w.writerows(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
