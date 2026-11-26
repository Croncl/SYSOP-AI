#!/usr/bin/env python3
"""Amostra a memória dos processos do SYSOP-AI durante uma rodada (O2: custo de memória na placa).

Lê /proc a cada --interval segundos e grava CSV com, por processo que casa com algum --match (substring da linha
de comando): VmRSS e VmHWM (pico de RSS desde que o processo nasceu), mais o MemAvailable da máquina e a
temperatura máxima das zonas térmicas. O llama-server roda em contêiner podman, mas o processo aparece no /proc do
host, então não precisa de `podman stats`. Só biblioteca padrão; não precisa de root para os processos do usuário.

    python scripts/mem_sampler.py --match llama-server --match ab_runner --out mem.csv &      # roda até SIGTERM
    python scripts/mem_sampler.py --summary mem.csv                                            # resumo
"""
from __future__ import annotations

import argparse
import csv
import glob
import os
import signal
import sys
import time
from pathlib import Path

FIELDS = ["ts", "pid", "match", "rss_kb", "hwm_kb", "mem_available_kb", "temp_c"]


def _status(pid: str) -> dict[str, int]:
    out = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                k, v = line.split(":", 1)
                out[k] = int(v.split()[0])
    except (OSError, ValueError):
        pass
    return out


def _cmdline(pid: str) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
    except OSError:
        return ""


def find(matches: list[str], me: int) -> list[tuple[str, str]]:
    found = []
    for d in os.listdir("/proc"):
        if d.isdigit() and int(d) != me:
            cmd = _cmdline(d)
            for m in matches:
                if m in cmd:
                    found.append((d, m))
                    break
    return found


def mem_available() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def temp() -> float | None:
    best = None
    for p in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            v = int(Path(p).read_text().strip()) / 1000
            best = v if best is None else max(best, v)
        except (OSError, ValueError):
            pass
    return best


def sample(matches: list[str], me: int) -> list[dict]:
    ts, avail, t = round(time.time(), 1), mem_available(), temp()
    rows = []
    for pid, m in find(matches, me):
        st = _status(pid)
        if st:
            rows.append({"ts": ts, "pid": pid, "match": m, "rss_kb": st.get("VmRSS"), "hwm_kb": st.get("VmHWM"),
                         "mem_available_kb": avail, "temp_c": t})
    if not rows:  # mesmo sem processo, registra a máquina (linha de base)
        rows.append({"ts": ts, "pid": "", "match": "", "rss_kb": None, "hwm_kb": None, "mem_available_kb": avail,
                     "temp_c": t})
    return rows


def summary(path: str) -> int:
    by: dict[str, dict] = {}
    avail = []
    for r in csv.DictReader(open(path)):
        if r["mem_available_kb"]:
            avail.append(int(r["mem_available_kb"]))
        if not r["match"]:
            continue
        s = by.setdefault(r["match"], {"rss": [], "hwm": 0, "pids": set()})
        s["rss"].append(int(r["rss_kb"] or 0))
        s["hwm"] = max(s["hwm"], int(r["hwm_kb"] or 0))
        s["pids"].add(r["pid"])
    for m, s in by.items():
        rss = sorted(s["rss"])
        print(f"{m}: amostras={len(rss)} pids={len(s['pids'])} RSS mediana={rss[len(rss) // 2] / 1024:.0f} MiB "
              f"máx={rss[-1] / 1024:.0f} MiB pico(VmHWM)={s['hwm'] / 1024:.0f} MiB")
    if avail:
        print(f"MemAvailable: mín={min(avail) / 1024:.0f} MiB máx={max(avail) / 1024:.0f} MiB")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--match", action="append", default=[], help="substring da linha de comando (pode repetir)")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--duration", type=float, default=0, help="segundos (0 = até SIGTERM/SIGINT)")
    ap.add_argument("--out", help="CSV de saída (anexa se existir)")
    ap.add_argument("--summary", help="só resume um CSV já gravado")
    a = ap.parse_args(argv)
    if a.summary:
        return summary(a.summary)
    if not a.out or not a.match:
        ap.error("--out e ao menos um --match são obrigatórios")
    stop = {"now": False}
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.update(now=True))
    new = not Path(a.out).exists()
    me, t_end = os.getpid(), (time.time() + a.duration) if a.duration else None
    with open(a.out, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        if new:
            w.writeheader()
        while not stop["now"] and (t_end is None or time.time() < t_end):
            w.writerows(sample(a.match, me))
            fh.flush()
            time.sleep(a.interval)
    print(f"{a.out}: amostragem encerrada", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
