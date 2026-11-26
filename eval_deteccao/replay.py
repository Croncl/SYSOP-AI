#!/usr/bin/env python3
"""Reproduz a detecção do SYSOP-AI sobre um journal exportado (journalctl -o json), num banco temporário.

Usa o mesmo caminho do coletor (collector.process: filtro + regras da triagem) e chama triage.open_incidents com
`now` = horário do log, a cada BATCH_S segundos de log ou BATCH_N eventos, como o coletor faz em tempo real.
Assim o resultado não depende do relógio de quem analisa nem de quando o journal foi exportado.

    journalctl -o json --since "@INICIO" --until "@FIM" > journal.json          # na placa
    python -m eval_deteccao.replay journal.json                                  # no PC: lista os incidentes
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "sysopai"))

import collector  # noqa: E402
import db as dbm  # noqa: E402
import triage  # noqa: E402


def _message(e: dict) -> str | None:
    m = e.get("MESSAGE")
    if isinstance(m, list):                # o journal exporta mensagens não-UTF-8 como lista de bytes
        try:
            return bytes(m).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return None
    return m if isinstance(m, str) else None


def load_journal(path: str | Path) -> list[dict]:
    """Entradas do `journalctl -o json` (uma por linha), em ordem de tempo; linhas ruins são ignoradas."""
    out = []
    for line in Path(path).read_text(errors="replace").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        msg = _message(e)
        if msg is None or "__REALTIME_TIMESTAMP" not in e:
            continue
        e["MESSAGE"] = msg
        out.append(e)
    out.sort(key=lambda e: int(e["__REALTIME_TIMESTAMP"]))
    return out


def ts_of(e: dict) -> float:
    return int(e["__REALTIME_TIMESTAMP"]) / 1e6


def replay(entries: Iterable[dict], *, db_path: str | None = None, host: str = "opad-master",
           batch_n: int = collector.BATCH_N, batch_s: float = collector.BATCH_S, **triage_kw) -> sqlite3.Connection:
    """Devolve a conexão com o banco resultante (eventos e incidentes)."""
    if db_path is None:
        db_path = str(Path(tempfile.mkdtemp(prefix="sysop_replay_")) / "replay.db")
    con = dbm.init(db_path)
    n, t_flush, last_ts = 0, None, None
    for e in entries:
        ts = ts_of(e)
        if t_flush is not None and n and ts - t_flush >= batch_s:     # lote venceu pelo tempo antes deste evento
            triage.open_incidents(con, now=int(last_ts), **triage_kw)
            n, t_flush = 0, None
        if collector.process(con, json.dumps(e), host):
            n += 1
            last_ts = ts
            t_flush = ts if t_flush is None else t_flush
            if n >= batch_n:
                triage.open_incidents(con, now=int(ts), **triage_kw)
                n, t_flush = 0, None
    if n:
        triage.open_incidents(con, now=int(last_ts), **triage_kw)
    con.commit()
    return con


def incidents(con: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in con.execute(
        "SELECT id, opened_at, kind, severity, src_ip, n_events, first_ts, last_ts, status FROM incidents ORDER BY id")]


def incidents_from_db(path: str) -> list[dict]:
    """Incidentes de um banco do agente (ex.: backup do sysop.db da placa), só leitura."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return incidents(con)
    finally:
        con.close()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("journal")
    a = ap.parse_args(argv)
    con = replay(load_journal(a.journal))
    for i in incidents(con):
        print(json.dumps(i, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
