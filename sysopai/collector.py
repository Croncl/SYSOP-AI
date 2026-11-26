"""Coletor assíncrono/não-bloqueante: segue o journald (sshd, sudo, fail2ban, kernel/UFW, AIDE) e grava em SQLite.

`journalctl -f -o json` é um processo filho: o coletor só lê o pipe (nunca bloqueia o
sistema), retoma do cursor após reinício (gravado no banco, na mesma transação dos eventos) e confirma em lote (menos fsync). auditd entra como fonte de CONTEXTO
forense (comandos/arquivos) e NÃO alimenta contagem de brute force, para não duplicar as falhas do sshd.
"""
from __future__ import annotations

import json
import re
import signal
import sqlite3
import subprocess
import time

import db as dbm
import triage

WATCH = {"sshd", "sudo", "fail2ban-server", "aide", "kernel"}
BATCH_N, BATCH_S = 50, 2.0


def keep(entry: dict) -> str | None:
    """Filtra o que interessa ANTES de gravar (o journal inteiro seria volume inútil). Retorna a mensagem."""
    ident = entry.get("SYSLOG_IDENTIFIER", "")
    msg = entry.get("MESSAGE")
    if not isinstance(msg, str) or ident not in WATCH:
        return None
    if ident == "kernel" and "[UFW " not in msg:
        return None
    return msg


def process(con, line: str, host: str, bert=None) -> bool:
    try:
        e = json.loads(line)
        msg = keep(e)
        if msg is None:
            return False
        ts = int(int(e.get("__REALTIME_TIMESTAMP", time.time() * 1e6)) / 1e6)
        triage.ingest(con, "journald", host, ts, msg, bert)
        return True
    except (ValueError, TypeError):
        return False  # linha malformada nunca derruba o coletor


CURSOR_SOURCE = "journald"
IDLE_S = 30.0          # sem eventos relevantes, o cursor avança mesmo assim a cada tanto
_CURSOR_RX = re.compile(r"^[a-z]=[0-9a-f]+(;[a-z]=[0-9a-f]+)*$")


def valid_cursor(c) -> bool:
    """Formato do cursor do journald (s=...;i=...;b=...;m=...;t=...;x=...). Valida antes de virar argumento de comando."""
    return isinstance(c, str) and len(c) <= 300 and bool(_CURSOR_RX.match(c))


def get_cursor(con) -> str | None:
    try:
        row = con.execute("SELECT cursor FROM collector_cursor WHERE source=?", (CURSOR_SOURCE,)).fetchone()
    except sqlite3.Error:
        return None
    return row[0] if row and valid_cursor(row[0]) else None


def set_cursor(con, cursor: str) -> None:
    con.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES (?,?,?) "
                "ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at",
                (CURSOR_SOURCE, cursor, int(time.time())))


def clear_cursor(con) -> None:
    con.execute("DELETE FROM collector_cursor WHERE source=?", (CURSOR_SOURCE,))


def journal_cmd(cursor: str | None) -> list[str]:
    base = ["journalctl", "-f", "-o", "json", "--no-pager"]
    return base + ([f"--after-cursor={cursor}"] if cursor else ["-n", "0"])


def _line_cursor(line: str) -> str | None:
    try:
        c = json.loads(line).get("__CURSOR")
    except (ValueError, AttributeError):
        return None
    return c if valid_cursor(c) else None


def _flush(con, n: int, last: str | None) -> None:
    """Confirma o lote: eventos e cursor na MESMA transação (nunca um sem o outro)."""
    if n:
        triage.open_incidents(con)
    if last:
        set_cursor(con, last)
    if n or last:
        con.commit()


def run(db_path: str | None = None, host: str = "opad-master", popen=subprocess.Popen):
    con = dbm.connect(db_path)
    con.execute("CREATE TABLE IF NOT EXISTS collector_cursor "
                "(source TEXT PRIMARY KEY, cursor TEXT NOT NULL, updated_at INTEGER NOT NULL)")
    cursor = get_cursor(con)
    while True:
        p = popen(journal_cmd(cursor), stdout=subprocess.PIPE, text=True, bufsize=1)
        n, t0, last, got = 0, time.time(), None, False
        try:
            for line in p.stdout:  # bloqueia só aqui, no pipe
                got = True
                n += process(con, line, host)
                last = _line_cursor(line) or last
                dt = time.time() - t0
                if n >= BATCH_N or (n and dt >= BATCH_S) or (not n and last and dt >= IDLE_S):
                    _flush(con, n, last)
                    n, t0, last = 0, time.time(), None
        finally:  # SIGTERM (SystemExit) ou fim do pipe: não perde o lote em andamento
            _flush(con, n, last)
            if p.poll() is None:
                p.terminate()
        rc = p.wait()
        if cursor and not got and rc > 0:  # o journalctl recusou o cursor (rc<0 é sinal: não é recusa)
            clear_cursor(con)
            con.commit()
            cursor = None
            continue
        return


def _term(*_):
    raise SystemExit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _term)   # `systemctl stop`: confirma o lote e o cursor antes de sair
    run()
