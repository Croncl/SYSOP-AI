"""Coletor assíncrono/não-bloqueante: segue o journald (sshd, sudo, fail2ban, kernel/UFW, AIDE) e grava em SQLite.

`journalctl -f -o json --cursor-file=...` é um processo filho: o coletor só lê o pipe (nunca bloqueia o
sistema), retoma do cursor após reinício e confirma em lote (menos fsync). auditd entra como fonte de CONTEXTO
forense (comandos/arquivos) e NÃO alimenta contagem de brute force, para não duplicar as falhas do sshd.
"""
from __future__ import annotations

import json
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


def run(db_path: str | None = None, cursor_file: str = "/var/lib/sysopai/journal.cursor", host: str = "opad-master"):
    con = dbm.connect(db_path)
    p = subprocess.Popen(["journalctl", "-f", "-o", "json", "--no-pager", f"--cursor-file={cursor_file}", "-n", "0"],
                         stdout=subprocess.PIPE, text=True, bufsize=1)
    n, t0 = 0, time.time()
    for line in p.stdout:  # bloqueia só aqui, no pipe
        n += process(con, line, host)
        if n >= BATCH_N or (n and time.time() - t0 >= BATCH_S):
            triage.open_incidents(con)
            con.commit()
            n, t0 = 0, time.time()


if __name__ == "__main__":
    run()
