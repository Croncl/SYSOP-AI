"""Retenção e pseudonimização (passo 12).

 - eventos brutos: agregados por dia e apagados depois de RAW_DAYS (60);
 - IP em claro: depois de IP_DAYS (180) vira pseudônimo (HMAC) em agregados, incidentes, ações finalizadas
   e resumos; texto livre que contém IP é reescrito com pseudo.scrub;
 - audit_log não é tocado: já nasce só com pseudônimo e é imutável;
 - ações pendentes ficam intactas (a aprovação amarra o hash dos argumentos);
 - sem a chave, a pseudonimização é ADIADA (trocar por um valor único fundiria IPs diferentes).
"""
from __future__ import annotations

import time

import pseudo
from pseudo import pseudonym, scrub

RAW_DAYS = 60
IP_DAYS = 180
DIA = 86400
FINAIS = ("executed", "verified", "failed", "rejected")


def purge(con, now: int | None = None, raw_days: int = RAW_DAYS, ip_days: int = IP_DAYS) -> dict:
    now = int(now or time.time())
    cut_raw, cut_ip = now - raw_days * DIA, now - ip_days * DIA
    dia_ip = time.strftime("%Y-%m-%d", time.gmtime(cut_ip))
    out = {"raw_apagados": 0, "agregados": 0, "incidentes": 0, "acoes": 0, "resumos": 0, "pseudonimizacao": "ok"}

    n = con.execute("SELECT count(*) FROM raw_events WHERE ts < ?", (cut_raw,)).fetchone()[0]
    if n:
        con.execute(
            "INSERT INTO daily_aggregates SELECT date(ts,'unixepoch'), coalesce(src_ip,''), event_type, label, count(*) "
            "FROM raw_events WHERE ts < ? GROUP BY 1,2,3,4 "
            "ON CONFLICT(day,src_ip,event_type,label) DO UPDATE SET n = n + excluded.n", (cut_raw,))
        con.execute("DELETE FROM raw_events WHERE ts < ?", (cut_raw,))
    out["raw_apagados"] = n

    if pseudo.get_key() is None:
        out["pseudonimizacao"] = "adiada: chave ausente"
    else:
        for r in con.execute("SELECT DISTINCT src_ip FROM daily_aggregates WHERE day < ? AND src_ip <> '' "
                             "AND src_ip NOT LIKE 'ip:%'", (dia_ip,)).fetchall():
            con.execute("UPDATE daily_aggregates SET src_ip=? WHERE day < ? AND src_ip=?",
                        (pseudonym(r[0]), dia_ip, r[0]))
            out["agregados"] += 1

        for r in con.execute("SELECT id, src_ip, summary FROM incidents WHERE opened_at < ?", (cut_ip,)).fetchall():
            ip, resumo = r["src_ip"], r["summary"]
            novo_ip = pseudonym(ip) if ip and not ip.startswith("ip:") else ip
            novo_res = scrub(resumo) if resumo else resumo
            if (novo_ip, novo_res) != (ip, resumo):
                con.execute("UPDATE incidents SET src_ip=?, summary=? WHERE id=?", (novo_ip, novo_res, r["id"]))
                out["incidentes"] += 1

        marcas = ",".join("?" * len(FINAIS))
        for r in con.execute(f"SELECT id, args_json, reason, result FROM agent_actions WHERE ts < ? "
                             f"AND status IN ({marcas})", (cut_ip, *FINAIS)).fetchall():
            antigo = (r["args_json"], r["reason"], r["result"])
            novo = tuple(scrub(x) if x else x for x in antigo)
            if novo != antigo:
                con.execute("UPDATE agent_actions SET args_json=?, reason=?, result=? WHERE id=?", (*novo, r["id"]))
                out["acoes"] += 1

        for r in con.execute("SELECT id, text FROM summaries WHERE ts < ?", (cut_ip,)).fetchall():
            novo = scrub(r["text"])
            if novo != r["text"]:
                con.execute("UPDATE summaries SET text=? WHERE id=?", (novo, r["id"]))
                out["resumos"] += 1

    con.commit()
    try:
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:
        pass
    return out
