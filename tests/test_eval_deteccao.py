"""Avaliação da detecção (eval_deteccao): replay do journal e métricas contra um gabarito."""
import csv
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from eval_deteccao import metricas as M  # noqa: E402
from eval_deteccao import replay as RP  # noqa: E402

T0 = 1_800_000_000


def j(ts, ident, msg):
    return {"__REALTIME_TIMESTAMP": str(int(ts * 1e6)), "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg}


def ssh_fail(ts, ip, port=40000):
    return j(ts, "sshd", f"Failed password for root from {ip} port {port} ssh2")


def ufw(ts, ip, dpt):
    return j(ts, "kernel", f"[UFW BLOCK] IN=wlan0 OUT= MAC=aa SRC={ip} DST=192.168.0.4 LEN=44 PROTO=TCP SPT=40000 "
                           f"DPT={dpt} WINDOW=1024 SYN")


def _journal(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))
    return path


@pytest.fixture
def lab(tmp_path):
    ev = []
    ev += [ssh_fail(T0 + 2 * i, "203.0.113.10") for i in range(30)]                       # E1: rápido
    ev += [ssh_fail(T0 + 700 + 5 * i, "203.0.113.11") for i in range(8)]                  # E2: abaixo do limiar
    ev += [ssh_fail(T0 + 1400, "198.51.100.7"), ssh_fail(T0 + 1405, "198.51.100.7"),
           j(T0 + 1410, "sshd", "Accepted password for opad from 198.51.100.7 port 5000 ssh2")]   # E3: benigno
    ev += [ufw(T0 + 2000 + i, "203.0.113.12", 1000 + i) for i in range(15)]              # E4: varredura
    ev += [ssh_fail(T0 + 3000 + i, "203.0.113.99") for i in range(12)]                    # fora do gabarito
    ev += [j(T0 + 9, "fail2ban-server", "[sshd-sombra] Ban 203.0.113.10"),
           j(T0 + 3101, "fail2ban-server", "[sshd] Ban 203.0.113.11")]                    # outra jail: ignorada
    gab = tmp_path / "gabarito.csv"
    with open(gab, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["episodio", "tipo", "ip", "inicio", "fim", "esperado", "ferramenta", "notas"])
        w.writerow(["E1", "ssh_bruteforce", "203.0.113.10", T0, T0 + 60, "detectar", "ssh", ""])
        w.writerow(["E2", "ssh_bruteforce", "203.0.113.11", T0 + 700, T0 + 740, "nao_detectar", "ssh", "8 falhas"])
        w.writerow(["E3", "benigno", "198.51.100.7", T0 + 1400, T0 + 1410, "nao_detectar", "ssh", "digitação"])
        w.writerow(["E4", "port_scan", "203.0.113.12", T0 + 2000, T0 + 2015, "detectar", "nmap", ""])
    return _journal(tmp_path / "journal.json", ev), gab


def test_load_journal_tolera_bytes_e_lixo(tmp_path):
    p = tmp_path / "j.json"
    p.write_text("lixo\n" + json.dumps({**j(T0 + 5, "sshd", ""), "MESSAGE": list(b"Invalid user x from 1.2.3.4")})
                 + "\n" + json.dumps(j(T0, "sshd", "a")) + "\n")
    es = RP.load_journal(p)
    assert [e["MESSAGE"] for e in es] == ["a", "Invalid user x from 1.2.3.4"]


def test_replay_consolida_e_usa_horario_do_log(tmp_path):
    ev = [ssh_fail(T0 + 2.5 * i, "203.0.113.10", 40000 + i) for i in range(120)]   # 5 min de ataque
    incs = RP.incidents(RP.replay(RP.load_journal(_journal(tmp_path / "j.json", ev))))
    assert len(incs) == 1
    assert (incs[0]["n_events"], incs[0]["severity"]) == (120, "high")
    assert T0 <= incs[0]["opened_at"] <= T0 + 30                                   # detectado no começo do ataque


def test_metricas(lab):
    journal, gab = lab
    eps, entries = M.read_gabarito(gab), RP.load_journal(journal)
    sets = {"SYSOP": M.sysop_detections(RP.incidents(RP.replay(entries)), "SYSOP-AI (replay)"),
            "f2b": M.f2b_sim_detections(entries), "f2b-real": M.f2b_journal_detections(entries, "sshd-sombra")}
    res, evs = M.evaluate(eps, entries, sets)
    s, f, fr = res["SYSOP"], res["f2b"], res["f2b-real"]
    assert (s["ssh_bruteforce"]["tp"], s["ssh_bruteforce"]["fn"], s["ssh_bruteforce"]["fp"]) == (1, 1, 1)
    assert s["ssh_bruteforce"]["precision"] == 0.5 and s["ssh_bruteforce"]["recall"] == 0.5
    assert (s["port_scan"]["tp"], s["port_scan"]["fp"], s["port_scan"]["recall"]) == (1, 0, 1.0)
    assert (f["ssh_bruteforce"]["tp"], f["ssh_bruteforce"]["fn"], f["ssh_bruteforce"]["fp"]) == (2, 0, 1)
    assert f["port_scan"]["fn"] == 1                                       # a jail sshd não vê o UFW
    assert (fr["ssh_bruteforce"]["tp"], fr["ssh_bruteforce"]["fp"]) == (1, 0)
    assert evs["E2"]["ssh_max_10min"] == 8 and evs["E4"]["ports_max_10min"] == 15
    assert "abaixo do limiar" in M.why_fn(s["ssh_bruteforce"]["fn_list"][0], evs["E2"], "SYSOP-AI (replay)")
    assert "não lê o UFW" in M.why_fn(eps[3], evs["E4"], "fail2ban (simulado)")
    assert s["ssh_bruteforce"]["ttd_med"] is not None and 0 <= s["ssh_bruteforce"]["ttd_med"] <= 30


def test_ipv6_no_ssh_e_explicado(tmp_path):
    ev = [ssh_fail(T0 + i, "2001:db8::5") for i in range(20)]
    gab = tmp_path / "g.csv"
    gab.write_text("episodio,tipo,ip,inicio,fim,esperado,ferramenta,notas\n"
                   f"V6,ssh_bruteforce,2001:db8::5,{T0},{T0 + 20},nao_detectar,ssh,\n")
    entries = RP.load_journal(_journal(tmp_path / "j.json", ev))
    res, evs = M.evaluate(M.read_gabarito(gab), entries,
                          {"SYSOP": M.sysop_detections(RP.incidents(RP.replay(entries)), "SYSOP-AI (replay)"),
                           "f2b": M.f2b_sim_detections(entries)})
    assert res["SYSOP"]["ssh_bruteforce"]["fn"] == 1 and res["f2b"]["ssh_bruteforce"]["tp"] == 1
    assert "IPv6 no SSH" in M.why_fn(M.read_gabarito(gab)[0], evs["V6"], "SYSOP-AI (replay)")


def test_cli_completo(lab, tmp_path):
    journal, gab = lab
    out, csvd = tmp_path / "d.md", tmp_path / "csv"
    assert M.main(["--gabarito", str(gab), "--journal", str(journal), "--out", str(out), "--csv-dir", str(csvd)]) == 0
    md = out.read_text()
    assert "fail2ban (real, sshd-sombra)" in md and "abaixo do limiar" in md
    assert (csvd / "deteccao.csv").exists() and (csvd / "fn_fp.csv").exists()
