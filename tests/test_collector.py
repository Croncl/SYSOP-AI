import json
import pytest
import collector
import db


@pytest.fixture
def con(tmp_path):
    c = db.init(str(tmp_path / "t.db"))
    yield c
    c.close()


def _j(ident, msg, ts_us=1700000000000000):
    return json.dumps({"SYSLOG_IDENTIFIER": ident, "MESSAGE": msg, "__REALTIME_TIMESTAMP": str(ts_us)})


def test_keep_filtra():
    assert collector.keep({"SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "x"}) == "x"
    assert collector.keep({"SYSLOG_IDENTIFIER": "cron", "MESSAGE": "x"}) is None
    assert collector.keep({"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": "usb 1-1: nova"}) is None
    assert collector.keep({"SYSLOG_IDENTIFIER": "sshd", "MESSAGE": ["lista"]}) is None  # MESSAGE não-texto


def test_process_grava_evento_classificado(con):
    ok = collector.process(con, _j("sshd", "Failed password for root from 203.0.113.9 port 22 ssh2"), "h")
    assert ok
    r = con.execute("SELECT * FROM raw_events").fetchone()
    assert (r["ts"], r["event_type"], r["src_ip"], r["label"], r["source"]) == \
        (1700000000, "ssh_fail", "203.0.113.9", "bruteforce", "journald")


def test_process_ufw_do_kernel(con):
    assert collector.process(con, _j("kernel", "[UFW BLOCK] IN=wlan0 SRC=198.51.100.7 DST=192.168.0.4"), "h")
    assert con.execute("SELECT event_type FROM raw_events").fetchone()[0] == "ufw_block"


def test_linha_malformada_nao_derruba(con):
    for lixo in ["", "não é json", "{", json.dumps({"SYSLOG_IDENTIFIER": "sshd", "MESSAGE": "x", "__REALTIME_TIMESTAMP": "abc"})]:
        assert collector.process(con, lixo, "h") is False
    assert con.execute("SELECT count(*) FROM raw_events").fetchone()[0] == 0
