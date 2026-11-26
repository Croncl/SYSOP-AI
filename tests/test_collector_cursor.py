import json

import pytest

import collector
import db

C1 = "s=aaa;i=1;b=bbb;m=1;t=1;x=1"
C2 = "s=aaa;i=2;b=bbb;m=2;t=2;x=2"
C3 = "s=aaa;i=3;b=bbb;m=3;t=3;x=3"


def linha(ident, msg, cursor, ts_us=1700000000000000):
    return json.dumps({"__CURSOR": cursor, "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg, "__REALTIME_TIMESTAMP": str(ts_us)})


FALHA = "Failed password for root from 203.0.113.9 port 22 ssh2"


class FakeProc:
    def __init__(self, linhas, rc=0, explode=None):
        self._linhas, self.returncode, self._explode = list(linhas), rc, explode
        self.terminated = False
        self.stdout = self._gen()

    def _gen(self):
        for ln in self._linhas:
            yield ln
        if self._explode:
            raise self._explode

    def poll(self):
        return self.returncode if self.terminated or not self._linhas else None

    def wait(self):
        return self.returncode

    def terminate(self):
        self.terminated = True


def fabrica(*procs):
    chamadas = []
    fila = list(procs)

    def popen(cmd, **kw):
        chamadas.append(list(cmd))
        return fila.pop(0)

    return popen, chamadas


@pytest.fixture
def dbp(tmp_path):
    p = str(tmp_path / "c.db")
    db.init(p).close()
    return p


def cursor_gravado(dbp):
    c = db.connect(dbp)
    try:
        r = c.execute("SELECT cursor FROM collector_cursor WHERE source='journald'").fetchone()
        return r[0] if r else None
    finally:
        c.close()


def eventos(dbp):
    c = db.connect(dbp)
    try:
        return c.execute("SELECT count(*) FROM raw_events").fetchone()[0]
    finally:
        c.close()


def test_sem_cursor_comeca_do_agora(dbp):
    popen, chamadas = fabrica(FakeProc([]))
    collector.run(dbp, popen=popen)
    assert chamadas == [["journalctl", "-f", "-o", "json", "--no-pager", "-n", "0"]]


def test_grava_eventos_e_cursor_juntos(dbp):
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1), linha("sshd", FALHA, C2)]))
    collector.run(dbp, popen=popen)
    assert eventos(dbp) == 2 and cursor_gravado(dbp) == C2


def test_retoma_do_cursor_gravado(dbp):
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1)]))
    collector.run(dbp, popen=popen)
    popen2, chamadas = fabrica(FakeProc([]))
    collector.run(dbp, popen=popen2)
    assert chamadas == [["journalctl", "-f", "-o", "json", "--no-pager", f"--after-cursor={C1}"]]
    assert "-n" not in chamadas[0]


@pytest.mark.parametrize("lixo", ["--exec=evil", "s=aaa; rm -rf /", "", "s=XYZ", "x" * 400, "$(id)", "s=1\ni=2"])
def test_cursor_invalido_no_banco_e_ignorado(dbp, lixo):
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (lixo,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([]))
    collector.run(dbp, popen=popen)
    assert chamadas == [["journalctl", "-f", "-o", "json", "--no-pager", "-n", "0"]]


def test_cursor_invalido_vindo_do_journal_nao_e_gravado(dbp):
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, "--exec=evil")]))
    collector.run(dbp, popen=popen)
    assert eventos(dbp) == 1 and cursor_gravado(dbp) is None


def test_journalctl_recusa_o_cursor_recomeca_sem_ele(dbp):
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (C1,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([], rc=1), FakeProc([linha("sshd", FALHA, C2)]))
    collector.run(dbp, popen=popen)
    assert len(chamadas) == 2 and f"--after-cursor={C1}" in chamadas[0] and chamadas[1][-2:] == ["-n", "0"]
    assert cursor_gravado(dbp) == C2 and eventos(dbp) == 1


def test_parada_por_sinal_nao_apaga_o_cursor(dbp):
    """rc negativo = morto por sinal (systemctl stop): NÃO é recusa de cursor."""
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (C1,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([], rc=-15))
    collector.run(dbp, popen=popen)
    assert len(chamadas) == 1 and cursor_gravado(dbp) == C1


def test_recusa_de_cursor_so_tenta_uma_vez(dbp):
    c = db.connect(dbp)
    c.execute("INSERT INTO collector_cursor(source,cursor,updated_at) VALUES ('journald',?,1)", (C1,))
    c.commit()
    c.close()
    popen, chamadas = fabrica(FakeProc([], rc=1), FakeProc([], rc=1))
    collector.run(dbp, popen=popen)
    assert len(chamadas) == 2


def test_sigterm_confirma_o_lote_em_andamento(dbp):
    """SystemExit (o que o handler de SIGTERM levanta) no meio da leitura: o lote parcial e o cursor são gravados."""
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1), linha("sshd", FALHA, C2)], explode=SystemExit(0)))
    with pytest.raises(SystemExit):
        collector.run(dbp, popen=popen)
    assert eventos(dbp) == 2 and cursor_gravado(dbp) == C2


def test_linhas_irrelevantes_tambem_avancam_o_cursor(dbp, monkeypatch):
    relogio = {"t": 1000.0}
    monkeypatch.setattr(collector.time, "time", lambda: relogio["t"])

    def gen():
        yield linha("cron", "tarefa", C1)
        relogio["t"] += collector.IDLE_S + 1
        yield linha("cron", "tarefa", C2)

    class P(FakeProc):
        def _gen(self):
            return gen()

    popen, _ = fabrica(P([]))
    collector.run(dbp, popen=popen)
    assert eventos(dbp) == 0 and cursor_gravado(dbp) == C2


def test_evento_e_cursor_sao_a_mesma_transacao(dbp, monkeypatch):
    """Se gravar o cursor falha, os eventos do lote NÃO persistem (e vice-versa): reprocessa na volta, sem furo."""
    import sqlite3
    popen, _ = fabrica(FakeProc([linha("sshd", FALHA, C1)]))

    def quebrado(con, cursor):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(collector, "set_cursor", quebrado)
    with pytest.raises(sqlite3.OperationalError):
        collector.run(dbp, popen=popen)
    assert eventos(dbp) == 0 and cursor_gravado(dbp) is None
