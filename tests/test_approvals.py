import json
import sqlite3

import pytest

import approvals

ROW = {"id": 5, "ts": 1000, "tool": "ban_ip_fail2ban", "args_json": json.dumps({"ip": "203.0.113.9"}), "status": "pending"}


@pytest.fixture
def apath(tmp_path):
    p = str(tmp_path / "a.db")
    approvals.init(p)
    return p


def test_grant_e_approver(apath):
    approvals.grant(ROW, "maria", apath, now=2000)
    assert approvals.approver(ROW, apath, now=2100) == "maria"


def test_qualquer_alteracao_invalida_a_aprovacao(apath):
    approvals.grant(ROW, "maria", apath, now=2000)
    outra = json.dumps({"ip": "203.0.113.10"})
    assert approvals.approver({**ROW, "args_json": outra}, apath, now=2100) is None   # argumentos trocados
    assert approvals.approver({**ROW, "tool": "run_aide_check"}, apath, now=2100) is None
    assert approvals.approver({**ROW, "ts": 1001}, apath, now=2100) is None            # replay em outra ação
    assert approvals.approver({**ROW, "id": 6}, apath, now=2100) is None


def test_aprovacao_expira(apath):
    approvals.grant(ROW, "maria", apath, now=2000)
    assert approvals.approver(ROW, apath, now=2000 + approvals.MAX_AGE_S) == "maria"
    assert approvals.approver(ROW, apath, now=2000 + approvals.MAX_AGE_S + 1) is None
    assert approvals.approver(ROW, apath, now=1999) is None


@pytest.mark.parametrize("quem", ["", "agent", "policy:read", "sysop"])
def test_grant_recusa_nao_humanos(apath, quem):
    with pytest.raises(PermissionError):
        approvals.grant(ROW, quem, apath)


def test_grant_duplo_e_estado(apath):
    approvals.grant(ROW, "maria", apath)
    with pytest.raises(ValueError):
        approvals.grant(ROW, "maria", apath)
    with pytest.raises(ValueError):
        approvals.grant({**ROW, "id": 9, "status": "executed"}, "maria", apath)


def test_arquivo_ausente_ou_corrompido_falha_fechada(tmp_path):
    assert approvals.approver(ROW, str(tmp_path / "nao_existe.db")) is None
    ruim = tmp_path / "ruim.db"
    ruim.write_text("lixo")
    assert approvals.approver(ROW, str(ruim)) is None


def test_check_do_banco_recusa_agent_direto(apath):
    con = sqlite3.connect(apath)
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO approvals VALUES (1,1,'t','d','agent',1)")
    con.close()


def test_leitura_somente_leitura_nao_escreve(apath):
    approvals.grant(ROW, "maria", apath)
    ro = sqlite3.connect(f"file:{apath}?mode=ro", uri=True)
    with pytest.raises(sqlite3.OperationalError):
        ro.execute("DELETE FROM approvals")
    ro.close()
