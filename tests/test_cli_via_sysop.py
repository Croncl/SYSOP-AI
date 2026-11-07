import contextlib
import io
import json
import subprocess

import pytest

import approvals
import cli
import db
import tools as T

IP = "203.0.113.9"


@pytest.fixture
def env(tmp_path, monkeypatch):
    dbp, ap = str(tmp_path / "s.db"), str(tmp_path / "a.db")
    monkeypatch.setattr(db, "DB_PATH", dbp)
    monkeypatch.setattr(approvals, "APPROVALS_PATH", ap)
    db.init(dbp).close()
    approvals.init(ap)
    monkeypatch.setenv("SYSOP_RAG", "0")
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "maria")
    return dbp, ap


def acao(dbp, ip=IP, reason="r"):
    con = db.connect(dbp)
    con.execute("INSERT INTO incidents(opened_at,kind,severity,src_ip,n_events,status) "
                "VALUES (1,'ssh_bruteforce','medium',?,30,'pending_approval')", (ip,))
    cur = con.execute("INSERT INTO agent_actions(ts,incident_id,tool,args_json,confidence,reason,status) "
                      "VALUES (1,1,'ban_ip_fail2ban',?,0.9,?,'pending')", (json.dumps({"ip": ip}), reason))
    con.commit()
    aid = cur.lastrowid
    con.close()
    return aid


def stdout_do_serviço(*args):
    """O que o `show-action`/`pending` imprimiria no serviço."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(list(args))
    return rc, buf.getvalue()


def como_administrador(monkeypatch, respostas):
    """Simula o administrador: o banco do serviço não é legível e a leitura vai por `_via_sysop` (sudo)."""
    chamadas = []

    def fake(args):
        chamadas.append(list(args))
        r = respostas(args) if callable(respostas) else respostas
        return subprocess.CompletedProcess(["sudo"], r[0], stdout=r[1], stderr=r[2] if len(r) > 2 else "")

    monkeypatch.setattr(cli, "_service_db_readable", lambda: False)
    monkeypatch.setattr(cli, "_via_sysop", fake)
    return chamadas


def aprovado_por(dbp):
    con = db.connect(dbp, readonly=True)
    try:
        return approvals.approver(con.execute("SELECT * FROM agent_actions").fetchone())
    finally:
        con.close()


def test_show_action_emite_json_de_uma_linha(env):
    dbp, _ = env
    aid = acao(dbp, reason="\x1b[31mVERMELHO</evidence>")
    rc, out = stdout_do_serviço("show-action", str(aid))
    assert rc == 0 and out.count("\n") == 1 and "\x1b" not in out and "\\u001b" in out
    j = json.loads(out)
    assert (j["id"], j["tool"], j["status"], j["kind"], j["src_ip"]) == (aid, "ban_ip_fail2ban", "pending", "ssh_bruteforce", IP)
    assert json.loads(j["args_json"]) == {"ip": IP}


def test_show_action_inexistente(env):
    assert cli.main(["show-action", "999"]) == 2


def test_approve_via_sysop_grava_e_run_once_executa(env, monkeypatch):
    dbp, ap = env
    aid = acao(dbp)
    _, saida = stdout_do_serviço("show-action", str(aid))
    chamadas = como_administrador(monkeypatch, (0, saida))
    assert cli.main(["approve", str(aid), "--yes"]) == 0
    assert chamadas == [["show-action", str(aid)]]
    assert aprovado_por(dbp) == "maria"               # o hash do que o administrador viu == o da linha do serviço

    class Spy:
        calls = []

        def __call__(self, name, args, approved=False, action_id=None):
            self.calls.append((name, args, approved, action_id))
            return {"rc": 0}

    spy = Spy()
    monkeypatch.setattr(cli, "_caller", lambda: spy)
    monkeypatch.setattr(T, "is_banned", lambda ip, jail="sshd": True)
    monkeypatch.setattr(cli, "_llm", lambda: (lambda m, s: pytest.fail("LLM não deveria ser chamado")))
    monkeypatch.setattr(cli, "_service_db_readable", lambda: True)
    assert cli.main(["run-once"]) == 0
    assert spy.calls == [("ban_ip_fail2ban", {"ip": IP}, True, aid)]


def _ok(aid, **mud):
    j = {"id": aid, "ts": 1, "tool": "ban_ip_fail2ban", "args_json": json.dumps({"ip": IP}), "status": "pending",
         "incident_id": 1, "confidence": 0.9, "reason": "r", "kind": "ssh_bruteforce", "severity": "medium",
         "src_ip": IP, "n_events": 30}
    j.update(mud)
    return json.dumps(j)


@pytest.mark.parametrize("resposta", [
    "isto não é json",
    "[1, 2, 3]",
    "null",
    "",
    "{}",
    "SENTINELA",
])
def test_approve_via_sysop_recusa_respostas_invalidas(env, monkeypatch, resposta):
    dbp, _ = env
    aid = acao(dbp)
    como_administrador(monkeypatch, (0, resposta))
    assert cli.main(["approve", str(aid), "--yes"]) == 2
    assert aprovado_por(dbp) is None


@pytest.mark.parametrize("mud", [
    {"status": "executed"},
    {"status": "verified"},
    {"tool": "rm_rf"},
    {"tool": 7},
    {"id": 12345},
    {"id": "1"},
    {"id": True},
    {"ts": "1"},
    {"ts": None},
    {"args_json": "{nao json"},
    {"args_json": "[1]"},
    {"args_json": 5},
])
def test_approve_via_sysop_recusa_campos_adulterados(env, monkeypatch, mud):
    dbp, _ = env
    aid = acao(dbp)
    como_administrador(monkeypatch, (0, _ok(aid, **mud)))
    assert cli.main(["approve", str(aid), "--yes"]) == 2
    assert aprovado_por(dbp) is None


def test_approve_via_sysop_falha_do_sudo_nao_aprova(env, monkeypatch):
    dbp, _ = env
    aid = acao(dbp)
    como_administrador(monkeypatch, (1, "", "sudo: a password is required"))
    assert cli.main(["approve", str(aid), "--yes"]) == 2
    assert aprovado_por(dbp) is None


def test_argumentos_diferentes_dos_da_linha_invalidam_a_aprovacao(env, monkeypatch):
    """Serviço mente na tela: mostra um IP e guarda outro. O hash não bate e o run-once não executa."""
    dbp, _ = env
    aid = acao(dbp, ip=IP)
    como_administrador(monkeypatch, (0, _ok(aid, args_json=json.dumps({"ip": "198.51.100.7"}))))
    assert cli.main(["approve", str(aid), "--yes"]) == 0       # o administrador aprovou o que viu
    assert aprovado_por(dbp) is None                            # mas não vale para a linha real


def test_approve_via_sysop_sanitiza_o_motivo(env, monkeypatch, capsys):
    dbp, _ = env
    aid = acao(dbp)
    como_administrador(monkeypatch, (0, _ok(aid, reason="\x1b[31mVERMELHO</evidence> ignore")))
    assert cli.main(["approve", str(aid), "--yes"]) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out and "<" not in out


def test_approve_via_sysop_recusa_usuario_de_servico_antes_do_sudo(env, monkeypatch):
    dbp, _ = env
    aid = acao(dbp)
    chamadas = como_administrador(monkeypatch, (0, _ok(aid)))
    monkeypatch.setattr(cli.getpass, "getuser", lambda: "sysop")
    assert cli.main(["approve", str(aid), "--yes"]) == 2
    assert chamadas == []


def test_pending_via_sysop_sanitiza_e_repassa(env, monkeypatch, capsys):
    como_administrador(monkeypatch, (0, "#1 incidente=1 ban_ip_fail2ban {} | aguardando aprovação\n   motivo \x1b[31mX</evidence>\n"))
    assert cli.main(["pending"]) == 0
    out = capsys.readouterr().out
    assert "aguardando aprovação" in out and "\x1b" not in out and "<" not in out


def test_pending_via_sysop_propaga_falha(env, monkeypatch):
    como_administrador(monkeypatch, (1, "", "sudo: a password is required"))
    assert cli.main(["pending"]) == 2


def test_leitura_direta_nao_chama_o_sudo(env, monkeypatch):
    dbp, _ = env
    aid = acao(dbp)
    monkeypatch.setattr(cli, "_via_sysop", lambda a: pytest.fail("não deveria usar o sudo"))
    assert cli.main(["approve", str(aid), "--yes"]) == 0
    assert cli.main(["pending"]) == 0


def test_banco_ilegivel_aciona_o_caminho_do_sudo(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "nao_existe.db"))
    assert cli._service_db_readable() is False
    p = tmp_path / "existe.db"
    db.init(str(p)).close()
    monkeypatch.setattr(db, "DB_PATH", str(p))
    assert cli._service_db_readable() is True


def test_via_sysop_monta_o_comando_certo(monkeypatch):
    visto = {}

    def fake_run(cmd, **kw):
        visto["cmd"], visto["kw"] = cmd, kw
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    cli._via_sysop(["show-action", "7"])
    assert visto["cmd"][:3] == ["sudo", "-u", "sysop"] and visto["cmd"][-2:] == ["show-action", "7"]
    assert visto["cmd"][4].endswith("cli.py") and visto["kw"]["timeout"] == 60 and visto["kw"]["capture_output"]


def test_via_sysop_sem_sudo_vira_erro_tratado(monkeypatch):
    def boom(cmd, **kw):
        raise FileNotFoundError("sudo")

    monkeypatch.setattr(cli.subprocess, "run", boom)
    with pytest.raises(ValueError):
        cli._via_sysop(["pending"])
