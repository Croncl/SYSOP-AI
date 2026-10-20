"""Servidores MCP (stdio) que expõem o host ao agente como serviços padronizados.

  python mcp_server.py read     -> tools SOMENTE LEITURA (UFW, journald, AIDE)
  python mcp_server.py actions  -> UMA tool de escrita: execute_approved_action(action_id)

O agente NÃO escolhe argumentos de escrita: passa só um id; o servidor lê do banco (conexão mode=ro) os
argumentos que um HUMANO aprovou. Mesmo um agente comprometido não consegue banir um IP diferente do aprovado.
Dois servidores = duas permissões (o processo 'read' nem tem sudoers para fail2ban).
Lembrete (consolidado, seção 16): servidores MCP de terceiros injetam descrições no prompt; aqui só usamos
servidores NOSSOS, com descrições fixas.
"""
import json
import sys

from mcp.server.fastmcp import FastMCP

import db as dbm
import tools as T

mode = sys.argv[1] if len(sys.argv) > 1 else "read"
mcp = FastMCP(f"sysop-{mode}")

if mode == "read":
    @mcp.tool()
    def check_ufw_status() -> dict:
        """Estado do firewall UFW."""
        return T.call_tool("check_ufw_status", {})

    @mcp.tool()
    def query_journald(unit: str = "ssh", since: str = "30 min ago", limit: int = 50) -> dict:
        """Últimas linhas (sanitizadas) do journal de uma unidade da lista permitida."""
        return T.call_tool("query_journald", {"unit": unit, "since": since, "limit": limit})

    @mcp.tool()
    def run_aide_check() -> dict:
        """Verificação de integridade AIDE (pesada; minutos)."""
        return T.call_tool("run_aide_check", {})

elif mode == "actions":
    @mcp.tool()
    def execute_approved_action(action_id: int) -> dict:
        """Executa uma ação JÁ APROVADA por humano (status='approved'). Qualquer outro estado é recusado."""
        con = dbm.connect(readonly=True)
        row = con.execute("SELECT tool,args_json,status,approved_by FROM agent_actions WHERE id=?", (action_id,)).fetchone()
        if row is None or row["status"] != "approved" or not row["approved_by"] or row["approved_by"] == "agent":
            raise PermissionError("ação inexistente ou não aprovada por humano")
        if T.REGISTRY[row["tool"]].risk != "write":
            raise PermissionError("somente tools de escrita passam por aqui")
        args = json.loads(row["args_json"])
        if row["tool"] == "ban_ip_fail2ban" and T.is_protected(con, T.parse_ip(args["ip"])):
            raise PermissionError("IP em rede protegida")  # revalida no servidor: não confia na linha do banco
        return T.call_tool(row["tool"], args, approved=True)
else:
    raise SystemExit("modo: read | actions")

if __name__ == "__main__":
    mcp.run()  # transporte stdio
