"""Cliente MCP (stdio) com a mesma assinatura de tools.call_tool: troca o backend sem mexer no grafo."""
import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import tools as T

SERVER = str(Path(__file__).with_name("mcp_server.py"))


async def _call(mode: str, tool: str, arguments: dict, env: dict) -> dict:
    params = StdioServerParameters(command=sys.executable, args=[SERVER, mode], env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            res = await s.call_tool(tool, arguments)
    if res.isError:
        raise RuntimeError(res.content[0].text if res.content else "erro MCP")
    if res.structuredContent is not None:
        sc = res.structuredContent
        return sc.get("result", sc) if isinstance(sc, dict) and set(sc) == {"result"} else sc
    return json.loads(res.content[0].text)


def mcp_caller(timeout: int = 1900):
    env = {"PATH": os.environ.get("PATH", ""), "SYSOP_DB": os.environ.get("SYSOP_DB", ""),
           "PYTHONPATH": str(Path(__file__).parent)}

    def call(name: str, args: dict, approved: bool = False, action_id: int | None = None) -> dict:
        spec = T.REGISTRY[name]
        if spec.risk == "write":
            if not approved or action_id is None:
                raise PermissionError("escrita via MCP exige action_id aprovado")
            coro = _call("actions", "execute_approved_action", {"action_id": action_id}, env)
        else:
            coro = _call("read", name, args, env)
        return asyncio.run(asyncio.wait_for(coro, timeout))
    return call
