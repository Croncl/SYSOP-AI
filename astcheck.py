"""Validador estático (AST) para tools geradas pelo LLM. Só stdlib: roda no host E dentro do sandbox.

Modelo de ameaça: o código vem do LLM, que leu LOGS controlados pelo atacante (log injection).
Estratégia: ALLOWLIST (não denylist). Uma tool gerada é uma função PURA `run(lines) -> dict` que analisa
linhas de log recebidas por argumento. Ela não abre arquivos, não usa rede, não executa processos, não
define classes. Tudo que não está explicitamente permitido é rejeitado. O AST é só a 1ª barreira:
a 2ª é o sandbox (sem rede, sem capabilities, FS somente leitura) e a 3ª é o humano (HITL).
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field

MAX_SOURCE_BYTES = 8192
MAX_NODES = 2500
ALLOWED_IMPORTS = frozenset({"re", "json", "ipaddress", "datetime", "collections", "math", "itertools", "statistics"})

# Nomes proibidos mesmo que alguém consiga referenciá-los (mensagens de erro mais claras que "não está na allowlist")
FORBIDDEN_NAMES = frozenset({
    "eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr", "globals", "locals", "vars",
    "dir", "input", "breakpoint", "exit", "quit", "help", "memoryview", "type", "object", "super", "classmethod",
    "staticmethod", "property", "print", "id", "bytearray", "bytes", "callable", "hasattr", "issubclass",
})
FORBIDDEN_ATTRS = frozenset({"format", "format_map", "mro", "system", "popen", "fork", "spawn", "environ"})
FORBIDDEN_ATTR_PREFIXES = ("gi_", "cr_", "ag_", "tb_", "f_", "co_", "func_")
FORBIDDEN_NODES = (
    ast.ClassDef, ast.AsyncFunctionDef, ast.Await, ast.Yield, ast.YieldFrom, ast.Global, ast.Nonlocal,
    ast.With, ast.AsyncWith, ast.AsyncFor, ast.Delete,
)


@dataclass
class Report:
    ok: bool
    sha256: str = ""
    errors: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    nodes: int = 0

    def as_dict(self) -> dict:
        return {"ok": self.ok, "sha256": self.sha256, "errors": self.errors, "imports": self.imports, "nodes": self.nodes}


def _is_literal(node: ast.AST) -> bool:
    try:
        ast.literal_eval(node)
        return True
    except Exception:
        return False


def _is_re_flag(n: ast.AST) -> bool:
    return isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "re" and n.attr.isupper()


def _safe_toplevel_value(node: ast.AST) -> bool:
    """Literal, ou re.compile(<literais>[, re.FLAG]): padrão comum e sem efeito colateral no import."""
    if _is_literal(node):
        return True
    if (isinstance(node, ast.Call) and not node.keywords and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and node.func.attr == "compile"):
        return all(_is_literal(a) or _is_re_flag(a) for a in node.args)
    return False


def validate(source: str) -> Report:
    rep = Report(ok=False)
    raw = source.encode("utf-8", "replace")
    rep.sha256 = hashlib.sha256(raw).hexdigest()
    if len(raw) > MAX_SOURCE_BYTES:
        rep.errors.append(f"código maior que {MAX_SOURCE_BYTES} bytes")
        return rep
    if "\x00" in source:
        rep.errors.append("byte nulo")
        return rep
    try:
        tree = ast.parse(source, mode="exec")
    except (SyntaxError, ValueError, RecursionError) as exc:
        rep.errors.append(f"sintaxe inválida: {type(exc).__name__}")
        return rep

    # --- forma do módulo: imports, docstring, constantes literais e funções ---
    run_fn = None
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                top = a.name.split(".")[0]
                if a.name != top or top not in ALLOWED_IMPORTS:
                    rep.errors.append(f"import proibido: {a.name}")
                rep.imports.append(a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level or (node.module or "").split(".")[0] not in ALLOWED_IMPORTS or "." in (node.module or ""):
                rep.errors.append(f"from-import proibido: {node.module}")
            rep.imports.append(node.module or "")
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            pass  # docstring
        elif isinstance(node, ast.Assign) and all(isinstance(t, ast.Name) for t in node.targets) and _safe_toplevel_value(node.value):
            pass  # constante literal (não executa código no import)
        elif isinstance(node, ast.FunctionDef):
            if node.decorator_list:
                rep.errors.append(f"decorator proibido em {node.name}")
            if node.name == "run":
                run_fn = node
        else:
            rep.errors.append(f"instrução de topo proibida: {type(node).__name__} (linha {getattr(node, 'lineno', '?')})")
    if run_fn is None:
        rep.errors.append("falta def run(lines)")
    else:
        a = run_fn.args
        if [x.arg for x in a.args] != ["lines"] or a.vararg or a.kwarg or a.kwonlyargs or a.defaults:
            rep.errors.append("assinatura deve ser exatamente run(lines)")

    # --- varredura completa de nós ---
    for node in ast.walk(tree):
        rep.nodes += 1
        if isinstance(node, FORBIDDEN_NODES):
            rep.errors.append(f"construção proibida: {type(node).__name__}")
        elif isinstance(node, ast.Name):
            if node.id in FORBIDDEN_NAMES or (node.id.startswith("__") and node.id.endswith("__")):
                rep.errors.append(f"nome proibido: {node.id}")
        elif isinstance(node, ast.Attribute):
            at = node.attr
            if at.startswith("_") or at in FORBIDDEN_ATTRS or at.startswith(FORBIDDEN_ATTR_PREFIXES):
                rep.errors.append(f"atributo proibido: .{at}")
        elif isinstance(node, ast.arg) and node.arg.startswith("__"):
            rep.errors.append("parâmetro dunder")
    if rep.nodes > MAX_NODES:
        rep.errors.append("código complexo demais")

    rep.errors = sorted(set(rep.errors))
    rep.ok = not rep.errors
    return rep
