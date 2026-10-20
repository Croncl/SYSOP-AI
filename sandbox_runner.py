"""Executado DENTRO do sandbox (container sem rede) com `python -I -S`. Lê JSON do stdin, escreve 1 linha JSON.

stdin : {"source": "...", "lines": ["..."]}
stdout: {"ok": true, "result": {...}} | {"ok": false, "error": "..."}
Defesa em profundidade: revalida o AST, usa builtins mínimos e __import__ restrito, impõe rlimits.
"""
import json
import os
import resource
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import astcheck  # noqa: E402

SAFE_BUILTIN_NAMES = (
    "abs all any bool dict enumerate filter float frozenset int isinstance len list map max min range reversed "
    "round set sorted str sum tuple zip chr ord divmod pow slice iter next "
    "Exception ValueError KeyError IndexError TypeError AttributeError ZeroDivisionError StopIteration"
).split()
MAX_OUT = 64 * 1024


def _limits():
    for res, val in ((resource.RLIMIT_CPU, 5), (resource.RLIMIT_AS, 256 * 2**20), (resource.RLIMIT_FSIZE, 0),
                     (resource.RLIMIT_NOFILE, 16), (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(res, (val, val))
        except (ValueError, OSError):
            pass


def main() -> None:
    req = json.loads(sys.stdin.read())
    src, lines = req["source"], req["lines"]
    rep = astcheck.validate(src)
    if not rep.ok:
        print(json.dumps({"ok": False, "error": "AST: " + "; ".join(rep.errors)}))
        return
    import builtins
    allowed = astcheck.ALLOWED_IMPORTS
    real_import = builtins.__import__

    def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level or name.split(".")[0] not in allowed:
            raise ImportError(f"import bloqueado: {name}")
        return real_import(name, globals, locals, fromlist, level)

    safe = {n: getattr(builtins, n) for n in SAFE_BUILTIN_NAMES}
    safe["__import__"] = guarded_import
    ns = {"__builtins__": safe, "__name__": "sysop_tool"}
    _limits()
    try:
        exec(compile(src, "<tool>", "exec"), ns)  # noqa: S102  (AST validado; builtins mínimos; sandbox externo)
        out = ns["run"]([str(x)[:2000] for x in lines[:20000]])
        if not isinstance(out, dict):
            raise TypeError("run() deve retornar dict")
        txt = json.dumps(out)
        if len(txt) > MAX_OUT:
            raise ValueError("saída maior que 64 KB")
        print(json.dumps({"ok": True, "result": out}))
    except BaseException as exc:  # inclui MemoryError
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}))


if __name__ == "__main__":
    main()
