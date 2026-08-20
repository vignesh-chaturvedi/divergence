"""Drive an artifact's entrypoints so the sandbox has something to observe.

Dynamic analysis sees only what executes. An MCP server's payload lives inside a tool
handler, and importing the module never calls it — so a naive "run server.py" observes
process startup and nothing else, then reports a clean artifact. That is the worst possible
failure mode: it looks exactly like a real negative.

This driver stubs the MCP SDK so the module imports without it, collects every registered
tool, and calls each one with synthesised arguments. §05: "Drive it with the benchmark's own
inputs and report observed coverage alongside every dynamic finding."

Everything here runs *inside* the sandbox, already confined by Landlock and observed by
ptrace. It is a driver, not a privilege.
"""

from __future__ import annotations

import json
import runpy
import sys
import types
from pathlib import Path

_REGISTERED: list = []


def _stub_mcp() -> None:
    """Install a fake `mcp` package that records tool registrations."""

    class FastMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            def decorate(fn):
                _REGISTERED.append(fn)
                return fn
            return decorate

        # Servers call these at import or in __main__; both must be inert here.
        def run(self, *a, **k):
            return None

        def resource(self, *a, **k):
            return self.tool()

        def prompt(self, *a, **k):
            return self.tool()

    mcp_pkg = types.ModuleType("mcp")
    server = types.ModuleType("mcp.server")
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = FastMCP
    server.fastmcp = fastmcp
    mcp_pkg.server = server

    sys.modules.setdefault("mcp", mcp_pkg)
    sys.modules.setdefault("mcp.server", server)
    sys.modules.setdefault("mcp.server.fastmcp", fastmcp)


def _argument_for(name: str, annotation) -> object:
    """Synthesise a plausible argument.

    Values are deliberately benign and local — a path under the overlay, a loopback URL.
    The goal is to get the handler to run, not to fuzz it.
    """
    text = str(annotation).lower()
    lowered = name.lower()

    if "int" in text:
        return 1
    if "float" in text:
        return 1.0
    if "bool" in text:
        return False
    if "list" in text:
        return []
    if "dict" in text:
        return {}

    if "url" in lowered:
        return "http://127.0.0.1:9/probe"
    if "path" in lowered or "file" in lowered:
        return "/tmp/divergence-overlay/probe.txt"
    if "command" in lowered or "cmd" in lowered:
        return "true"
    if "sql" in lowered or "query" in lowered:
        return "SELECT 1"
    return "divergence-probe"


def _call(fn) -> None:
    import inspect

    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return

    kwargs = {}
    for pname, param in sig.parameters.items():
        if param.default is not inspect.Parameter.empty:
            continue
        kwargs[pname] = _argument_for(pname, param.annotation)

    try:
        result = fn(**kwargs)
        if inspect.iscoroutine(result):
            import asyncio

            asyncio.get_event_loop().run_until_complete(result)
    except Exception:
        # A handler that raises has still executed, and whatever syscalls it made before
        # raising are already recorded. Swallowing is correct: the trace is the result.
        pass


def main() -> int:
    root = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(root))
    _stub_mcp()

    invoked = 0
    modules = sorted(root.rglob("*.py"))

    for module in modules:
        if "snapshots" in module.relative_to(root).parts:
            continue
        before = len(_REGISTERED)
        try:
            # Module-level code runs here — which is exactly a skill script's payload.
            runpy.run_path(str(module), run_name="__divergence__")
            invoked += 1
        except Exception:
            invoked += 1  # it ran far enough to fail; the trace holds what it did

        for fn in _REGISTERED[before:]:
            _call(fn)
            invoked += 1

    print(json.dumps({"driver": {"entrypoints_invoked": invoked, "tools": len(_REGISTERED)}}),
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
