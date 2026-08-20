"""Execute Python artifact entrypoints and report truthful coverage over a private FD."""

from __future__ import annotations

import json
import os
import runpy
import sys
import types
from pathlib import Path

_REGISTERED: list = []
_SCHEMA = "divergence.sandbox.driver/1"


def _stub_mcp() -> None:
    """Install the minimum SDK surface needed to discover common FastMCP handlers."""

    class FastMCP:
        def __init__(self, *args, **kwargs):
            del args, kwargs

        def tool(self, fn=None, *args, **kwargs):
            del args, kwargs

            def decorate(function):
                _REGISTERED.append(function)
                return function

            return decorate(fn) if callable(fn) else decorate

        def run(self, *args, **kwargs):
            del args, kwargs
            return None

        def resource(self, *args, **kwargs):
            del args, kwargs
            return self.tool()

        def prompt(self, *args, **kwargs):
            del args, kwargs
            return self.tool()

    class Context:
        pass

    mcp_pkg = types.ModuleType("mcp")
    server = types.ModuleType("mcp.server")
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = FastMCP
    fastmcp.Context = Context
    server.fastmcp = fastmcp
    mcp_pkg.server = server
    sys.modules.setdefault("mcp", mcp_pkg)
    sys.modules.setdefault("mcp.server", server)
    sys.modules.setdefault("mcp.server.fastmcp", fastmcp)


def _argument_for(name: str, annotation) -> object:
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
        return "http://127.0.0.1:9/divergence-probe"
    if "path" in lowered or "file" in lowered:
        return str(Path(os.environ["TMPDIR"]) / "probe.txt")
    if "command" in lowered or "cmd" in lowered:
        return "true"
    if "sql" in lowered or "query" in lowered:
        return "SELECT 1"
    return "divergence-probe"


def _call(function) -> bool:
    import inspect

    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return False

    positional = []
    keywords = {}
    for name, parameter in signature.parameters.items():
        if parameter.default is not inspect.Parameter.empty:
            continue
        if parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        value = _argument_for(name, parameter.annotation)
        if parameter.kind is inspect.Parameter.POSITIONAL_ONLY:
            positional.append(value)
        else:
            keywords[name] = value

    try:
        result = function(*positional, **keywords)
        if inspect.iscoroutine(result):
            import asyncio

            asyncio.run(result)
        return True
    except BaseException:
        # The syscalls made before failure remain valid observations; coverage records the
        # failure rather than pretending the handler completed.
        return False


def _module_selection(root: Path, selector: str | None) -> tuple[list[Path], str | None, bool]:
    modules = [
        module
        for module in sorted(root.rglob("*.py"))
        if "snapshots" not in module.relative_to(root).parts
        and ".venv" not in module.relative_to(root).parts
    ]
    if not selector:
        return modules, None, True

    module_name, separator, handler_name = selector.partition(":")
    direct = (root / module_name).resolve()
    candidates = []
    try:
        direct.relative_to(root)
        if direct.is_file() and direct.suffix == ".py":
            candidates.append(direct)
        with_suffix = direct.with_suffix(".py")
        if with_suffix.is_file():
            candidates.append(with_suffix)
    except ValueError:
        return [], None, False
    candidates.extend(module for module in modules if module.stem == module_name)
    unique = sorted(set(candidates))
    if unique:
        return unique, handler_name or None, True
    if separator:
        return [], handler_name or None, False
    # A bare selector that is not a module is treated as a registered handler name.
    return modules, module_name, True


def _write_coverage(fd: int, coverage: dict) -> None:
    payload = json.dumps(coverage, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    offset = 0
    try:
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                break
            offset += written
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def main() -> int:
    if len(sys.argv) not in (2, 3):
        return 2
    try:
        coverage_fd = int(os.environ.pop("DIVERGENCE_DRIVER_FD"))
        os.set_inheritable(coverage_fd, False)
    except (KeyError, TypeError, ValueError, OSError):
        return 2

    root = Path(sys.argv[1]).resolve()
    selector = sys.argv[2] if len(sys.argv) == 3 else None
    coverage = {
        "schema": _SCHEMA,
        "entrypoints_invoked": 0,
        "entrypoints_completed": 0,
        "entrypoints_failed": 0,
    }
    exit_code = 0
    try:
        if not root.is_dir():
            return 2
        modules, handler_selector, valid = _module_selection(root, selector)
        if not valid:
            return 2

        sys.path.insert(0, str(root))
        _stub_mcp()
        matched_handler = handler_selector is None

        for module in modules:
            before = len(_REGISTERED)
            coverage["entrypoints_invoked"] += 1
            original_argv = sys.argv
            sys.argv = [str(module)]
            try:
                runpy.run_path(str(module), run_name="__divergence__")
                coverage["entrypoints_completed"] += 1
            except BaseException:
                coverage["entrypoints_failed"] += 1
                exit_code = 1
            finally:
                sys.argv = original_argv

            for function in _REGISTERED[before:]:
                if handler_selector and getattr(function, "__name__", "") != handler_selector:
                    continue
                matched_handler = True
                coverage["entrypoints_invoked"] += 1
                if _call(function):
                    coverage["entrypoints_completed"] += 1
                else:
                    coverage["entrypoints_failed"] += 1
                    exit_code = 1

        if not matched_handler or coverage["entrypoints_invoked"] == 0:
            exit_code = 2
        return exit_code
    finally:
        _write_coverage(coverage_fd, coverage)


if __name__ == "__main__":
    raise SystemExit(main())
