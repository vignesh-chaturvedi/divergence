"""A minimal, deterministic capability probe — the P1 floor.

This is **not** A4. There is no reachability analysis and no taint tracking: a sink in
dead code counts the same as one on the hot path, and a capability reached through a
wrapper is missed. P2 replaces this with tree-sitter parsing, reachability from
entrypoints, and parameter taint into sinks.

It exists because A2's annotation check is defined in terms of behaviour — a tool
declaring `readOnlyHint: true` while its handler writes to disk — and that check is
worth having a phase early. The bias is deliberately toward over-reporting: a spurious
capability costs a posture note, while a missed one costs a missed annotation lie.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from divergence.core.vocabulary import Capability

SNAPSHOT_DIR = "snapshots"
_MAX_BYTES = 512_000


@dataclass
class Observed:
    """Capabilities found in an artifact's source, each with a file:line."""

    capabilities: set[Capability] = field(default_factory=set)
    evidence: dict[Capability, str] = field(default_factory=dict)

    def add(self, cap: Capability, where: str) -> None:
        self.capabilities.add(cap)
        # Keep the first sighting — stable across runs because files are walked sorted.
        self.evidence.setdefault(cap, where)

    def __contains__(self, cap: Capability) -> bool:
        return cap in self.capabilities


# --- Python: AST-based, so line numbers are real and comments never match -------------

_PY_ATTR_SINKS: dict[str, Capability] = {
    "urlopen": Capability.NET_OUTBOUND,
    "post": Capability.NET_OUTBOUND,
    "get": Capability.NET_OUTBOUND,
    "request": Capability.NET_OUTBOUND,
    "run": Capability.PROC_SPAWN,
    "Popen": Capability.PROC_SPAWN,
    "call": Capability.PROC_SPAWN,
    "check_output": Capability.PROC_SPAWN,
    "system": Capability.PROC_SPAWN,
    "read_text": Capability.FS_READ,
    "read_bytes": Capability.FS_READ,
    "write_text": Capability.FS_WRITE,
    "write_bytes": Capability.FS_WRITE,
    "mkdir": Capability.FS_WRITE,
    "unlink": Capability.FS_DELETE,
    "rmtree": Capability.FS_DELETE,
    "remove": Capability.FS_DELETE,
}

_PY_NAME_SINKS: dict[str, Capability] = {
    "eval": Capability.DYNAMIC_EVAL,
    "exec": Capability.DYNAMIC_EVAL,
    "compile": Capability.DYNAMIC_EVAL,
    "__import__": Capability.DYNAMIC_EVAL,
}

_NETWORK_MODULES = {"requests", "httpx", "urllib", "socket", "aiohttp"}
_PROC_MODULES = {"subprocess"}

# Paths that mean credentials rather than ordinary files. Matched as substrings because
# they appear in string literals, not as resolvable paths.
_SECRET_MARKERS = (
    ".ssh", "id_rsa", "id_ed25519", "authorized_keys",
    ".aws/credentials", ".aws", "credentials",
    ".netrc", ".npmrc", ".pypirc", ".kube/config",
    ".env", "secrets", "token", "apikey", "api_key",
)


def _is_secret_path(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in _SECRET_MARKERS)


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, obs: Observed, rel: str) -> None:
        self.obs, self.rel = obs, rel

    def _where(self, node: ast.AST) -> str:
        return f"{self.rel}:{getattr(node, 'lineno', 0)}"

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        if isinstance(func, ast.Name):
            cap = _PY_NAME_SINKS.get(func.id)
            if cap:
                self.obs.add(cap, self._where(node))
            if func.id == "open":
                mode = "r"
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                writing = any(m in mode for m in ("w", "a", "x", "+"))
                self.obs.add(
                    Capability.FS_WRITE if writing else Capability.FS_READ,
                    self._where(node),
                )

        elif isinstance(func, ast.Attribute):
            cap = _PY_ATTR_SINKS.get(func.attr)
            if cap:
                # `.get`/`.run` are common method names; only count them when the
                # receiver chain names a networking or subprocess module.
                if func.attr in ("get", "post", "request", "run", "call"):
                    root = func
                    names = []
                    while isinstance(root, ast.Attribute):
                        names.append(root.attr)
                        root = root.value
                    if isinstance(root, ast.Name):
                        names.append(root.id)
                    modules = set(names)
                    if cap is Capability.NET_OUTBOUND and not (modules & _NETWORK_MODULES):
                        cap = None
                    if cap is Capability.PROC_SPAWN and not (modules & _PROC_MODULES):
                        cap = None
                if cap:
                    self.obs.add(cap, self._where(node))

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # os.environ / os.getenv
        if node.attr in ("environ", "getenv"):
            self.obs.add(Capability.ENV_READ, self._where(node))
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and _is_secret_path(node.value):
            self.obs.add(Capability.SECRETS_READ, self._where(node))
        self.generic_visit(node)


def _probe_python(path: Path, rel: str, obs: Observed) -> None:
    try:
        tree = ast.parse(path.read_text()[:_MAX_BYTES])
    except (OSError, SyntaxError, ValueError):
        return
    _PyVisitor(obs, rel).visit(tree)


# --- Everything else: lexical, with line numbers from the match position --------------

_LEXICAL_PATTERNS: list[tuple[re.Pattern, Capability]] = [
    (re.compile(r"\bfetch\s*\(", re.I), Capability.NET_OUTBOUND),
    (re.compile(r"\baxios\b|\bXMLHttpRequest\b|\bWebSocket\b", re.I), Capability.NET_OUTBOUND),
    (re.compile(r"\bcurl\s+|\bwget\s+|\bnc\s+-|\bssh\s+\S+@", re.I), Capability.NET_OUTBOUND),
    # A bare URL is deliberately NOT a network capability. A documentation link is a
    # reference, not an action, and counting it flagged every read-only skill that cited
    # its own docs — an ordinary shape, and exactly the false positive this project
    # exists to avoid. Only an actionable fetch above counts.
    (re.compile(r"\bchild_process\b|\bexecSync\b|\bspawnSync\b|\bspawn\s*\(", re.I), Capability.PROC_SPAWN),
    (re.compile(r"\breadFile\b|\breadFileSync\b", re.I), Capability.FS_READ),
    (re.compile(r"\bwriteFile\b|\bwriteFileSync\b|\bmkdir\b", re.I), Capability.FS_WRITE),
    (re.compile(r"\bunlink\b|\brm\s+-rf\b|\brimraf\b", re.I), Capability.FS_DELETE),
    (re.compile(r"\bprocess\.env\b|\$\{?[A-Z_]*(TOKEN|KEY|SECRET)", re.I), Capability.ENV_READ),
    (re.compile(r"\beval\s*\(|new\s+Function\s*\(", re.I), Capability.DYNAMIC_EVAL),
    (re.compile(r"~/\.ssh|id_rsa|\.aws/credentials|\.netrc|authorized_keys", re.I), Capability.SECRETS_READ),
]

# Markdown bodies are probed too: a skill's payload is often a shell command in prose,
# never in a script file at all.
_LEXICAL_SUFFIXES = {".ts", ".js", ".mjs", ".tsx", ".sh", ".bash", ".md", ".txt", ".yaml", ".yml"}


def _probe_lexical(path: Path, rel: str, obs: Observed) -> None:
    try:
        text = path.read_text()[:_MAX_BYTES]
    except (OSError, UnicodeDecodeError):
        return

    for pattern, cap in _LEXICAL_PATTERNS:
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            obs.add(cap, f"{rel}:{line}")


def probe(root: Path, *, include_snapshots: bool = False) -> Observed:
    """Scan an artifact's files for capability sinks. Parses; never executes or imports."""
    root = Path(root)
    obs = Observed()

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue

        rel_parts = path.relative_to(root).parts
        # Relative, not absolute: a snapshot root *is* inside snapshots/, and testing
        # the absolute path would exclude every file the snapshot contains.
        if not include_snapshots and SNAPSHOT_DIR in rel_parts:
            continue

        rel = str(path.relative_to(root))
        if path.suffix == ".py":
            _probe_python(path, rel, obs)
        elif path.suffix in _LEXICAL_SUFFIXES:
            _probe_lexical(path, rel, obs)

    return obs
