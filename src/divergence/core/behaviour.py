"""A4 — static behaviour extraction (B_s).

A tree-sitter parse of the implementation. Walk from each entrypoint — a tool handler or
a skill script — and collect the *reachable* capability set, then run a light taint pass
tracking entrypoint parameters into sinks.

Three things separate this from P1's flat sink scan, and each one closes a specific
failure it had:

**Attribution.** Capabilities belong to the entrypoints that can reach them. P1 blamed a
read-only tool for its sibling's `write_text`, which forced a guard that cost recall. A
call graph removes the guess.

**Parsing, not matching.** A sink inside a comment or a string literal is not a sink. A
regex cannot tell the difference; a grammar can, and the corpus contains artifacts that
discuss dangerous operations without performing them.

**Honest limits.** Unresolved calls are counted and reported rather than silently
dropped. §11 is explicit: scope aggressively, publish the false-negative rate, and do not
claim soundness we do not have.

What this still does not do, and P5's sandbox does: anything dynamic. A capability
reached through a computed attribute, a re-export, or a decoded payload is invisible
here by construction.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import tree_sitter_bash
import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

from divergence.core.vocabulary import Capability

SNAPSHOT_DIR = "snapshots"
_MAX_BYTES = 512_000

PYTHON = Language(tree_sitter_python.language())
TYPESCRIPT = Language(tree_sitter_typescript.language_typescript())
TSX = Language(tree_sitter_typescript.language_tsx())
BASH = Language(tree_sitter_bash.language())

_BY_SUFFIX: dict[str, tuple[Language, str]] = {
    ".py": (PYTHON, "python"),
    ".ts": (TYPESCRIPT, "typescript"),
    ".mts": (TYPESCRIPT, "typescript"),
    ".js": (TYPESCRIPT, "typescript"),
    ".mjs": (TYPESCRIPT, "typescript"),
    ".tsx": (TSX, "typescript"),
    ".jsx": (TSX, "typescript"),
    ".sh": (BASH, "bash"),
    ".bash": (BASH, "bash"),
}

MODULE_SCOPE = "<module>"

# Fenced code blocks inside a skill body. The body is prose, but a fenced block is source
# the agent is told to run — a skill's payload is frequently a `curl … | sh` that never
# appears in any script file. Only fenced blocks count; prose that merely mentions a
# command is documentation, and treating it as code was a P1 false-positive source.
_FENCE_RE = re.compile(r"^[ \t]*```([A-Za-z0-9_+-]*)[ \t]*\n(.*?)^[ \t]*```", re.DOTALL | re.MULTILINE)

_FENCE_LANGUAGES = {
    "": (BASH, "bash"),
    "sh": (BASH, "bash"),
    "bash": (BASH, "bash"),
    "shell": (BASH, "bash"),
    "console": (BASH, "bash"),
    "zsh": (BASH, "bash"),
    "python": (PYTHON, "python"),
    "py": (PYTHON, "python"),
    "typescript": (TYPESCRIPT, "typescript"),
    "ts": (TYPESCRIPT, "typescript"),
    "javascript": (TYPESCRIPT, "typescript"),
    "js": (TYPESCRIPT, "typescript"),
}


def _fenced_blocks(text: str) -> list[tuple[Language, str, str, int]]:
    """Extract (language, family, source, starting line) for each fenced block."""
    blocks = []
    for match in _FENCE_RE.finditer(text):
        label = (match.group(1) or "").lower()
        entry = _FENCE_LANGUAGES.get(label)
        if entry is None:
            continue
        language, family = entry
        line = text.count("\n", 0, match.start()) + 1
        blocks.append((language, family, match.group(2), line))
    return blocks


@dataclass(frozen=True, slots=True)
class Sink:
    """One capability-bearing call, with where it is and what flows into it."""

    capability: Capability
    location: str
    callee: str = ""
    tainted_by: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Entrypoint:
    """A tool handler or script, with everything reachable from it."""

    name: str
    kind: str  # "tool_handler" | "script"
    location: str
    capabilities: frozenset[Capability] = frozenset()
    sinks: tuple[Sink, ...] = ()
    reached: tuple[str, ...] = ()

    @property
    def tainted_sinks(self) -> tuple[Sink, ...]:
        return tuple(s for s in self.sinks if s.tainted_by)


@dataclass
class Behaviour:
    """B_s for one artifact."""

    entrypoints: tuple[Entrypoint, ...] = ()
    capabilities: set[Capability] = field(default_factory=set)
    evidence: dict[Capability, str] = field(default_factory=dict)
    unreachable_capabilities: set[Capability] = field(default_factory=set)
    unreachable_evidence: dict[Capability, str] = field(default_factory=dict)
    functions: tuple[Entrypoint, ...] = ()
    unresolved: tuple[str, ...] = ()
    parse_errors: tuple[str, ...] = ()

    def for_entrypoint(self, name: str) -> Entrypoint:
        for e in self.entrypoints:
            if e.name == name:
                return e
        raise KeyError(f"no entrypoint named {name!r}")

    def find(self, name: str) -> Entrypoint | None:
        """Reachable set for any named function, entrypoint or not.

        A tool declared in a manifest may be implemented by a plain function that no
        decorator marks. Callers that know a name from the declared surface can resolve
        it here rather than falling back to an artifact-wide reading.
        """
        for e in (*self.entrypoints, *self.functions):
            if e.name == name:
                return e
        return None

    @property
    def all_capabilities(self) -> set[Capability]:
        """Reachable plus unreachable. What the artifact contains, not what it runs."""
        return self.capabilities | self.unreachable_capabilities


# --- sink tables ---------------------------------------------------------------------
# Keyed by the resolved callee name. `_QUALIFIED` entries must match the full dotted
# path, because their final segment is a common method name — `.get` and `.run` appear
# on dictionaries and test runners far more often than on HTTP clients.

_PY_QUALIFIED: dict[str, Capability] = {
    "urllib.request.urlopen": Capability.NET_OUTBOUND,
    "requests.get": Capability.NET_OUTBOUND,
    "requests.post": Capability.NET_OUTBOUND,
    "requests.put": Capability.NET_OUTBOUND,
    "requests.request": Capability.NET_OUTBOUND,
    "httpx.get": Capability.NET_OUTBOUND,
    "httpx.post": Capability.NET_OUTBOUND,
    "socket.socket": Capability.NET_OUTBOUND,
    "subprocess.run": Capability.PROC_SPAWN,
    "subprocess.Popen": Capability.PROC_SPAWN,
    "subprocess.call": Capability.PROC_SPAWN,
    "subprocess.check_output": Capability.PROC_SPAWN,
    "subprocess.check_call": Capability.PROC_SPAWN,
    "os.system": Capability.PROC_SPAWN,
    "os.popen": Capability.PROC_SPAWN,
    "os.execv": Capability.PROC_SPAWN,
    "shutil.rmtree": Capability.FS_DELETE,
    "os.remove": Capability.FS_DELETE,
    "os.unlink": Capability.FS_DELETE,
    "os.rmdir": Capability.FS_DELETE,
    "os.makedirs": Capability.FS_WRITE,
    # A database connection opens a file. Deliberately FS_READ only: proving a write
    # means understanding the SQL that flows through it, which no parser does. Recorded
    # as a known false negative rather than an over-claim.
    "sqlite3.connect": Capability.FS_READ,
}

_PY_METHOD: dict[str, Capability] = {
    "read_text": Capability.FS_READ,
    "read_bytes": Capability.FS_READ,
    "write_text": Capability.FS_WRITE,
    "write_bytes": Capability.FS_WRITE,
    "mkdir": Capability.FS_WRITE,
    "unlink": Capability.FS_DELETE,
    "urlopen": Capability.NET_OUTBOUND,
}

_PY_BARE: dict[str, Capability] = {
    "eval": Capability.DYNAMIC_EVAL,
    "exec": Capability.DYNAMIC_EVAL,
    "compile": Capability.DYNAMIC_EVAL,
    "__import__": Capability.DYNAMIC_EVAL,
}

_TS_NAMES: dict[str, Capability] = {
    "fetch": Capability.NET_OUTBOUND,
    "readFile": Capability.FS_READ,
    "readFileSync": Capability.FS_READ,
    "createReadStream": Capability.FS_READ,
    "writeFile": Capability.FS_WRITE,
    "writeFileSync": Capability.FS_WRITE,
    "appendFile": Capability.FS_WRITE,
    "mkdir": Capability.FS_WRITE,
    "unlink": Capability.FS_DELETE,
    "rmSync": Capability.FS_DELETE,
    "exec": Capability.PROC_SPAWN,
    "execSync": Capability.PROC_SPAWN,
    "spawn": Capability.PROC_SPAWN,
    "spawnSync": Capability.PROC_SPAWN,
    "eval": Capability.DYNAMIC_EVAL,
    "Function": Capability.DYNAMIC_EVAL,
    # Headless browser drivers. Navigating is egress, launching is a process, and
    # evaluating a page script is dynamic execution — all three are real capabilities a
    # browser-automation server genuinely has, and all three are declared by honest ones.
    "goto": Capability.NET_OUTBOUND,
    "launch": Capability.PROC_SPAWN,
    "evaluate": Capability.DYNAMIC_EVAL,
}

_TS_QUALIFIED: dict[str, Capability] = {
    "axios.get": Capability.NET_OUTBOUND,
    "axios.post": Capability.NET_OUTBOUND,
    "http.request": Capability.NET_OUTBOUND,
    "https.request": Capability.NET_OUTBOUND,
}

# Shell command names. Deliberately not "any command is a subprocess" — a script that
# runs `echo` has no capability worth reporting, and saying otherwise makes every shell
# script look identical.
_SHEBANG_FAMILIES = {
    "sh": (BASH, "bash"), "bash": (BASH, "bash"), "zsh": (BASH, "bash"),
    "python": (PYTHON, "python"), "python3": (PYTHON, "python"),
    "node": (TYPESCRIPT, "typescript"),
}


def _language_from_shebang(path: Path) -> tuple[Language, str] | None:
    """Resolve a suffix-less executable by its interpreter line.

    A skill can bundle `bin/optimize` with no extension. Skipping it because the filename
    carries no suffix would hand an attacker a trivial way to hide a script.
    """
    try:
        with path.open("rb") as fh:
            first = fh.readline(256).decode("utf-8", "replace")
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    for token in reversed(first.strip().replace("/", " ").split()):
        entry = _SHEBANG_FAMILIES.get(token.strip())
        if entry is not None:
            return entry
    return None


_SH_COMMANDS: dict[str, Capability] = {
    "curl": Capability.NET_OUTBOUND,
    "wget": Capability.NET_OUTBOUND,
    "nc": Capability.NET_OUTBOUND,
    "netcat": Capability.NET_OUTBOUND,
    "scp": Capability.NET_OUTBOUND,
    "sftp": Capability.NET_OUTBOUND,
    "ssh": Capability.NET_OUTBOUND,
    "rsync": Capability.NET_OUTBOUND,
    "cat": Capability.FS_READ,
    "head": Capability.FS_READ,
    "tail": Capability.FS_READ,
    "tee": Capability.FS_WRITE,
    "touch": Capability.FS_WRITE,
    "mkdir": Capability.FS_WRITE,
    "cp": Capability.FS_WRITE,
    "mv": Capability.FS_WRITE,
    "rm": Capability.FS_DELETE,
    "rmdir": Capability.FS_DELETE,
    "eval": Capability.DYNAMIC_EVAL,
    "source": Capability.DYNAMIC_EVAL,
    "sh": Capability.PROC_SPAWN,
    "bash": Capability.PROC_SPAWN,
    "zsh": Capability.PROC_SPAWN,
    "xargs": Capability.PROC_SPAWN,
    "sudo": Capability.PROC_SPAWN,
}

_SECRET_MARKERS = (
    ".ssh", "id_rsa", "id_ed25519", "authorized_keys",
    ".aws/credentials", ".aws", "credentials",
    ".netrc", ".npmrc", ".pypirc", ".kube/config",
    ".env", "secrets", "apikey", "api_key",
)

# Names that are never worth reporting as unresolved.
_IGNORE_UNRESOLVED = {
    "print", "len", "str", "int", "float", "dict", "list", "set", "tuple", "bool",
    "sorted", "sum", "min", "max", "range", "enumerate", "zip", "map", "filter",
    "isinstance", "getattr", "setattr", "hasattr", "repr", "format", "abs", "round",
    "any", "all", "next", "iter", "type", "super", "hash", "id", "bytes", "join",
    "split", "strip", "lower", "upper", "startswith", "endswith", "replace", "append",
    "extend", "items", "keys", "values", "encode", "decode", "loads", "dumps", "Path",
    "FastMCP", "get", "add", "pop", "setdefault", "discard", "console", "log", "JSON",
    "stringify", "parse", "Promise", "Error", "String", "Number", "Array", "Object",
    "require", "echo", "exit", "return", "test", "read", "local", "export", "printf",
}


# --- generic tree helpers -------------------------------------------------------------

def _text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _line(node: Node) -> int:
    return node.start_point[0] + 1


def _walk(node: Node):
    """Depth-first over every node. Cheap enough at corpus scale, and version-stable."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _dotted_name(node: Node, src: bytes) -> str:
    """Resolve a callee node to a dotted name, e.g. `urllib.request.urlopen`."""
    if node.type in ("identifier", "word"):
        return _text(node, src)
    if node.type in ("attribute", "member_expression"):
        obj = node.child_by_field_name("object")
        attr = node.child_by_field_name("attribute") or node.child_by_field_name("property")
        if obj is not None and attr is not None:
            left = _dotted_name(obj, src)
            return f"{left}.{_text(attr, src)}" if left else _text(attr, src)
    return _text(node, src).split("(")[0].strip()


def _identifiers_in(node: Node, src: bytes) -> set[str]:
    return {
        _text(n, src)
        for n in _walk(node)
        if n.type in ("identifier", "word", "variable_name")
    }


# --- per-file analysis ----------------------------------------------------------------

@dataclass
class _Scope:
    """One function (or module scope) in one file."""

    name: str
    kind: str
    location: str
    params: tuple[str, ...] = ()
    sinks: list[Sink] = field(default_factory=list)
    calls: set[str] = field(default_factory=set)
    is_entrypoint: bool = False

    # Raw material for the taint pass, which cannot run during the tree walk: a variable
    # may be assigned from a parameter before the sink that consumes it is even visited.
    raw_sinks: list[tuple[Capability, str, str, frozenset[str]]] = field(default_factory=list)
    assignments: list[tuple[frozenset[str], frozenset[str]]] = field(default_factory=list)


def _make_owner_lookup(func_nodes: list[tuple[Node, "_Scope"]], module: "_Scope"):
    """Return a function mapping any node to the innermost scope containing it.

    Innermost wins, so a sink inside a nested function is attributed to that function
    rather than to whatever encloses it.
    """

    def owner_of(node: Node) -> _Scope:
        best, best_span = module, None
        for fnode, scope in func_nodes:
            if fnode.start_byte <= node.start_byte and node.end_byte <= fnode.end_byte:
                span = fnode.end_byte - fnode.start_byte
                if best_span is None or span < best_span:
                    best, best_span = scope, span
        return best

    return owner_of


def _string_literal_secret(node: Node, src: bytes) -> bool:
    """True when a string literal *is* a credential-bearing path.

    Three exclusions, each found by verifying the extractor against the corpus by hand:

    - **Docstrings.** A tool that documents "reads the key at ~/.ssh/id_rsa" is telling
      you what it does, not doing it. Prose is not a path.
    - **Interpolated strings.** `f"sess-{hash(api_key)}"` mentions a credential-shaped
      identifier and touches nothing.
    - **Anything containing whitespace.** A real path literal is a single token; a
      sentence is not.

    Without these, honest artifacts that merely *discuss* credentials were credited with
    reading them — a false positive on exactly the security-vocabulary trap family.
    """
    raw = _text(node, src)

    # An f-string / template literal interpolates; it is not a fixed path.
    if node.type in ("template_string", "formatted_string") or raw[:2].lower().startswith("f"):
        if any(c in raw for c in "{}"):
            return False
    if any(child.type in ("interpolation", "template_substitution") for child in node.children):
        return False

    # A docstring is the first statement of a module, class, or function body.
    parent = node.parent
    if parent is not None and parent.type == "expression_statement":
        grand = parent.parent
        if grand is not None and grand.type in ("block", "module") and grand.children:
            if grand.children[0] is parent:
                return False

    value = raw.strip("\"'`").lower()
    if not value or any(c.isspace() for c in value):
        return False

    return any(marker in value for marker in _SECRET_MARKERS)


def _solve_taint(scope: _Scope) -> None:
    """Propagate parameter taint through local assignments, then label each sink.

    Taint carries **provenance**: each tainted name remembers which entrypoint parameters
    it derives from, so a sink reports `cmd` rather than the local alias `full` that
    happened to carry it. The originating parameter is what a reviewer needs — it names
    the attacker-controlled input, and the alias is an implementation detail.

    A deliberately small fixpoint: names only, no field or index sensitivity, and no
    propagation across calls. §04 asks for "a light taint pass tracking parameters into
    sinks"; anything more is P2 overrun, and the sandbox settles the hard cases anyway.
    """
    origins: dict[str, set[str]] = {p: {p} for p in scope.params}

    for _ in range(len(scope.assignments) + 1):
        grew = False
        for lhs, rhs in scope.assignments:
            inherited = set().union(*(origins[r] for r in rhs if r in origins)) if rhs else set()
            if not inherited:
                continue
            for name in lhs:
                before = origins.get(name, set())
                if not inherited <= before:
                    origins[name] = before | inherited
                    grew = True
        if not grew:
            break

    def provenance(args: frozenset[str]) -> tuple[str, ...]:
        found: set[str] = set()
        for name in args:
            found |= origins.get(name, set())
        return tuple(sorted(found))

    scope.sinks = [
        Sink(capability=cap, location=loc, callee=callee, tainted_by=provenance(args))
        for cap, loc, callee, args in scope.raw_sinks
    ] + scope.sinks


def _python_scopes(tree, src: bytes, rel: str) -> tuple[list[_Scope], set[str]]:
    scopes: list[_Scope] = []
    unresolved: set[str] = set()

    # Map every function body node to its owning scope so a single pass can attribute.
    module = _Scope(name=MODULE_SCOPE, kind="script", location=f"{rel}:1")
    scopes.append(module)

    func_nodes: list[tuple[Node, _Scope]] = []

    for node in _walk(tree.root_node):
        if node.type != "function_definition":
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _text(name_node, src)

        params: list[str] = []
        params_node = node.child_by_field_name("parameters")
        if params_node is not None:
            for p in _walk(params_node):
                if p.type == "identifier" and p.parent is not None and p.parent.type in (
                    "parameters", "typed_parameter", "default_parameter",
                    "typed_default_parameter",
                ):
                    params.append(_text(p, src))

        # `@mcp.tool()` — a decorated registration is the handler entrypoint.
        decorated = node.parent is not None and node.parent.type == "decorated_definition"
        is_tool = False
        if decorated:
            for dec in node.parent.children:
                if dec.type == "decorator" and ".tool" in _text(dec, src):
                    is_tool = True

        scope = _Scope(
            name=name,
            kind="tool_handler" if is_tool else "function",
            location=f"{rel}:{_line(node)}",
            params=tuple(dict.fromkeys(params)),
            is_entrypoint=is_tool,
        )
        scopes.append(scope)
        func_nodes.append((node, scope))

    owner_of = _make_owner_lookup(func_nodes, module)

    for node in _walk(tree.root_node):
        if node.type == "call":
            fn = node.child_by_field_name("function")
            if fn is None:
                continue
            name = _dotted_name(fn, src)
            scope = owner_of(node)
            loc = f"{rel}:{_line(node)}"

            cap = _PY_QUALIFIED.get(name)
            if cap is None and "." in name:
                cap = _PY_METHOD.get(name.rsplit(".", 1)[1])
            if cap is None and "." not in name:
                cap = _PY_BARE.get(name)

            if name == "open" or name.endswith(".open"):
                mode = "r"
                args = node.child_by_field_name("arguments")
                if args is not None:
                    strings = [a for a in args.children if a.type == "string"]
                    if len(strings) > 1:
                        mode = _text(strings[1], src).strip("\"'")
                cap = Capability.FS_WRITE if any(m in mode for m in "wax+") else Capability.FS_READ

            if cap is not None:
                args_node = node.child_by_field_name("arguments") or node
                scope.raw_sinks.append(
                    (cap, loc, name, frozenset(_identifiers_in(args_node, src)))
                )
            else:
                scope.calls.add(name.rsplit(".", 1)[-1])
                base = name.split(".", 1)[0]
                if base not in _IGNORE_UNRESOLVED and name.rsplit(".", 1)[-1] not in _IGNORE_UNRESOLVED:
                    unresolved.add(name)

        elif node.type == "attribute":
            attr = node.child_by_field_name("attribute")
            if attr is not None and _text(attr, src) in ("environ", "getenv"):
                owner_of(node).sinks.append(
                    Sink(Capability.ENV_READ, f"{rel}:{_line(node)}", callee="os.environ")
                )

        elif node.type == "string" and _string_literal_secret(node, src):
            owner_of(node).sinks.append(
                Sink(Capability.SECRETS_READ, f"{rel}:{_line(node)}", callee="<path literal>")
            )

        elif node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                owner_of(node).assignments.append(
                    (frozenset(_identifiers_in(left, src)), frozenset(_identifiers_in(right, src)))
                )

    for scope in scopes:
        _solve_taint(scope)

    return scopes, unresolved


def _typescript_scopes(tree, src: bytes, rel: str) -> tuple[list[_Scope], set[str]]:
    scopes: list[_Scope] = []
    unresolved: set[str] = set()
    module = _Scope(name=MODULE_SCOPE, kind="script", location=f"{rel}:1", is_entrypoint=True)
    scopes.append(module)

    func_nodes: list[tuple[Node, _Scope]] = []
    fn_types = {
        "function_declaration", "function_expression", "arrow_function",
        "method_definition", "generator_function_declaration",
    }

    for node in _walk(tree.root_node):
        if node.type not in fn_types:
            continue
        name_node = node.child_by_field_name("name")
        name = _text(name_node, src) if name_node is not None else f"<anon:{_line(node)}>"

        params: list[str] = []
        params_node = node.child_by_field_name("parameters")
        if params_node is not None:
            for p in _walk(params_node):
                if p.type == "identifier" and p.parent is not None and p.parent.type in (
                    "formal_parameters", "required_parameter", "optional_parameter",
                ):
                    params.append(_text(p, src))

        scope = _Scope(
            name=name, kind="function", location=f"{rel}:{_line(node)}",
            params=tuple(dict.fromkeys(params)), is_entrypoint=True,
        )
        scopes.append(scope)
        func_nodes.append((node, scope))

    owner_of = _make_owner_lookup(func_nodes, module)

    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn is None:
                continue
            name = _dotted_name(fn, src)
            scope = owner_of(node)
            loc = f"{rel}:{_line(node)}"

            cap = _TS_QUALIFIED.get(name) or _TS_NAMES.get(name.rsplit(".", 1)[-1])
            if cap is not None:
                args = node.child_by_field_name("arguments") or node
                scope.raw_sinks.append(
                    (cap, loc, name, frozenset(_identifiers_in(args, src)))
                )
            else:
                scope.calls.add(name.rsplit(".", 1)[-1])
                if name.rsplit(".", 1)[-1] not in _IGNORE_UNRESOLVED:
                    unresolved.add(name)

        elif node.type == "member_expression":
            if _dotted_name(node, src).startswith("process.env"):
                owner_of(node).sinks.append(
                    Sink(Capability.ENV_READ, f"{rel}:{_line(node)}", callee="process.env")
                )

        elif node.type in ("string", "template_string") and _string_literal_secret(node, src):
            owner_of(node).sinks.append(
                Sink(Capability.SECRETS_READ, f"{rel}:{_line(node)}", callee="<path literal>")
            )

        elif node.type in ("variable_declarator", "assignment_expression"):
            left = node.child_by_field_name("name") or node.child_by_field_name("left")
            right = node.child_by_field_name("value") or node.child_by_field_name("right")
            if left is not None and right is not None:
                owner_of(node).assignments.append(
                    (frozenset(_identifiers_in(left, src)), frozenset(_identifiers_in(right, src)))
                )

    for scope in scopes:
        _solve_taint(scope)

    return scopes, unresolved


def _bash_scopes(tree, src: bytes, rel: str) -> tuple[list[_Scope], set[str]]:
    """Shell. §04 is candid that this is where static analysis is weakest.

    A grammar gets us past the obvious failure — a command inside a comment or a quoted
    string is not a command. It does not get us past a command assembled from fragments
    at runtime, and nothing static will.
    """
    scopes: list[_Scope] = []
    unresolved: set[str] = set()
    module = _Scope(name=MODULE_SCOPE, kind="script", location=f"{rel}:1", is_entrypoint=True)
    scopes.append(module)

    for node in _walk(tree.root_node):
        if node.type == "command":
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            name = _text(name_node, src).strip()
            cap = _SH_COMMANDS.get(name)
            if cap is not None:
                module.sinks.append(
                    Sink(cap, f"{rel}:{_line(node)}", callee=name)
                )
            elif name not in _IGNORE_UNRESOLVED:
                unresolved.add(name)

        elif node.type == "file_redirect":
            module.sinks.append(
                Sink(Capability.FS_WRITE, f"{rel}:{_line(node)}", callee="<redirect>")
            )

    return scopes, unresolved


_DISPATCH = {
    "python": _python_scopes,
    "typescript": _typescript_scopes,
    "bash": _bash_scopes,
}


# --- assembly -------------------------------------------------------------------------

def extract(root: Path, *, include_snapshots: bool = False) -> Behaviour:
    """Extract B_s for an artifact: per-entrypoint reachable capabilities plus taint."""
    root = Path(root)

    all_scopes: dict[str, list[_Scope]] = {}
    entrypoints_raw: list[tuple[str, _Scope]] = []
    unresolved: set[str] = set()
    parse_errors: list[str] = []

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if not include_snapshots and SNAPSHOT_DIR in rel_parts:
            continue

        rel = str(path.relative_to(root))

        if path.suffix == ".md":
            try:
                body = path.read_text()[:_MAX_BYTES]
            except (OSError, UnicodeDecodeError):
                continue
            for language, family, block_src, line in _fenced_blocks(body):
                tree = Parser(language).parse(block_src.encode())
                label = f"{rel}#L{line}"
                scopes, block_unresolved = _DISPATCH[family](tree, block_src.encode(), label)
                unresolved |= block_unresolved
                for scope in scopes:
                    if not scope.sinks and not scope.calls:
                        continue
                    scope.is_entrypoint = True
                    all_scopes.setdefault(scope.name, []).append(scope)
                    entrypoints_raw.append((label, scope))
            continue

        entry = _BY_SUFFIX.get(path.suffix) or _language_from_shebang(path)
        if entry is None:
            continue
        language, family = entry

        try:
            src = path.read_bytes()[:_MAX_BYTES]
        except OSError:
            continue
        tree = Parser(language).parse(src)
        if tree.root_node.has_error:
            parse_errors.append(rel)

        scopes, file_unresolved = _DISPATCH[family](tree, src, rel)
        unresolved |= file_unresolved

        for scope in scopes:
            all_scopes.setdefault(scope.name, []).append(scope)
            if scope.is_entrypoint:
                entrypoints_raw.append((rel, scope))

        # Module scope runs at import, so anything it reaches is reachable by
        # definition — including the constants a handler later dereferences. Verification
        # found a credential manager whose store path was a module-level constant being
        # reported as unreachable, which is plainly wrong: importing the server builds it.
        module = next((s for s in scopes if s.name == MODULE_SCOPE), None)
        if module is not None and (module.sinks or module.calls) and not module.is_entrypoint:
            module.is_entrypoint = True
            entrypoints_raw.append((rel, module))

    def resolve(name: str) -> list[_Scope]:
        return [s for s in all_scopes.get(name, []) if s.kind != "script"]

    reachable_scopes: set[int] = set()

    def walk(scope: _Scope, *, mark: bool) -> tuple[tuple[Sink, ...], tuple[str, ...]]:
        """Breadth-first over the call graph from one scope.

        `mark` records which scopes an entrypoint can reach, so anything left unmarked
        afterwards is genuinely unreferenced rather than merely not yet visited.
        """
        sinks: list[Sink] = list(scope.sinks)
        seen: set[str] = set()
        if mark:
            reachable_scopes.add(id(scope))

        queue = deque(scope.calls)
        while queue:
            callee = queue.popleft()
            if callee in seen:
                continue
            seen.add(callee)
            for target in resolve(callee):
                if mark:
                    reachable_scopes.add(id(target))
                sinks.extend(target.sinks)
                queue.extend(target.calls)

        return tuple(sinks), tuple(sorted(seen))

    built: list[Entrypoint] = []
    for rel, scope in entrypoints_raw:
        sinks, reached = walk(scope, mark=True)
        built.append(
            Entrypoint(
                name=scope.name if scope.name != MODULE_SCOPE else rel,
                kind="tool_handler" if scope.kind == "tool_handler" else "script",
                location=scope.location,
                capabilities=frozenset(s.capability for s in sinks),
                sinks=sinks,
                reached=reached,
            )
        )

    functions: list[Entrypoint] = []
    for name, scopes in all_scopes.items():
        for scope in scopes:
            if scope.is_entrypoint or scope.kind == "script" or name == MODULE_SCOPE:
                continue
            sinks, reached = walk(scope, mark=False)
            functions.append(
                Entrypoint(
                    name=scope.name, kind="function", location=scope.location,
                    capabilities=frozenset(s.capability for s in sinks),
                    sinks=sinks, reached=reached,
                )
            )

    behaviour = Behaviour(
        entrypoints=tuple(built),
        functions=tuple(functions),
        unresolved=tuple(sorted(unresolved)),
        parse_errors=tuple(parse_errors),
    )

    for ep in built:
        for sink in ep.sinks:
            behaviour.capabilities.add(sink.capability)
            behaviour.evidence.setdefault(sink.capability, sink.location)

    # Sinks in code no entrypoint can reach. Not attributed to anyone, but not discarded
    # either — an unreferenced helper that opens a socket is worth a posture note.
    for scopes in all_scopes.values():
        for scope in scopes:
            if id(scope) in reachable_scopes:
                continue
            for sink in scope.sinks:
                if sink.capability not in behaviour.capabilities:
                    behaviour.unreachable_capabilities.add(sink.capability)
                    behaviour.unreachable_evidence.setdefault(sink.capability, sink.location)

    return behaviour
