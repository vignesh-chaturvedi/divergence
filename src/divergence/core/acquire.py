"""A1 — acquisition.

Resolve a target into its *declared surface* without executing it. Static parse of
tool-registration calls and skill frontmatter is primary; a sandboxed `tools/list` is a
fallback only, and is not implemented here because nothing in P1 executes anything.

For skills this walks the **full bundle** — scripts, resources, anything the frontmatter
does not mention. That gap is exactly where a supply-chain payload lives, so acquisition
that stops at frontmatter would hand the rest of the pipeline a blind spot it cannot
recover from.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

MANIFEST_NAMES = ("manifest.json", "tools.json")
SKILL_FILE = "SKILL.md"
SNAPSHOT_DIR = "snapshots"

SOURCE_SUFFIXES = {".py", ".ts", ".js", ".tsx", ".mjs", ".sh", ".bash"}
TEXT_SUFFIXES = SOURCE_SUFFIXES | {".md", ".json", ".yaml", ".yml", ".toml", ".txt"}

# Widely installed artifacts a typosquat would imitate. A real deployment reads this
# from a registry snapshot; keeping it inline keeps P1 offline and reproducible.
POPULAR_NAMES = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "mcp-server-git",
    "mcp-server-fetch",
    "server-filesystem",
    "server-github",
)

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?(.*)\Z", re.DOTALL)


@dataclass(frozen=True, slots=True)
class ToolDecl:
    """One tool's declared surface — the reasoning surface an agent receives verbatim."""

    name: str
    description: str = ""
    annotations: dict = field(default_factory=dict)
    schema_properties: dict = field(default_factory=dict)
    required: tuple[str, ...] = ()
    source_ref: str = ""

    def schema_text(self) -> str:
        """Every string in the schema, concatenated.

        Property descriptions are part of what the agent ingests and are where schema
        poisoning hides, so they must be searchable alongside the tool description.
        """
        return json.dumps(self.schema_properties)


@dataclass(frozen=True, slots=True)
class SkillDecl:
    """A skill's frontmatter plus body.

    `allowed_tools` is `None` when absent, which is not the same as an empty string —
    absence means unrestricted, and conflating the two invents false positives.
    """

    name: str
    description: str = ""
    allowed_tools: str | None = None
    body: str = ""
    source_ref: str = ""


@dataclass(frozen=True, slots=True)
class Provenance:
    """Publisher and registry facts. §04: the signal a typosquat leaves is here, not in source."""

    name: str = ""
    version: str = ""
    author: str = ""
    signed: bool | None = None
    first_published: str = ""
    downloads_30d: int | None = None
    nearest_popular_name: str = ""
    typosquat_distance: int | None = None


@dataclass(frozen=True, slots=True)
class Snapshot:
    """One version of an artifact, for ledger diffing."""

    label: str
    root: Path


@dataclass(frozen=True, slots=True)
class Artifact:
    """A resolved target: what it says it is, and every file it ships."""

    root: Path
    kind: str
    tools: tuple[ToolDecl, ...] = ()
    skill: SkillDecl | None = None
    bundle_files: tuple[Path, ...] = ()
    provenance: Provenance = field(default_factory=Provenance)
    snapshots: tuple[Snapshot, ...] = ()

    def tool(self, name: str) -> ToolDecl:
        for t in self.tools:
            if t.name == name:
                return t
        raise KeyError(f"no tool named {name!r} in {self.root}")

    @property
    def claim_text(self) -> str:
        """Everything the artifact says about itself, in one blob.

        This is the C surface — what a claim extractor will read in P3, and what the
        deterministic checks in P1 search for parameter names and instruction phrasing.
        """
        parts = [t.description for t in self.tools]
        parts += [t.schema_text() for t in self.tools]
        if self.skill:
            parts += [self.skill.description, self.skill.body]
        return "\n".join(parts)


def _levenshtein(a: str, b: str) -> int:
    """Edit distance, for typosquat proximity. Small inputs, so the simple DP is fine."""
    if a == b:
        return 0
    if not a or not b:
        return max(len(a), len(b))

    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(
                min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb))
            )
        previous = current
    return previous[-1]


def _nearest_popular(name: str) -> tuple[str, int] | tuple[str, None]:
    """Closest popular name and its distance, or no signal when the name is unremarkable.

    Only near-misses matter. An unrelated name is far from everything, and reporting
    that distance would be noise; an exact match is the real package, not a squat.
    """
    if not name:
        return "", None

    best_name, best_distance = "", None
    for popular in POPULAR_NAMES:
        for candidate in (popular, popular.rsplit("/", 1)[-1]):
            d = _levenshtein(name.lower(), candidate.lower())
            if best_distance is None or d < best_distance:
                best_name, best_distance = popular, d

    # 0 means it *is* the popular package. Above 3 it is simply a different name.
    if best_distance is None or best_distance == 0 or best_distance > 3:
        return "", None
    return best_name, best_distance


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _tools_from_manifest(root: Path) -> list[ToolDecl]:
    for name in MANIFEST_NAMES:
        manifest = root / name
        if not manifest.is_file():
            continue
        data = _read_json(manifest)
        tools = []
        for entry in data.get("tools", []):
            schema = entry.get("inputSchema") or {}
            tools.append(
                ToolDecl(
                    name=str(entry.get("name", "")),
                    description=str(entry.get("description", "")),
                    annotations=dict(entry.get("annotations") or {}),
                    schema_properties=dict(schema.get("properties") or {}),
                    required=tuple(schema.get("required") or []),
                    source_ref=f"{name}",
                )
            )
        if tools:
            return tools
    return []


def _tools_from_python(path: Path) -> list[ToolDecl]:
    """Find `@mcp.tool()`-decorated functions and lift their docstrings.

    Parsing, never importing — an MCP server's module body runs arbitrary code at import
    time, so `ast` is the only safe way to read a registration.
    """
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError):
        return []

    tools = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        decorated = False
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(target, ast.Attribute) and target.attr == "tool":
                decorated = True
        if not decorated:
            continue

        tools.append(
            ToolDecl(
                name=node.name,
                description=(ast.get_docstring(node) or "").strip(),
                schema_properties={
                    a.arg: {"type": "unknown"}
                    for a in node.args.args
                    if a.arg not in ("self", "cls")
                },
                source_ref=f"{path.name}:{node.lineno}",
            )
        )
    return tools


_TS_TOOL_RE = re.compile(
    r"""name\s*[:=]\s*["']([a-zA-Z_][\w-]*)["']\s*,\s*description\s*[:=]\s*["`']([^"`']*)""",
)


def _tools_from_typescript(path: Path) -> list[ToolDecl]:
    """Lexical extraction of tool literals. Superseded by tree-sitter in P2."""
    try:
        text = path.read_text()
    except OSError:
        return []
    return [
        ToolDecl(name=m.group(1), description=m.group(2), source_ref=f"{path.name}")
        for m in _TS_TOOL_RE.finditer(text)
    ]


def _tools_from_source(root: Path) -> list[ToolDecl]:
    tools: list[ToolDecl] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or SNAPSHOT_DIR in path.relative_to(root).parts:
            continue
        if path.suffix == ".py":
            tools.extend(_tools_from_python(path))
        elif path.suffix in (".ts", ".js", ".mjs", ".tsx"):
            tools.extend(_tools_from_typescript(path))
    return tools


def _parse_skill(path: Path) -> SkillDecl | None:
    try:
        text = path.read_text()
    except OSError:
        return None

    match = _FRONTMATTER_RE.match(text)
    if not match:
        return SkillDecl(name=path.parent.name, body=text, source_ref=path.name)

    raw, body = match.group(1), match.group(2)
    try:
        meta = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        meta = {}
    if not isinstance(meta, dict):
        meta = {}

    allowed = meta.get("allowed-tools", meta.get("allowed_tools"))
    return SkillDecl(
        name=str(meta.get("name", path.parent.name)),
        description=str(meta.get("description", "")),
        allowed_tools=None if allowed is None else str(allowed),
        body=body,
        source_ref=path.name,
    )


def _provenance(root: Path) -> Provenance:
    pkg = _read_json(root / "package.json")
    reg = _read_json(root / "registry.json")

    name = str(pkg.get("name", ""))
    nearest, distance = _nearest_popular(name)

    # An explicit registry record wins over our own computation — it is the ground truth
    # a real acquisition would fetch from the registry API.
    if reg.get("nearest_popular_name"):
        nearest = str(reg["nearest_popular_name"])
        distance = reg.get("edit_distance", distance)

    return Provenance(
        name=name,
        version=str(pkg.get("version", "")),
        author=str(pkg.get("author", "")),
        signed=reg.get("signed"),
        first_published=str(reg.get("first_published", "")),
        downloads_30d=reg.get("downloads_30d"),
        nearest_popular_name=nearest,
        typosquat_distance=distance,
    )


def _bundle_files(root: Path) -> list[Path]:
    """Every file in the bundle, snapshots excluded — they are separate artifacts."""
    # Relative parts, not absolute — a snapshot's own root lives under snapshots/.
    return [
        p
        for p in sorted(root.rglob("*"))
        if p.is_file() and SNAPSHOT_DIR not in p.relative_to(root).parts
    ]


def _snapshots(root: Path) -> list[Snapshot]:
    snap_root = root / SNAPSHOT_DIR
    if not snap_root.is_dir():
        return []
    return [Snapshot(label=d.name, root=d) for d in sorted(snap_root.iterdir()) if d.is_dir()]


def detect_kind(root: Path) -> str:
    """A skill announces itself with SKILL.md; anything else declaring tools is a server."""
    if (root / SKILL_FILE).is_file() or any(root.rglob(SKILL_FILE)):
        return "agent_skill"
    return "mcp_server"


def acquire(root: Path, *, use_manifest: bool = True) -> Artifact:
    """Resolve a target directory into its declared surface. Executes nothing.

    `use_manifest=False` forces the source parser, which is how the fallback ordering
    gets tested: a manifest is convenient but a static parse of the registration calls
    is what must work when there is no manifest to trust.
    """
    root = Path(root)
    kind = detect_kind(root)

    tools: list[ToolDecl] = []
    if kind == "mcp_server":
        tools = _tools_from_manifest(root) if use_manifest else []
        if not tools:
            tools = _tools_from_source(root)

    skill = None
    if kind == "agent_skill":
        skill_path = root / SKILL_FILE
        if not skill_path.is_file():
            candidates = sorted(root.rglob(SKILL_FILE))
            skill_path = candidates[0] if candidates else None
        if skill_path:
            skill = _parse_skill(skill_path)

    return Artifact(
        root=root,
        kind=kind,
        tools=tuple(tools),
        skill=skill,
        bundle_files=tuple(_bundle_files(root)),
        provenance=_provenance(root),
        snapshots=tuple(_snapshots(root)),
    )
