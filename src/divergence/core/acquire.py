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
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MANIFEST_NAMES = ("manifest.json", "tools.json")
SKILL_FILE = "SKILL.md"
SNAPSHOT_DIR = "snapshots"

SOURCE_SUFFIXES = {".py", ".ts", ".js", ".tsx", ".mjs", ".sh", ".bash"}
TEXT_SUFFIXES = SOURCE_SUFFIXES | {".md", ".json", ".yaml", ".yml", ".toml", ".txt"}
_MAX_METADATA_BYTES = 2_000_000
_MAX_BUNDLE_FILES = 10_000
_IGNORED_DIRS = {".git", ".hg", ".svn"}

# Registry facts are trusted only when the acquisition layer itself obtained them.  This
# process-local map lets ``pipeline.load()`` reacquire a remotely downloaded directory
# without turning a package-controlled sidecar into a trust oracle.
_TRUSTED_REGISTRY: dict[Path, dict[str, Any]] = {}

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
    diagnostics: tuple[str, ...] = ()

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

    @property
    def complete(self) -> bool:
        """Whether acquisition covered every input it intended to inspect."""
        return not self.diagnostics


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
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
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
    substantive = tuple(
        token
        for token in re.split(r"[-_./@]+", name.lower())
        if token and token not in {"mcp", "server", "modelcontextprotocol"}
    )
    for popular in POPULAR_NAMES:
        for candidate in (popular, popular.rsplit("/", 1)[-1]):
            d = _levenshtein(name.lower(), candidate.lower())
            candidate_substantive = tuple(
                token
                for token in re.split(r"[-_./@]+", candidate.lower())
                if token and token not in {"mcp", "server", "modelcontextprotocol"}
            )
            # Registry ecosystems permit several wrapper conventions.  A different
            # package name with exactly the same substantive token(s) is a near-miss even
            # when raw edit distance is large (``filesystem-mcp-server`` versus
            # ``mcp-server-filesystem``).
            if (
                substantive
                and substantive == candidate_substantive
                and name.lower() != candidate.lower()
            ):
                d = 1
            if best_distance is None or d < best_distance:
                best_name, best_distance = popular, d

    # 0 means it *is* the popular package. Above 3 it is simply a different name.
    if best_distance is None or best_distance == 0 or best_distance > 3:
        return "", None
    return best_name, best_distance


def _bounded_text(path: Path, limit: int = _MAX_METADATA_BYTES) -> tuple[str, str]:
    """Read at most ``limit`` bytes and report truncation/decoding explicitly."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(limit + 1)
    except OSError as exc:
        return "", f"could not read {path.name}: {exc}"
    if len(raw) > limit:
        return "", f"skipped oversized metadata file {path.name} (> {limit} bytes)"
    try:
        return raw.decode("utf-8"), ""
    except UnicodeDecodeError:
        return "", f"could not decode {path.name} as UTF-8"


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    text, error = _bounded_text(path)
    if error:
        return {}, error
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return {}, f"malformed JSON in {path.name}: {exc.msg} at line {exc.lineno}"
    if not isinstance(data, dict):
        return {}, f"malformed {path.name}: top level must be an object"
    return data, ""


def walk_bundle(
    root: Path, *, include_snapshots: bool = False
) -> tuple[tuple[Path, ...], tuple[str, ...]]:
    """Walk a bundle without following links or special files.

    ``Path.rglob`` follows directory links on some platforms and offers no total-file
    bound.  Both properties are attacker-controlled for a package being inspected.
    """
    root = Path(root)
    files: list[Path] = []
    diagnostics: list[str] = []
    pending = [root]

    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            diagnostics.append(f"could not enumerate {directory}: {exc}")
            continue

        for entry in entries:
            path = Path(entry.path)
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                diagnostics.append(f"could not inspect {path}: {exc}")
                continue

            rel_parts = path.relative_to(root).parts
            if stat.S_ISLNK(mode):
                diagnostics.append(f"skipped symbolic link {path.relative_to(root)}")
                continue
            if stat.S_ISDIR(mode):
                if entry.name in _IGNORED_DIRS:
                    continue
                if not include_snapshots and SNAPSHOT_DIR in rel_parts:
                    continue
                pending.append(path)
                continue
            if not stat.S_ISREG(mode):
                diagnostics.append(f"skipped special file {path.relative_to(root)}")
                continue
            if not include_snapshots and SNAPSHOT_DIR in rel_parts:
                continue
            files.append(path)
            if len(files) >= _MAX_BUNDLE_FILES:
                diagnostics.append(
                    f"bundle file limit reached ({_MAX_BUNDLE_FILES}); analysis is partial"
                )
                return tuple(sorted(files)), tuple(diagnostics)

    return tuple(sorted(files)), tuple(diagnostics)


def _tools_from_manifest(root: Path, diagnostics: list[str]) -> list[ToolDecl]:
    for name in MANIFEST_NAMES:
        manifest = root / name
        if not manifest.is_file():
            continue
        data, error = _read_json(manifest)
        if error:
            diagnostics.append(error)
            continue
        raw_tools = data.get("tools", [])
        if not isinstance(raw_tools, list):
            diagnostics.append(f"malformed {name}: tools must be an array")
            continue
        tools = []
        for index, entry in enumerate(raw_tools):
            if not isinstance(entry, dict):
                diagnostics.append(f"malformed {name}: tools[{index}] must be an object")
                continue
            schema = entry.get("inputSchema") or {}
            if not isinstance(schema, dict):
                diagnostics.append(
                    f"malformed {name}: tools[{index}].inputSchema must be an object"
                )
                schema = {}
            annotations = entry.get("annotations") or {}
            properties = schema.get("properties") or {}
            required = schema.get("required") or []
            if not isinstance(annotations, dict) or not isinstance(properties, dict):
                diagnostics.append(f"malformed {name}: tools[{index}] contains invalid mappings")
                annotations = annotations if isinstance(annotations, dict) else {}
                properties = properties if isinstance(properties, dict) else {}
            if not isinstance(required, list):
                diagnostics.append(f"malformed {name}: tools[{index}].required must be an array")
                required = []
            tool_name = entry.get("name")
            if not isinstance(tool_name, str) or not tool_name.strip():
                diagnostics.append(f"malformed {name}: tools[{index}] has no valid name")
                continue
            tools.append(
                ToolDecl(
                    name=tool_name,
                    description=str(entry.get("description", "")),
                    annotations=dict(annotations),
                    schema_properties=dict(properties),
                    required=tuple(str(item) for item in required),
                    source_ref=f"{name}",
                )
            )
        if tools:
            return tools
    return []


def _tools_from_python(path: Path, diagnostics: list[str]) -> list[ToolDecl]:
    """Find `@mcp.tool()`-decorated functions and lift their docstrings.

    Parsing, never importing — an MCP server's module body runs arbitrary code at import
    time, so `ast` is the only safe way to read a registration.
    """
    try:
        text, error = _bounded_text(path)
        if error:
            diagnostics.append(error)
            return []
        tree = ast.parse(text)
    except SyntaxError as exc:
        diagnostics.append(f"could not parse {path.name}: line {exc.lineno}")
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


def _tools_from_typescript(path: Path, diagnostics: list[str]) -> list[ToolDecl]:
    """Lexical extraction of tool literals. Superseded by tree-sitter in P2."""
    try:
        text, error = _bounded_text(path)
    except OSError:
        return []
    if error:
        diagnostics.append(error)
        return []
    return [
        ToolDecl(name=m.group(1), description=m.group(2), source_ref=f"{path.name}")
        for m in _TS_TOOL_RE.finditer(text)
    ]


def _tools_from_source(
    root: Path, files: tuple[Path, ...], diagnostics: list[str]
) -> list[ToolDecl]:
    tools: list[ToolDecl] = []
    for path in files:
        if path.suffix == ".py":
            tools.extend(_tools_from_python(path, diagnostics))
        elif path.suffix in (".ts", ".js", ".mjs", ".tsx"):
            tools.extend(_tools_from_typescript(path, diagnostics))
    return tools


def _merge_tools(manifest: list[ToolDecl], source: list[ToolDecl]) -> list[ToolDecl]:
    """Reconcile both declared surfaces; neither is allowed to mask the other."""
    merged: dict[str, ToolDecl] = {tool.name: tool for tool in manifest}
    for candidate in source:
        current = merged.get(candidate.name)
        if current is None:
            merged[candidate.name] = candidate
            continue
        descriptions = list(
            dict.fromkeys(
                text for text in (current.description, candidate.description) if text.strip()
            )
        )
        merged[candidate.name] = ToolDecl(
            name=current.name,
            description="\n".join(descriptions),
            annotations=current.annotations,
            schema_properties={**candidate.schema_properties, **current.schema_properties},
            required=current.required or candidate.required,
            source_ref=f"{current.source_ref}; {candidate.source_ref}",
        )
    return [merged[name] for name in sorted(merged)]


def _parse_skill(path: Path, diagnostics: list[str]) -> SkillDecl | None:
    text, error = _bounded_text(path)
    if error:
        diagnostics.append(error)
        return None

    match = _FRONTMATTER_RE.match(text)
    if not match:
        return SkillDecl(name=path.parent.name, body=text, source_ref=path.name)

    raw, body = match.group(1), match.group(2)
    try:
        meta = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        diagnostics.append(
            f"malformed YAML in {path.name}: {getattr(exc, 'problem', None) or 'parse error'}"
        )
        meta = {}
    if not isinstance(meta, dict):
        diagnostics.append(f"malformed {path.name}: frontmatter must be a mapping")
        meta = {}

    allowed = meta.get("allowed-tools", meta.get("allowed_tools"))

    # Frontmatter is YAML, so `allowed-tools` may arrive as a list — either inline
    # (`[Read, Grep]`) or as a block sequence. `str()` on a list yields "['Read', 'Grep']",
    # which matches no known tool and grants nothing, so a skill written in that entirely
    # valid style was flagged for exceeding a permission it had been given. Normalise to
    # the comma form the capability mapper expects.
    if isinstance(allowed, (list, tuple)):
        allowed = ", ".join(str(item) for item in allowed)

    return SkillDecl(
        name=str(meta.get("name", path.parent.name)),
        description=str(meta.get("description", "")),
        allowed_tools=None if allowed is None else str(allowed),
        body=body,
        source_ref=path.name,
    )


def register_trusted_provenance(root: Path, metadata: dict[str, Any]) -> None:
    """Remember registry metadata obtained by an explicit remote acquisition."""
    _TRUSTED_REGISTRY[Path(root).resolve()] = dict(metadata)


def _provenance(
    root: Path,
    registry_metadata: dict[str, Any] | None = None,
    diagnostics: list[str] | None = None,
) -> Provenance:
    pkg, package_error = (
        _read_json(root / "package.json") if (root / "package.json").is_file() else ({}, "")
    )
    if package_error and diagnostics is not None:
        diagnostics.append(package_error)
    reg = registry_metadata or _TRUSTED_REGISTRY.get(root.resolve(), {})

    name = str(reg.get("name") or pkg.get("name", ""))
    version = str(reg.get("version") or pkg.get("version", ""))
    author = str(reg.get("author") or pkg.get("author", ""))
    nearest, distance = _nearest_popular(name)

    # Only an acquisition-supplied registry response may override local package data.
    if reg.get("nearest_popular_name"):
        nearest = str(reg["nearest_popular_name"])
        distance = reg.get("edit_distance", distance)

    return Provenance(
        name=name,
        version=version,
        author=author,
        signed=reg.get("signed"),
        first_published=str(reg.get("first_published", "")),
        downloads_30d=reg.get("downloads_30d"),
        nearest_popular_name=nearest,
        typosquat_distance=distance,
    )


def _snapshots(root: Path) -> list[Snapshot]:
    snap_root = root / SNAPSHOT_DIR
    if not snap_root.is_dir():
        return []
    return [
        Snapshot(label=d.name, root=d)
        for d in sorted(snap_root.iterdir())
        if d.is_dir() and not d.is_symlink()
    ]


def detect_kind(root: Path, files: tuple[Path, ...] | None = None) -> str:
    """A skill announces itself with SKILL.md; anything else declaring tools is a server."""
    files = files if files is not None else walk_bundle(root)[0]
    if any(path.name == SKILL_FILE for path in files):
        return "agent_skill"
    return "mcp_server"


def acquire(
    root: Path,
    *,
    use_manifest: bool = True,
    registry_metadata: dict[str, Any] | None = None,
) -> Artifact:
    """Resolve a target directory into its declared surface. Executes nothing.

    `use_manifest=False` forces the source parser, which is how the fallback ordering
    gets tested: a manifest is convenient but a static parse of the registration calls
    is what must work when there is no manifest to trust.
    """
    root = Path(root).resolve()
    files, walk_diagnostics = walk_bundle(root)
    diagnostics = list(walk_diagnostics)
    kind = detect_kind(root, files)

    tools: list[ToolDecl] = []
    if kind == "mcp_server":
        manifest = _tools_from_manifest(root, diagnostics) if use_manifest else []
        source = _tools_from_source(root, files, diagnostics)
        tools = _merge_tools(manifest, source) if use_manifest else source
        if not tools:
            diagnostics.append(
                "no statically declared tools found; live tools/list was not executed"
            )

    skill = None
    if kind == "agent_skill":
        skill_path = root / SKILL_FILE
        if not skill_path.is_file():
            candidates = sorted(path for path in files if path.name == SKILL_FILE)
            skill_path = candidates[0] if candidates else None
        if skill_path:
            skill = _parse_skill(skill_path, diagnostics)
        if skill is None:
            diagnostics.append("skill declaration could not be parsed")

    return Artifact(
        root=root,
        kind=kind,
        tools=tuple(tools),
        skill=skill,
        bundle_files=files,
        provenance=_provenance(root, registry_metadata, diagnostics),
        snapshots=tuple(_snapshots(root)),
        diagnostics=tuple(dict.fromkeys(diagnostics)),
    )
