"""A1 — target resolution.

Turns whatever the user points at into a list of artifacts to analyse.

P1 implements the offline sources: a directory, a skill bundle, and a local MCP client
config. The client config is the one that matters most in practice — "scan what I have
installed" is the product's actual entry point, and it is also the input the fleet
analyzers in P4 will need.

Remote specs (npm, PyPI, GitHub) raise rather than returning nothing. §10 makes
offline-by-default a feature: the configuration being asked about is itself sensitive,
so reaching the network is a decision the user makes explicitly, not a side effect of a
scan.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from divergence.core.acquire import Artifact, acquire

# Keys used by the MCP client configs in circulation.
_SERVER_KEYS = ("mcpServers", "servers", "mcp_servers")

_REMOTE_SPEC = re.compile(r"^(npm|pypi|npx|uvx|github|https?|git\+https?):", re.I)


class ResolutionError(Exception):
    """The target could not be turned into something analysable."""


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """One artifact to analyse, plus how we got to it."""

    name: str
    source: str
    artifact: Artifact | None = None
    unresolved_reason: str = ""

    @property
    def resolved(self) -> bool:
        return self.artifact is not None


def _artifact_root_for_command(entry: dict) -> Path | None:
    """Find a local directory for a configured server, if one exists.

    A config entry is a command line, not a path. When an argument points at a real file
    on disk, its directory is the artifact. When the command fetches from a registry at
    launch (`npx -y some-server`), there is nothing local to read and we say so instead
    of guessing.
    """
    for arg in entry.get("args") or []:
        candidate = Path(str(arg)).expanduser()
        if candidate.is_file():
            return candidate.parent
        if candidate.is_dir():
            return candidate

    cwd = entry.get("cwd")
    if cwd and Path(cwd).expanduser().is_dir():
        return Path(cwd).expanduser()

    return None


def _server_block(data: dict) -> dict:
    """The server map from a client config, whichever key this client happens to use."""
    for key in _SERVER_KEYS:
        if isinstance(data.get(key), dict):
            return data[key]
    return {}


def _resolve_client_config(path: Path, data: dict) -> list[ResolvedTarget]:
    servers = _server_block(data)
    if not servers:
        raise ResolutionError(
            f"{path}: no MCP server block found (looked for {', '.join(_SERVER_KEYS)})"
        )

    targets: list[ResolvedTarget] = []
    for name, entry in sorted(servers.items()):
        if not isinstance(entry, dict):
            continue

        root = _artifact_root_for_command(entry)
        if root is None:
            command = " ".join([str(entry.get("command", ""))] + [str(a) for a in entry.get("args") or []])
            targets.append(
                ResolvedTarget(
                    name=name,
                    source=str(path),
                    unresolved_reason=(
                        f"no local artifact for `{command.strip()}` — the server is fetched "
                        "at launch, which needs network acquisition (not in P1)"
                    ),
                )
            )
            continue

        targets.append(ResolvedTarget(name=name, source=str(path), artifact=acquire(root)))

    return targets


def _read_client_config(path: Path) -> dict | None:
    """Parse a client config once, or return None when this is not one.

    Parsed here and handed to the resolver rather than re-read: the file is the user's
    real configuration, and reading it twice is both wasteful and a chance for the two
    reads to disagree.
    """
    if path.suffix != ".json":
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, dict) and any(k in data for k in _SERVER_KEYS):
        return data
    return None


def resolve(target: str) -> list[ResolvedTarget]:
    """Resolve a target string into artifacts. Never executes anything it resolves."""
    if _REMOTE_SPEC.match(target):
        scheme = target.split(":", 1)[0]
        raise ResolutionError(
            f"remote target {target!r} requires network acquisition, which P1 does not "
            f"implement. Fetch the {scheme} package yourself and point at the directory."
        )

    path = Path(target).expanduser()
    if not path.exists():
        raise ResolutionError(f"{target}: no such file or directory")

    if path.is_file():
        config = _read_client_config(path)
        if config is not None:
            return _resolve_client_config(path, config)
        # A lone file — analyse the bundle it sits in.
        path = path.parent

    return [ResolvedTarget(name=path.name, source=str(path), artifact=acquire(path))]
