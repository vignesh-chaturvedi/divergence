"""A3 — the manifest ledger.

Canonicalise and hash every tool definition and skill bundle at first approval. On
rescan, diff and classify what changed.

This exists because post-approval mutation is the attack MCP's design makes easy and
that no single-snapshot scanner can catch: at every individual moment the artifact is
internally consistent. The finding is not in any one version, it is in the transition.

Classification, in ascending severity:

- **cosmetic** — wording moved, no new reach and no reversal of meaning.
- **capability-expanding** — new parameters, new sinks, new bundled files. The version
  that was approved could not do this.
- **semantics-inverting** — an annotation flipped, or a description now says materially
  the opposite. The strongest signal, because it means the approved promise was retracted
  without the name or the interface changing.
"""

from __future__ import annotations

import enum
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from divergence.core.acquire import Artifact
from divergence.core.behaviour import extract
from divergence.core.vocabulary import (
    AttackClass,
    Capability,
    Channel,
    Finding,
)


class ChangeKind(enum.IntEnum):
    """Ordered so that `max()` over a set of changes yields the verdict-driving one."""

    COSMETIC = 1
    CAPABILITY_EXPANDING = 2
    SEMANTICS_INVERTING = 3


# Annotations are machine-readable promises. Flipping one from restrictive to permissive
# after approval reverses the promise without touching the interface.
_PERMISSIVE_FLIP = {
    "readOnlyHint": (True, False),
    "destructiveHint": (False, True),
    "openWorldHint": (False, True),
}


@dataclass(frozen=True, slots=True)
class Change:
    kind: ChangeKind
    detail: str
    evidence: str = ""


def _canonical(artifact: Artifact, capabilities: set[Capability]) -> dict:
    """A stable, order-independent representation of everything worth hashing.

    Sorting is load-bearing: a registry that returns tools in a different order must not
    read as a mutation, or the ledger cries wolf on every rescan and gets ignored.
    """
    return {
        "kind": artifact.kind,
        "tools": sorted(
            (
                {
                    "name": t.name,
                    "description": " ".join(t.description.split()),
                    "annotations": dict(sorted(t.annotations.items())),
                    "properties": sorted(t.schema_properties),
                    "required": sorted(t.required),
                }
                for t in artifact.tools
            ),
            key=lambda d: d["name"],
        ),
        "skill": (
            {
                "name": artifact.skill.name,
                "description": " ".join(artifact.skill.description.split()),
                "allowed_tools": artifact.skill.allowed_tools,
                "body": " ".join(artifact.skill.body.split()),
            }
            if artifact.skill
            else None
        ),
        "bundle": sorted(
            f"{p.name}:{hashlib.sha256(p.read_bytes()).hexdigest()[:16]}"
            for p in artifact.bundle_files
            if p.is_file()
        ),
        "capabilities": sorted(c.value for c in capabilities),
    }


def _classify(before: dict, after: dict) -> list[Change]:
    """Diff two canonical records into ordered changes."""
    changes: list[Change] = []

    old_caps = set(before.get("capabilities") or [])
    new_caps = set(after.get("capabilities") or [])
    gained = new_caps - old_caps
    if gained:
        changes.append(
            Change(
                ChangeKind.CAPABILITY_EXPANDING,
                f"gained capability: {', '.join(sorted(gained))}",
                evidence=f"capabilities {sorted(old_caps)} -> {sorted(new_caps)}",
            )
        )

    old_tools = {t["name"]: t for t in before.get("tools") or []}
    new_tools = {t["name"]: t for t in after.get("tools") or []}

    for name, new in new_tools.items():
        old = old_tools.get(name)
        if old is None:
            changes.append(
                Change(ChangeKind.CAPABILITY_EXPANDING, f"new tool {name!r}", evidence=name)
            )
            continue

        added_params = set(new["properties"]) - set(old["properties"])
        if added_params:
            changes.append(
                Change(
                    ChangeKind.CAPABILITY_EXPANDING,
                    f"tool {name!r} gained parameter(s): {', '.join(sorted(added_params))}",
                    evidence=f"{name}.inputSchema",
                )
            )

        for hint, (restrictive, permissive) in _PERMISSIVE_FLIP.items():
            if old["annotations"].get(hint) == restrictive and new["annotations"].get(hint) == permissive:
                changes.append(
                    Change(
                        ChangeKind.SEMANTICS_INVERTING,
                        f"tool {name!r} flipped {hint} from {restrictive} to {permissive}",
                        evidence=f"{name}.annotations.{hint}",
                    )
                )

        if old["description"] != new["description"]:
            changes.append(
                Change(
                    ChangeKind.COSMETIC,
                    f"tool {name!r} description reworded",
                    evidence=f"{name}.description",
                )
            )

    old_skill, new_skill = before.get("skill"), after.get("skill")
    if old_skill and new_skill:
        if old_skill["allowed_tools"] != new_skill["allowed_tools"]:
            changes.append(
                Change(
                    ChangeKind.SEMANTICS_INVERTING,
                    f"allowed-tools changed: {old_skill['allowed_tools']!r} -> "
                    f"{new_skill['allowed_tools']!r}",
                    evidence="SKILL.md: allowed-tools",
                )
            )
        if old_skill["body"] != new_skill["body"]:
            changes.append(
                Change(ChangeKind.COSMETIC, "skill body reworded", evidence="SKILL.md")
            )

    old_bundle = {b.split(":", 1)[0]: b for b in before.get("bundle") or []}
    new_bundle = {b.split(":", 1)[0]: b for b in after.get("bundle") or []}

    for name, digest in new_bundle.items():
        if name not in old_bundle:
            changes.append(
                Change(
                    ChangeKind.CAPABILITY_EXPANDING,
                    f"new bundled file {name!r}",
                    evidence=name,
                )
            )
        elif old_bundle[name] != digest:
            # Content changed. Severity is decided by whether capability grew, which the
            # capability comparison above has already recorded if it did.
            changes.append(
                Change(ChangeKind.COSMETIC, f"bundled file {name!r} changed", evidence=name)
            )

    return changes


class Ledger:
    """SQLite-backed record of what each artifact looked like when it was approved."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def _init_schema(self) -> None:
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    artifact_id TEXT PRIMARY KEY,
                    fingerprint TEXT NOT NULL,
                    canonical   TEXT NOT NULL,
                    recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

    # --- hashing -------------------------------------------------------------------

    def canonical(self, artifact: Artifact, capabilities: set[Capability] | None = None) -> dict:
        caps = extract(artifact.root).capabilities if capabilities is None else capabilities
        return _canonical(artifact, caps)

    def fingerprint(self, artifact: Artifact, capabilities: set[Capability] | None = None) -> str:
        blob = json.dumps(self.canonical(artifact, capabilities), sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    # --- the two operations --------------------------------------------------------

    def record(
        self,
        artifact: Artifact,
        *,
        artifact_id: str,
        observed_capabilities: set[Capability] | None = None,
    ) -> list[Finding]:
        """Approve an artifact at its current state. Never itself a finding."""
        canonical = self.canonical(artifact, observed_capabilities)
        blob = json.dumps(canonical, sort_keys=True)
        digest = hashlib.sha256(blob.encode()).hexdigest()

        with self._connect() as con:
            con.execute(
                "INSERT OR REPLACE INTO approvals (artifact_id, fingerprint, canonical) "
                "VALUES (?, ?, ?)",
                (artifact_id, digest, blob),
            )
        return []

    def diff(
        self,
        artifact: Artifact,
        *,
        artifact_id: str,
        observed_capabilities: set[Capability] | None = None,
    ) -> list[Finding]:
        """Compare an artifact against its approved state.

        An artifact with no prior approval yields nothing — there is no baseline to
        diverge from, and inventing one would flag every first scan.
        """
        with self._connect() as con:
            row = con.execute(
                "SELECT canonical FROM approvals WHERE artifact_id = ?", (artifact_id,)
            ).fetchone()

        if row is None:
            return []

        before = json.loads(row[0])
        after = self.canonical(artifact, observed_capabilities)

        changes = _classify(before, after)
        if not changes:
            return []

        worst = max(c.kind for c in changes)
        detail = "; ".join(c.detail for c in changes[:4])
        evidence = next((c.evidence for c in changes if c.kind is worst), "")

        if worst is ChangeKind.COSMETIC:
            return [
                Finding(
                    sample_id=artifact_id,
                    channel=Channel.POSTURE,
                    severity="info",
                    message=f"artifact changed since approval (cosmetic): {detail}",
                    evidence=evidence,
                    claim="ledger: no new capability, no reversed promise",
                )
            ]

        severity = "critical" if worst is ChangeKind.SEMANTICS_INVERTING else "high"
        return [
            Finding(
                sample_id=artifact_id,
                channel=Channel.RISK,
                attack_class=AttackClass.POST_APPROVAL_MUTATION,
                severity=severity,
                message=f"artifact mutated after approval ({worst.name.lower()}): {detail}",
                evidence=evidence,
                claim=f"ledger: approved fingerprint recorded for {artifact_id!r}",
            )
        ]
