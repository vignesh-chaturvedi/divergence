"""The shared vocabulary.

Two things live here, and they are the interfaces every other component speaks through.

`Capability` is the normalised capability set. A2 derives it from declarations, A4 will
derive it from source, and A8 will derive it from a syscall trace. Because all three
produce the same type, the divergence engine compares them without special-casing where
any given set came from.

`Finding`, `Channel` and `AttackClass` are the output vocabulary. They live in core
rather than in the benchmark because they are what the scanner produces; the benchmark
merely scores them.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass


class Capability(enum.StrEnum):
    """What an artifact can reach for.

    Deliberately coarse. Finer distinctions (which path, which host) belong in a
    finding's evidence, not in the vocabulary — keeping this set small is what lets a
    declaration, a parse and a syscall trace all map onto it.
    """

    FS_READ = "fs_read"
    FS_WRITE = "fs_write"
    FS_DELETE = "fs_delete"
    NET_OUTBOUND = "net_outbound"
    NET_LISTEN = "net_listen"
    PROC_SPAWN = "proc_spawn"
    ENV_READ = "env_read"
    SECRETS_READ = "secrets_read"
    DYNAMIC_EVAL = "dynamic_eval"


ALL_CAPABILITIES = frozenset(Capability)

# Capabilities that mutate state. `readOnlyHint: true` is a claim that none of these
# are reachable, which is what makes the annotation checkable rather than decorative.
MUTATING = frozenset({Capability.FS_WRITE, Capability.FS_DELETE, Capability.PROC_SPAWN})

# What each agent tool grants, in capability terms. The mapping is intentionally
# generous: over-granting produces a missed finding, under-granting produces a false
# positive on an honest declaration, and this project's whole thesis is that the second
# error is the expensive one.
_TOOL_CAPABILITIES: dict[str, frozenset[Capability]] = {
    "read": frozenset({Capability.FS_READ}),
    "glob": frozenset({Capability.FS_READ}),
    "grep": frozenset({Capability.FS_READ}),
    "write": frozenset({Capability.FS_WRITE}),
    "edit": frozenset({Capability.FS_READ, Capability.FS_WRITE}),
    "notebookedit": frozenset({Capability.FS_READ, Capability.FS_WRITE}),
    "webfetch": frozenset({Capability.NET_OUTBOUND}),
    "websearch": frozenset({Capability.NET_OUTBOUND}),
    # A shell is unbounded by definition. Anything less would flag honest declarations.
    "bash": ALL_CAPABILITIES,
    "task": ALL_CAPABILITIES,
}

_WILDCARDS = {"*", '"*"', "'*'", "all", "any"}


def allowed_tool_entries(declaration: str | None) -> tuple[str, ...]:
    """Parse the comma- or whitespace-separated forms used by skill frontmatter."""
    if declaration is None:
        return ()
    return tuple(
        token.strip().strip("\"'")
        for token in re.split(r"[\s,]+", declaration)
        if token.strip().strip("\"'")
    )


def unknown_allowed_tools(declaration: str | None) -> tuple[str, ...]:
    return tuple(
        entry
        for entry in allowed_tool_entries(declaration)
        if entry.lower() not in _TOOL_CAPABILITIES and entry.lower() not in _WILDCARDS
    )


def capabilities_for_allowed_tools(declaration: str | None) -> set[Capability]:
    """Normalise an `allowed-tools` declaration into a capability set.

    Absence and a wildcard both mean *unrestricted*, not *nothing*. Getting this
    backwards would make every skill without an explicit declaration appear to exceed
    its permissions — a false-positive stratum all on its own.
    """
    if declaration is None:
        return set(ALL_CAPABILITIES)

    entries = list(allowed_tool_entries(declaration))

    if not entries or any(e.lower() in _WILDCARDS for e in entries):
        return set(ALL_CAPABILITIES)

    # A namespaced or future tool has semantics this version cannot map.  Treating it as
    # granting nothing manufactures a permission contradiction; precision-first means the
    # unknown grant is conservatively unrestricted and surfaced separately as posture.
    if unknown_allowed_tools(declaration):
        return set(ALL_CAPABILITIES)

    granted: set[Capability] = set()
    for entry in entries:
        granted |= _TOOL_CAPABILITIES.get(entry.lower(), frozenset())
    return granted


def declaration_is_wildcard(declaration: str | None) -> bool:
    """True when a declaration imposes no restriction.

    Callers use this to route to the posture channel. §03 is explicit: a wildcard is a
    least-privilege observation, never evidence of malice, and thousands of benign
    published skills declare one.
    """
    if declaration is None:
        return True
    entries = [e.lower() for e in allowed_tool_entries(declaration)]
    return not any(entries) or any(e in _WILDCARDS for e in entries)


class Channel(enum.StrEnum):
    """The two output channels that must never be mixed.

    POSTURE describes what an artifact *can* do — high blast radius, broad filesystem
    access, wildcard permissions. Useful, non-urgent, and fires on benign and malicious
    artifacts alike.

    RISK describes divergence — a claim the artifact contradicts. Only RISK findings
    count toward a verdict.
    """

    POSTURE = "posture"
    RISK = "risk"


class AttackClass(enum.StrEnum):
    """The published taxonomy, plus the classes that only exist for skills."""

    DESCRIPTION_POISONING = "description_poisoning"
    SCHEMA_POISONING = "schema_poisoning"
    RETURN_VALUE_INJECTION = "return_value_injection"
    SHADOWING = "shadowing"
    PREFERENCE_MANIPULATION = "preference_manipulation"
    POST_APPROVAL_MUTATION = "post_approval_mutation"
    TYPOSQUAT = "typosquat"
    ANNOTATION_LIE = "annotation_lie"
    UNDECLARED_NETWORK = "undeclared_network"
    UNDECLARED_FILESYSTEM = "undeclared_filesystem"
    UNDECLARED_SECRETS = "undeclared_secrets"
    UNDECLARED_EXEC = "undeclared_exec"
    CROSS_TOOL_INSTRUCTION = "cross_tool_instruction"
    DYNAMIC_CODE_LOADING = "dynamic_code_loading"

    TRIGGER_SCOPE_HIJACK = "trigger_scope_hijack"
    REMOTE_FETCH_AT_LOAD = "remote_fetch_at_load"
    SCRIPT_EXCEEDS_ALLOWED_TOOLS = "script_exceeds_allowed_tools"
    BUNDLED_BINARY_NO_SOURCE = "bundled_binary_no_source"
    PROGRESSIVE_DISCLOSURE_PAYLOAD = "progressive_disclosure_payload"


@dataclass(frozen=True, slots=True)
class Finding:
    """One normalised finding.

    §04: no finding ships without both halves of the contradiction attached — a
    `file:line` for the behaviour and the exact claim it contradicts. `evidence` and
    `claim` carry those halves, and the CLI refuses to promote a risk finding that is
    missing either.
    """

    sample_id: str
    channel: Channel
    attack_class: AttackClass | None = None
    severity: str = "unknown"
    message: str = ""
    evidence: str = ""
    claim: str = ""
    confidence: float = 1.0

    @property
    def counts_toward_verdict(self) -> bool:
        """Posture findings never decide a verdict. This is the whole thesis."""
        return self.channel is Channel.RISK

    @property
    def is_evidence_bound(self) -> bool:
        """A risk finding must carry both halves of the contradiction to be reviewable."""
        return bool(self.evidence) and bool(self.claim)
