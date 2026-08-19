"""Core vocabulary of the benchmark.

Everything downstream — the loader, the metrics, every scanner adapter — speaks in
these types. Keeping them in one place is what lets a third-party scanner be scored
by the same code path as our own.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path


class Kind(enum.StrEnum):
    """What sort of artifact a sample is."""

    MCP_SERVER = "mcp_server"
    AGENT_SKILL = "agent_skill"


class Stratum(enum.StrEnum):
    """Which layer of the corpus a sample belongs to.

    The strata are not just bookkeeping — they define the metrics. Recall is measured
    over MALICIOUS, and the headline number, FPR-on-traps, is measured over FP_TRAP.
    """

    MALICIOUS = "malicious"
    FP_TRAP = "fp_trap"
    BENIGN_PLAIN = "benign_plain"
    OBFUSCATED = "obfuscated"

    @property
    def is_positive(self) -> bool:
        """True when a scanner *should* flag samples in this stratum."""
        return self in (Stratum.MALICIOUS, Stratum.OBFUSCATED)


class Channel(enum.StrEnum):
    """The two output channels that must never be mixed.

    POSTURE describes what an artifact *can* do — high blast radius, broad filesystem
    access, wildcard permissions. Useful, non-urgent, and fires on benign and malicious
    artifacts alike.

    RISK describes divergence — a claim the artifact contradicts. Only RISK findings
    count toward a verdict. Splitting these is what removes most of the false-positive
    rate before a single model runs.
    """

    POSTURE = "posture"
    RISK = "risk"


class AttackClass(enum.StrEnum):
    """The published taxonomy, plus the classes that only exist for skills.

    Used for per-class recall breakdowns: a scanner can score well overall while being
    structurally blind to one family, and that is worth seeing.
    """

    # Shared between servers and skills
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

    # Skill-specific — no MCP equivalent
    TRIGGER_SCOPE_HIJACK = "trigger_scope_hijack"
    REMOTE_FETCH_AT_LOAD = "remote_fetch_at_load"
    SCRIPT_EXCEEDS_ALLOWED_TOOLS = "script_exceeds_allowed_tools"
    BUNDLED_BINARY_NO_SOURCE = "bundled_binary_no_source"
    PROGRESSIVE_DISCLOSURE_PAYLOAD = "progressive_disclosure_payload"


class TrapFamily(enum.StrEnum):
    """Why a false-positive trap looks dangerous.

    This is the corpus's actual contribution, so the reason a trap is a trap is
    recorded as structured data rather than left to the rationale prose alone.
    """

    PRIVILEGED_BY_DESIGN = "privileged_by_design"
    IMPERATIVE_LANGUAGE = "imperative_language"
    WILDCARD_PERMISSIONS = "wildcard_permissions"
    SECURITY_DOMAIN_VOCABULARY = "security_domain_vocabulary"
    BROAD_BUT_HONEST_TRIGGER = "broad_but_honest_trigger"


@dataclass(frozen=True, slots=True)
class ExpectedFinding:
    """What a correct scanner ought to report for a sample.

    Recorded per sample so that a scanner can be scored on *why* it flagged something,
    not merely whether it did. A tool that flags a poisoned server for the wrong reason
    got the right answer by accident.
    """

    attack_class: AttackClass
    channel: Channel = Channel.RISK
    evidence_hint: str = ""


@dataclass(frozen=True, slots=True)
class Sample:
    """One labelled corpus artifact."""

    id: str
    kind: Kind
    stratum: Stratum
    language: str
    rationale: str
    path: Path
    artifact_path: Path
    attack_classes: tuple[AttackClass, ...] = ()
    trap_families: tuple[TrapFamily, ...] = ()
    expected: tuple[ExpectedFinding, ...] = ()
    tags: tuple[str, ...] = ()
    notes: str = ""

    @property
    def is_positive(self) -> bool:
        """True when a scanner is *supposed* to flag this sample."""
        return self.stratum.is_positive


@dataclass(frozen=True, slots=True)
class Finding:
    """A single normalised finding emitted by some scanner.

    Third-party scanners report wildly different shapes. An adapter's whole job is to
    collapse its tool's output into a list of these so the metrics never special-case.
    """

    sample_id: str
    channel: Channel
    attack_class: AttackClass | None = None
    severity: str = "unknown"
    message: str = ""
    evidence: str = ""

    @property
    def counts_toward_verdict(self) -> bool:
        """Posture findings never decide a verdict. This is the whole thesis."""
        return self.channel is Channel.RISK


@dataclass(frozen=True, slots=True)
class SampleResult:
    """One scanner's verdict on one sample."""

    sample_id: str
    findings: tuple[Finding, ...] = ()
    error: str | None = None
    duration_s: float = 0.0

    @property
    def flagged(self) -> bool:
        """A sample is flagged when at least one RISK finding lands on it."""
        return any(f.counts_toward_verdict for f in self.findings)

    @property
    def risk_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.counts_toward_verdict)

    @property
    def posture_findings(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if not f.counts_toward_verdict)


@dataclass
class ScanRun:
    """Everything one scanner produced over one corpus."""

    scanner: str
    version: str = "unknown"
    available: bool = True
    unavailable_reason: str = ""
    results: dict[str, SampleResult] = field(default_factory=dict)
    duration_s: float = 0.0

    def result_for(self, sample_id: str) -> SampleResult:
        return self.results.get(sample_id, SampleResult(sample_id=sample_id))
