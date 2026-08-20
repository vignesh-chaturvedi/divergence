"""Core vocabulary of the benchmark.

Everything downstream — the loader, the metrics, every scanner adapter — speaks in
these types. Keeping them in one place is what lets a third-party scanner be scored
by the same code path as our own.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path

# Channel, AttackClass and Finding are core scanner vocabulary, not benchmark concepts.
# They are re-exported here so existing importers keep working.
from divergence.core.vocabulary import AttackClass, Capability, Channel, Finding

__all__ = [
    "AttackClass", "Capability", "Channel", "Finding", "Kind", "Stratum", "TrapFamily",
    "ExpectedFinding", "Sample", "SampleResult", "ScanRun",
]


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

    # Hand-verified B_s ground truth. `None` means the sample has not been verified,
    # which is different from "verified as having no capabilities" (an empty tuple).
    verified_capabilities: tuple[Capability, ...] | None = None
    capability_miss_reason: str = ""
    evasion: str = ""  # obfuscated stratum: how the payload hides from static analysis

    @property
    def is_positive(self) -> bool:
        """True when a scanner is *supposed* to flag this sample."""
        return self.stratum.is_positive


@dataclass(frozen=True, slots=True)
class SampleResult:
    """One scanner's verdict on one sample."""

    sample_id: str
    findings: tuple[Finding, ...] = ()
    error: str | None = None
    duration_s: float = 0.0

    # Some scanners structurally cannot analyse some artifact kinds — mcp-shield reads
    # live MCP servers and has no notion of an agent skill. Counting those as misses
    # would manufacture a recall gap out of a scope difference and flatter whichever
    # scanner happens to cover more kinds. They are excluded from scoring and reported
    # as coverage instead.
    not_applicable: bool = False

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
