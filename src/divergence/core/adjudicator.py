"""A9 — optional, evidence-only adjudication for genuinely contested findings.

The deterministic pipeline remains the product.  A9 is deliberately a narrow escape
hatch: it receives a normalised finding rather than artifact bytes, is disabled unless a
caller supplies a backend, and may see at most five percent of a scan's findings.  Those
properties are the architecture, not implementation details — silently sending every
finding to a model would make the scanner expensive, non-reproducible, and unsafe.

The built-in command backend is provider-neutral.  It writes one JSON object to a
user-configured executable's stdin and expects one JSON object on stdout.  This lets an
operator use a frontier-model gateway without adding a vendor SDK or network behaviour to
the default installation.  The executable is never invoked through a shell.
"""

from __future__ import annotations

import enum
import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from divergence.core.vocabulary import Channel, Finding

COMMAND_ENV = "DIVERGENCE_ADJUDICATOR_COMMAND"
DEFAULT_TIMEOUT = 60
MAX_ESCALATION_FRACTION = 0.05


class AdjudicatorUnavailable(RuntimeError):
    """The explicitly configured adjudicator could not produce a valid verdict."""


class Verdict(enum.StrEnum):
    CONFIRM = "confirm"
    DISMISS = "dismiss"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class Adjudication:
    """A provider's assessment of one finding; the original finding is never mutated."""

    finding: Finding
    verdict: Verdict
    reasoning: str
    backend: str


@runtime_checkable
class AdjudicatorBackend(Protocol):
    name: str

    def adjudicate(self, evidence: dict[str, object]) -> tuple[Verdict, str]: ...


def evidence_payload(finding: Finding) -> dict[str, object]:
    """Return the complete, bounded A9 input — never raw artifact content."""
    return {
        "artifact": finding.sample_id,
        "channel": finding.channel.value,
        "attack_class": finding.attack_class.value if finding.attack_class else None,
        "severity": finding.severity,
        "message": finding.message,
        "claim": finding.claim,
        "evidence": finding.evidence,
        "confidence": finding.confidence,
    }


class CommandBackend:
    """Adjudicate through an explicitly configured executable using a JSON contract."""

    name = "command"

    def __init__(self, command: str, *, timeout: int = DEFAULT_TIMEOUT) -> None:
        argv = shlex.split(command)
        if not argv:
            raise ValueError("adjudicator command is empty")
        self.argv = tuple(argv)
        self.timeout = timeout

    def adjudicate(self, evidence: dict[str, object]) -> tuple[Verdict, str]:
        try:
            proc = subprocess.run(
                self.argv,
                input=json.dumps(evidence, sort_keys=True),
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdjudicatorUnavailable(f"adjudicator could not run: {exc}") from None

        if proc.returncode != 0:
            detail = (proc.stderr or "").strip().splitlines()
            raise AdjudicatorUnavailable(
                f"adjudicator exited {proc.returncode}: {detail[0] if detail else 'no diagnostic'}"
            )

        try:
            doc = json.loads(proc.stdout)
            if not isinstance(doc, dict):
                raise TypeError("response is not an object")
            verdict = Verdict(str(doc.get("verdict", "")))
            reasoning = str(doc.get("reasoning", "")).strip()
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise AdjudicatorUnavailable(f"invalid adjudicator response: {exc}") from None

        if not reasoning:
            raise AdjudicatorUnavailable("invalid adjudicator response: reasoning is empty")
        return verdict, reasoning[:2000]


def configured_backend() -> AdjudicatorBackend:
    """Return the explicitly configured A9 backend; there is intentionally no default."""
    command = os.environ.get(COMMAND_ENV, "").strip()
    if not command:
        raise AdjudicatorUnavailable(
            f"A9 is disabled; set {COMMAND_ENV} to an evidence-only adjudicator executable"
        )
    return CommandBackend(command)


def select_contested(
    findings: list[Finding],
    *,
    max_fraction: float = MAX_ESCALATION_FRACTION,
) -> list[Finding]:
    """Select mid-confidence risks without ever exceeding the hard budget.

    A scan with fewer than twenty findings has no integer budget at five percent.  It is
    intentionally not rounded up: escalating one of ten findings would violate the locked
    architecture even though doing so might feel convenient.
    """
    if not 0 <= max_fraction <= MAX_ESCALATION_FRACTION:
        raise ValueError(f"max_fraction must be between 0 and {MAX_ESCALATION_FRACTION:.2f}")

    budget = int(len(findings) * max_fraction)
    if budget == 0:
        return []

    contested = [
        finding
        for finding in findings
        if finding.channel is Channel.RISK and 0.45 <= finding.confidence < 0.85
    ]
    # The findings nearest the undecided midpoint are the ones deterministic rules settle
    # least confidently.  Stable secondary fields preserve reproducibility.
    contested.sort(
        key=lambda finding: (
            abs(finding.confidence - 0.65),
            finding.sample_id,
            finding.attack_class.value if finding.attack_class else "",
        )
    )
    return contested[:budget]


def adjudicate_findings(
    findings: list[Finding],
    *,
    backend: AdjudicatorBackend,
    max_fraction: float = MAX_ESCALATION_FRACTION,
) -> tuple[Adjudication, ...]:
    """Run A9 over the contested subset and retain deterministic findings unchanged."""
    results: list[Adjudication] = []
    for finding in select_contested(findings, max_fraction=max_fraction):
        verdict, reasoning = backend.adjudicate(evidence_payload(finding))
        results.append(
            Adjudication(
                finding=finding,
                verdict=verdict,
                reasoning=reasoning,
                backend=backend.name,
            )
        )
    return tuple(results)
