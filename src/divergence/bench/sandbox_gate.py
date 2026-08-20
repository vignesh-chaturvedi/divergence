"""The P5 exit gate.

§07: "Catches at least half the obfuscated stratum that static analysis missed, with
observed-coverage reported per finding."

Stated precisely: for every obfuscated sample, compare the capability set a parser can
prove (B_static) against the one observation records (B_dynamic). The gate is the share of
*high-signal* capabilities that only execution revealed.

The control sample matters as much as the payloads. `obf-006` is base64-heavy and entirely
benign; if the sandbox manufactures a finding there, the phase has reproduced the very
over-flagging the project exists to eliminate — at a higher cost.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from divergence.bench.models import Sample, Stratum
from divergence.core.behaviour import extract
from divergence.core.engine import _DYNAMIC_HIGH_SIGNAL, dynamic_divergence
from divergence.core.sandbox import Dynamic, observe
from divergence.core.vocabulary import Capability, Channel


@dataclass
class SampleDelta:
    sample_id: str
    static: set[Capability] = field(default_factory=set)
    dynamic: set[Capability] = field(default_factory=set)
    revealed: set[Capability] = field(default_factory=set)
    high_signal_revealed: set[Capability] = field(default_factory=set)
    risk_findings: int = 0
    coverage: str = ""
    ran: bool = False


@dataclass
class GateReport:
    deltas: list[SampleDelta] = field(default_factory=list)
    unavailable_reason: str = ""

    @property
    def available(self) -> bool:
        return not self.unavailable_reason

    @property
    def payloads(self) -> list[SampleDelta]:
        """Samples whose static analysis was genuinely incomplete."""
        return [d for d in self.deltas if d.sample_id != "obf-006-benign-base64-decoder"]

    @property
    def caught(self) -> int:
        return sum(1 for d in self.payloads if d.high_signal_revealed)

    @property
    def catch_rate(self) -> float | None:
        total = len(self.payloads)
        return self.caught / total if total else None

    @property
    def control_clean(self) -> bool:
        """The control must produce no risk finding."""
        control = [d for d in self.deltas if d.sample_id == "obf-006-benign-base64-decoder"]
        return all(d.risk_findings == 0 for d in control)


def run_gate(samples: list[Sample], *, timeout: int = 25) -> GateReport:
    report = GateReport()

    obfuscated = [s for s in samples if s.stratum is Stratum.OBFUSCATED]
    if not obfuscated:
        report.unavailable_reason = "no obfuscated samples in this corpus"
        return report

    from divergence.core.sandbox import availability

    state = availability()
    if not state.available:
        report.unavailable_reason = state.unavailable_reason
        return report

    for sample in sorted(obfuscated, key=lambda s: s.id):
        static = extract(sample.artifact_path).capabilities
        dynamic: Dynamic = observe(sample.artifact_path, timeout=timeout)

        revealed = dynamic.capabilities - static
        findings = dynamic_divergence(static, dynamic, sample_id=sample.id)

        report.deltas.append(
            SampleDelta(
                sample_id=sample.id,
                static=set(static),
                dynamic=set(dynamic.capabilities),
                revealed=revealed,
                high_signal_revealed=revealed & _DYNAMIC_HIGH_SIGNAL,
                risk_findings=sum(1 for f in findings if f.channel is Channel.RISK),
                coverage=dynamic.coverage_note,
                ran=dynamic.ran,
            )
        )

    return report


def render(report: GateReport) -> str:
    if not report.available:
        return (
            "Sandbox gate — not run\n"
            + "─" * 70
            + f"\n  {report.unavailable_reason}\n"
            "  Static-only analysis is unaffected; B_dynamic is an optional input.\n"
        )

    lines = [
        "P5 sandbox gate — what execution revealed that parsing could not",
        "─" * 96,
        f"{'sample':<38}{'B_static':<22}{'revealed by execution':<26}{'risk'}",
        "─" * 96,
    ]

    for d in report.deltas:
        static = ",".join(sorted(c.value for c in d.static)) or "—"
        revealed = ",".join(sorted(c.value for c in d.high_signal_revealed)) or "—"
        marker = "  <- control" if d.sample_id == "obf-006-benign-base64-decoder" else ""
        lines.append(f"{d.sample_id:<38}{static:<22}{revealed:<26}{d.risk_findings}{marker}")

    rate = report.catch_rate
    lines += [
        "─" * 96,
        f"  payloads caught      {report.caught}/{len(report.payloads)}"
        + (f"  ({rate * 100:.0f}%)" if rate is not None else ""),
        f"  gate (>= 50%)        {'PASS' if rate and rate >= 0.5 else 'FAIL'}",
        f"  control stayed clean {'yes' if report.control_clean else 'NO — over-flagging'}",
        "─" * 96,
        "",
        "Coverage, per sample — an empty capability set means nothing ran, not nothing happened:",
    ]
    for d in report.deltas:
        lines.append(f"  {d.sample_id:<38}{d.coverage}")

    return "\n".join(lines)
