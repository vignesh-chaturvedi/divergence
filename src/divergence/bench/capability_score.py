"""Scoring B_s extraction against hand-verified ground truth.

This is the P2 gate. Precision and recall over *capabilities*, not over findings —
a capability set that is wrong makes every downstream rule wrong, so it is worth
measuring on its own before the divergence engine consumes it.

The asymmetry matters. A **false positive** — claiming a capability the artifact does not
have — manufactures divergence out of nothing and is treated as a hard failure. A **false
negative** is a known cost of static analysis, so it is measured, attributed, and
published rather than hidden.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from divergence.core.behaviour import extract
from divergence.core.vocabulary import Capability
from divergence.bench.models import Sample


@dataclass
class CapabilityReport:
    """How well B_s extraction matches what a human found in the source."""

    samples_scored: int = 0
    total_expected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    by_capability: dict[Capability, tuple[int, int]] = field(default_factory=dict)
    false_negatives_by_sample: dict[str, list[str]] = field(default_factory=dict)
    false_positives_by_sample: dict[str, list[str]] = field(default_factory=dict)

    @property
    def recall(self) -> float | None:
        return self.true_positives / self.total_expected if self.total_expected else None

    @property
    def precision(self) -> float | None:
        claimed = self.true_positives + self.false_positives
        return self.true_positives / claimed if claimed else None

    @property
    def false_negative_rate(self) -> float:
        return self.false_negatives / self.total_expected if self.total_expected else 0.0

    @property
    def false_positive_detail(self) -> str:
        return "; ".join(
            f"{sid}: {', '.join(caps)}" for sid, caps in self.false_positives_by_sample.items()
        )

    @property
    def exact_match_rate(self) -> float | None:
        """Share of artifacts whose extracted set equals the verified set exactly."""
        if not self.samples_scored:
            return None
        wrong = set(self.false_negatives_by_sample) | set(self.false_positives_by_sample)
        return (self.samples_scored - len(wrong)) / self.samples_scored


def score_capabilities(samples: list[Sample]) -> CapabilityReport:
    """Compare extracted capability sets against the verified ground truth."""
    report = CapabilityReport()
    per_capability: dict[Capability, list[int]] = {}

    for sample in samples:
        expected = sample.verified_capabilities
        if expected is None:
            continue

        report.samples_scored += 1
        extracted = extract(sample.artifact_path).capabilities

        expected_set = set(expected)
        report.total_expected += len(expected_set)

        for cap in expected_set:
            bucket = per_capability.setdefault(cap, [0, 0])
            bucket[1] += 1
            if cap in extracted:
                bucket[0] += 1

        hits = expected_set & extracted
        misses = expected_set - extracted
        extra = extracted - expected_set

        report.true_positives += len(hits)
        report.false_negatives += len(misses)
        report.false_positives += len(extra)

        if misses:
            report.false_negatives_by_sample[sample.id] = sorted(c.value for c in misses)
        if extra:
            report.false_positives_by_sample[sample.id] = sorted(c.value for c in extra)

    report.by_capability = {c: (h, t) for c, (h, t) in per_capability.items()}
    return report


def render(report: CapabilityReport) -> str:
    """The P2 gate table."""
    pct = lambda v: "—" if v is None else f"{v * 100:.1f}%"  # noqa: E731

    lines = [
        "Capability extraction vs hand-verified ground truth",
        "─" * 66,
        f"  artifacts scored        {report.samples_scored}",
        f"  capabilities expected   {report.total_expected}",
        f"  precision               {pct(report.precision)}   (over-claiming is a hard failure)",
        f"  recall                  {pct(report.recall)}",
        f"  false-negative rate     {pct(report.false_negative_rate)}   <- published, per §11",
        f"  exact-set match         {pct(report.exact_match_rate)}",
        "─" * 66,
        "",
        "Recall by capability",
        "─" * 66,
    ]

    for cap, (found, total) in sorted(report.by_capability.items(), key=lambda kv: kv[0].value):
        bar = "█" * round(10 * found / total) if total else ""
        lines.append(f"  {cap.value:<16} {found:>3}/{total:<3} {pct(found / total):>7}  {bar}")

    lines.append("─" * 66)

    if report.false_negatives_by_sample:
        lines += ["", "Known false negatives", "─" * 66]
        for sid, caps in sorted(report.false_negatives_by_sample.items()):
            lines.append(f"  {sid}")
            lines.append(f"    missed: {', '.join(caps)}")

    if report.false_positives_by_sample:
        lines += ["", "FALSE POSITIVES — over-claimed capability", "─" * 66]
        for sid, caps in sorted(report.false_positives_by_sample.items()):
            lines.append(f"  {sid}: {', '.join(caps)}")

    return "\n".join(lines)
