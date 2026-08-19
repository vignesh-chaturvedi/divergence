"""Scoring.

The ordering of this module is deliberate. `fpr_on_traps` is the headline number, not a
derived afterthought, because it is the one figure that separates this benchmark from
every recall-only benchmark in the space.

A note on what counts as a detection: a sample is flagged when a scanner reports at
least one **risk** finding on it. Posture findings are recorded and displayed but never
move a verdict. Scoring a tool that has no posture channel is unaffected — its findings
all arrive as risk, which is exactly how it behaves in the field.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from divergence.bench.models import (
    AttackClass,
    Sample,
    ScanRun,
    Stratum,
    TrapFamily,
)


def _ratio(numerator: int, denominator: int) -> float | None:
    """None means undefined, which is not the same as zero and must not print as zero."""
    return numerator / denominator if denominator else None


@dataclass(frozen=True, slots=True)
class StratumScore:
    """How a scanner did on one stratum."""

    stratum: Stratum
    total: int
    flagged: int

    @property
    def flag_rate(self) -> float | None:
        return _ratio(self.flagged, self.total)


@dataclass
class Score:
    """One scanner's full scorecard over the corpus."""

    scanner: str
    available: bool = True
    unavailable_reason: str = ""

    # Artifacts this scanner could actually analyse. A scanner that only reads MCP servers
    # is scored on MCP servers; excluding skills it cannot see is the difference between
    # a comparison and a rigged one.
    scored: int = 0
    skipped: int = 0

    true_positives: int = 0
    false_negatives: int = 0
    false_positives: int = 0
    true_negatives: int = 0

    errors: int = 0
    duration_s: float = 0.0

    by_stratum: dict[Stratum, StratumScore] = field(default_factory=dict)
    recall_by_attack_class: dict[AttackClass, tuple[int, int]] = field(default_factory=dict)
    fpr_by_trap_family: dict[TrapFamily, tuple[int, int]] = field(default_factory=dict)

    # Of the samples correctly flagged, how many were flagged for the right reason.
    correctly_attributed: int = 0

    total_risk_findings: int = 0
    total_posture_findings: int = 0

    # ---- headline -------------------------------------------------------------

    @property
    def fpr_on_traps(self) -> float | None:
        """The headline. Share of false-positive traps a scanner wrongly flags.

        Lower is better. This is where every shipping scanner falls over, and it is
        the number the writeup leads with.
        """
        s = self.by_stratum.get(Stratum.FP_TRAP)
        return s.flag_rate if s else None

    # ---- conventional ---------------------------------------------------------

    @property
    def precision(self) -> float | None:
        return _ratio(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float | None:
        return _ratio(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def fpr_on_benign(self) -> float | None:
        s = self.by_stratum.get(Stratum.BENIGN_PLAIN)
        return s.flag_rate if s else None

    @property
    def coverage(self) -> float | None:
        """Share of the corpus this scanner could analyse at all."""
        total = self.scored + self.skipped
        return _ratio(self.scored, total) if total else None

    @property
    def attribution_rate(self) -> float | None:
        """Right answer for the right reason, among true positives."""
        return _ratio(self.correctly_attributed, self.true_positives)


def score_run(samples: list[Sample], run: ScanRun) -> Score:
    """Score one scanner's run against the labelled corpus."""
    score = Score(
        scanner=run.scanner,
        available=run.available,
        unavailable_reason=run.unavailable_reason,
        duration_s=run.duration_s,
    )

    if not run.available:
        return score

    stratum_totals: dict[Stratum, int] = {}
    stratum_flagged: dict[Stratum, int] = {}
    ac_hits: dict[AttackClass, list[int]] = {}
    tf_hits: dict[TrapFamily, list[int]] = {}

    for sample in samples:
        result = run.result_for(sample.id)

        if result.not_applicable:
            score.skipped += 1
            continue

        score.scored += 1
        flagged = result.flagged

        if result.error:
            score.errors += 1

        score.total_risk_findings += len(result.risk_findings)
        score.total_posture_findings += len(result.posture_findings)

        stratum_totals[sample.stratum] = stratum_totals.get(sample.stratum, 0) + 1
        stratum_flagged[sample.stratum] = stratum_flagged.get(sample.stratum, 0) + int(flagged)

        if sample.is_positive:
            if flagged:
                score.true_positives += 1
                reported = {f.attack_class for f in result.risk_findings if f.attack_class}
                if reported & set(sample.attack_classes):
                    score.correctly_attributed += 1
            else:
                score.false_negatives += 1

            for ac in sample.attack_classes:
                bucket = ac_hits.setdefault(ac, [0, 0])
                bucket[1] += 1
                bucket[0] += int(flagged)
        else:
            if flagged:
                score.false_positives += 1
            else:
                score.true_negatives += 1

            for tf in sample.trap_families:
                bucket = tf_hits.setdefault(tf, [0, 0])
                bucket[1] += 1
                bucket[0] += int(flagged)

    score.by_stratum = {
        st: StratumScore(stratum=st, total=total, flagged=stratum_flagged.get(st, 0))
        for st, total in stratum_totals.items()
    }
    score.recall_by_attack_class = {ac: (h, t) for ac, (h, t) in ac_hits.items()}
    score.fpr_by_trap_family = {tf: (h, t) for tf, (h, t) in tf_hits.items()}

    return score


def score_all(samples: list[Sample], runs: list[ScanRun]) -> list[Score]:
    """Score every run, ordered by the headline metric.

    Available scanners sort first, best FPR-on-traps at the top, ties broken by F1.
    Unavailable scanners sink to the bottom rather than vanishing — a missing baseline
    is information, and hiding it would flatter our own numbers.
    """
    scores = [score_run(samples, run) for run in runs]

    def sort_key(s: Score):
        return (
            not s.available,
            s.fpr_on_traps if s.fpr_on_traps is not None else 2.0,
            -(s.f1 or 0.0),
            s.scanner,
        )

    return sorted(scores, key=sort_key)
