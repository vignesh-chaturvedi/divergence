"""The P3 exit gate, as an executable assertion.

§07: "FPR on the trap stratum beats every baseline scanner by a wide, defensible margin.
This number is the headline of the writeup."
"""

from divergence.adapters.base import run_adapter
from divergence.adapters.divergence import DivergenceScanner
from divergence.adapters.reference import KeywordScanner, NullScanner
from divergence.bench.metrics import score_run


def _score(scanner, samples):
    return score_run(samples, run_adapter(scanner, samples))


def test_fpr_on_traps_beats_the_strawman_by_a_wide_margin(samples):
    ours = _score(DivergenceScanner(), samples)
    theirs = _score(KeywordScanner(), samples)
    assert ours.fpr_on_traps == 0.0
    assert theirs.fpr_on_traps - ours.fpr_on_traps > 0.4


def test_zero_false_positives_anywhere(samples):
    score = _score(DivergenceScanner(), samples)
    assert score.false_positives == 0
    assert score.fpr_on_benign == 0.0


def test_recall_now_beats_the_strawman_too(samples):
    """The trade the project accepted at P1 is no longer a trade."""
    ours = _score(DivergenceScanner(), samples)
    theirs = _score(KeywordScanner(), samples)
    assert ours.recall > theirs.recall


def test_beating_the_floor_is_not_enough_on_its_own(samples):
    """`null` also scores 0% FPR-on-traps. Precision without recall is the null scanner."""
    ours = _score(DivergenceScanner(), samples)
    floor = _score(NullScanner(), samples)
    assert floor.fpr_on_traps == 0.0
    assert ours.recall > 0.5, "matching the floor's FPR only counts alongside real recall"


def test_posture_channel_still_carries_the_noise(samples):
    """Precision holds because capability goes to posture, not because nothing is said."""
    score = _score(DivergenceScanner(), samples)
    assert score.total_posture_findings > score.total_risk_findings


def test_every_risk_finding_is_evidence_bound(samples):
    """§04: no finding ships without both halves of the contradiction."""
    scanner = DivergenceScanner()
    for sample in samples:
        for finding in scanner.scan(sample):
            if finding.counts_toward_verdict:
                assert finding.is_evidence_bound, f"{sample.id}: {finding.attack_class}"


def test_results_are_deterministic(samples):
    scanner = DivergenceScanner()
    first = _score(scanner, samples)
    second = _score(scanner, samples)
    assert (first.true_positives, first.false_positives) == (
        second.true_positives,
        second.false_positives,
    )
