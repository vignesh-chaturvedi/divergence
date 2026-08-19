"""The P1 exit gate, as an executable assertion.

§07: "Non-zero score on the benchmark using no model whatsoever. Annotation and
allowed-tools contradictions alone should already beat something."

Stated precisely: the deterministic core must detect real attacks while flagging *no*
benign artifact, and must beat the keyword strawman on precision and on FPR-on-traps.
Recall is expected to be low — that is what P2 and P3 are for.
"""

from divergence.adapters.base import run_adapter
from divergence.adapters.divergence import DivergenceScanner
from divergence.adapters.reference import KeywordScanner
from divergence.bench.metrics import score_run


def _score(scanner, samples):
    return score_run(samples, run_adapter(scanner, samples))


def test_gate_scores_non_zero_with_no_model(samples):
    score = _score(DivergenceScanner(), samples)
    assert score.true_positives > 0, "P1 must detect something without inference"


def test_gate_flags_no_trap(samples):
    """The headline. Zero false positives on artifacts engineered to look malicious."""
    score = _score(DivergenceScanner(), samples)
    assert score.fpr_on_traps == 0.0


def test_gate_flags_no_benign_artifact(samples):
    score = _score(DivergenceScanner(), samples)
    assert score.fpr_on_benign == 0.0


def test_gate_beats_the_strawman_on_precision(samples):
    ours = _score(DivergenceScanner(), samples)
    theirs = _score(KeywordScanner(), samples)
    assert ours.precision > theirs.precision
    assert ours.fpr_on_traps < theirs.fpr_on_traps


def test_every_detection_is_correctly_attributed(samples):
    """Right answer for the right reason. Deterministic checks have no excuse otherwise."""
    score = _score(DivergenceScanner(), samples)
    assert score.attribution_rate == 1.0


def test_posture_is_emitted_but_never_decides(samples):
    """Posture must actually fire — a channel that never emits is not a channel."""
    score = _score(DivergenceScanner(), samples)
    assert score.total_posture_findings > 0
    assert score.false_positives == 0


def test_no_scanner_errors(samples):
    assert _score(DivergenceScanner(), samples).errors == 0
