"""The P2 exit gate, as an executable assertion.

§07: "Capability sets manually verified on 50 real artifacts. Track and publish your own
false-negative rate."

Stated precisely: the extractor is scored against hand-verified ground truth on every
sample, and the false-negative rate is a reported number rather than an unknown. §11 is
blunt that we must not claim soundness we do not have — so the test asserts the rate is
*measured and bounded*, not that it is zero.
"""

from divergence.bench.capability_score import score_capabilities


def test_ground_truth_covers_at_least_fifty_artifacts(samples):
    verified = [s for s in samples if s.verified_capabilities is not None]
    assert len(verified) >= 50


def test_extraction_has_no_false_positives(samples):
    """Over-claiming a capability is how a scanner invents divergence that isn't there."""
    report = score_capabilities(samples)
    assert report.false_positives == 0, report.false_positive_detail


def test_false_negative_rate_is_measured_and_bounded(samples):
    report = score_capabilities(samples)
    assert report.total_expected > 0
    assert report.false_negative_rate < 0.10


def test_every_false_negative_has_a_recorded_reason(samples):
    """An unexplained miss is a bug; an explained one is a documented limit."""
    report = score_capabilities(samples)
    for sample_id, caps in report.false_negatives_by_sample.items():
        sample = next(s for s in samples if s.id == sample_id)
        assert sample.capability_miss_reason, f"{sample_id} misses {caps} with no reason"


def test_per_capability_recall_is_reported(samples):
    report = score_capabilities(samples)
    assert report.by_capability
    for cap, (found, expected) in report.by_capability.items():
        assert found <= expected
