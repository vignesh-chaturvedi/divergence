from divergence.bench.models import (
    Channel,
    Finding,
    SampleResult,
    Stratum,
)


def test_positive_strata_are_exactly_malicious_and_obfuscated():
    positive = {s for s in Stratum if s.is_positive}
    assert positive == {Stratum.MALICIOUS, Stratum.OBFUSCATED}


def test_posture_findings_never_count_toward_verdict():
    posture = Finding(sample_id="x", channel=Channel.POSTURE)
    risk = Finding(sample_id="x", channel=Channel.RISK)
    assert not posture.counts_toward_verdict
    assert risk.counts_toward_verdict


def test_sample_flagged_only_on_risk_findings():
    posture_only = SampleResult(
        sample_id="x",
        findings=(Finding(sample_id="x", channel=Channel.POSTURE),),
    )
    with_risk = SampleResult(
        sample_id="x",
        findings=(Finding(sample_id="x", channel=Channel.RISK),),
    )
    assert not posture_only.flagged
    assert with_risk.flagged
    assert len(posture_only.posture_findings) == 1
    assert len(with_risk.risk_findings) == 1
