from pathlib import Path

from divergence.bench.models import (
    Channel,
    Finding,
    Kind,
    Sample,
    SampleResult,
    Stratum,
)


def test_truth_label_not_stratum_controls_positive_status():
    control = Sample(
        id="control",
        kind=Kind.MCP_SERVER,
        stratum=Stratum.OBFUSCATED,
        language="python",
        rationale="x" * 130,
        path=Path("."),
        artifact_path=Path("."),
        malicious=False,
    )
    assert not control.is_positive


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
