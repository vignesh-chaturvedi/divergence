"""Scoring must be arithmetically correct — the headline number depends on it."""

from divergence.bench.models import (
    AttackClass,
    Channel,
    Finding,
    Sample,
    SampleResult,
    ScanRun,
    Stratum,
    TrapFamily,
    Kind,
)
from divergence.bench.metrics import score_run, score_all
from pathlib import Path


def _sample(id, stratum, attack=(), trap=()):
    return Sample(
        id=id, kind=Kind.MCP_SERVER, stratum=stratum, language="python",
        rationale="x" * 130, path=Path("."), artifact_path=Path("."),
        attack_classes=attack, trap_families=trap,
    )


def _flag(sample_id, attack_class=None, channel=Channel.RISK):
    return SampleResult(
        sample_id=sample_id,
        findings=(Finding(sample_id=sample_id, channel=channel, attack_class=attack_class),),
    )


def _corpus():
    return [
        _sample("mal-1", Stratum.MALICIOUS, attack=(AttackClass.UNDECLARED_NETWORK,)),
        _sample("mal-2", Stratum.MALICIOUS, attack=(AttackClass.SHADOWING,)),
        _sample("trap-1", Stratum.FP_TRAP, trap=(TrapFamily.WILDCARD_PERMISSIONS,)),
        _sample("trap-2", Stratum.FP_TRAP, trap=(TrapFamily.IMPERATIVE_LANGUAGE,)),
        _sample("benign-1", Stratum.BENIGN_PLAIN),
    ]


def test_perfect_scanner():
    samples = _corpus()
    run = ScanRun(scanner="perfect", results={
        "mal-1": _flag("mal-1", AttackClass.UNDECLARED_NETWORK),
        "mal-2": _flag("mal-2", AttackClass.SHADOWING),
    })
    s = score_run(samples, run)
    assert s.true_positives == 2
    assert s.false_negatives == 0
    assert s.false_positives == 0
    assert s.recall == 1.0
    assert s.precision == 1.0
    assert s.fpr_on_traps == 0.0
    assert s.attribution_rate == 1.0


def test_flags_everything_scanner():
    samples = _corpus()
    run = ScanRun(scanner="paranoid", results={sid: _flag(sid) for sid in
                  ["mal-1", "mal-2", "trap-1", "trap-2", "benign-1"]})
    s = score_run(samples, run)
    assert s.recall == 1.0            # catches both malicious
    assert s.fpr_on_traps == 1.0      # but flags every trap
    assert s.fpr_on_benign == 1.0
    assert s.precision == 0.4         # 2 tp / (2 tp + 3 fp: 2 traps + 1 benign)


def test_posture_findings_do_not_flag():
    samples = _corpus()
    run = ScanRun(scanner="posture-only", results={
        "trap-1": _flag("trap-1", channel=Channel.POSTURE),
    })
    s = score_run(samples, run)
    assert s.false_positives == 0
    assert s.fpr_on_traps == 0.0
    assert s.total_posture_findings == 1


def test_attribution_requires_right_reason():
    samples = _corpus()
    # Flags mal-1 but blames the wrong attack class.
    run = ScanRun(scanner="wrong-reason", results={
        "mal-1": _flag("mal-1", AttackClass.SHADOWING),  # actually undeclared_network
    })
    s = score_run(samples, run)
    assert s.true_positives == 1
    assert s.correctly_attributed == 0


def test_unavailable_scanner_sinks_and_undefined_metrics_stay_none():
    samples = _corpus()
    good = ScanRun(scanner="good", results={"mal-1": _flag("mal-1"), "mal-2": _flag("mal-2")})
    absent = ScanRun(scanner="absent", available=False, unavailable_reason="not installed")
    scores = score_all(samples, [absent, good])
    assert scores[0].scanner == "good"      # available first
    assert scores[-1].scanner == "absent"
    assert scores[-1].fpr_on_traps is None  # undefined, not zero
