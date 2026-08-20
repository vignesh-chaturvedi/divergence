"""Scoring must be arithmetically correct — the headline number depends on it."""

from pathlib import Path

from divergence.bench.metrics import score_all, score_run, wilson95
from divergence.bench.models import (
    AttackClass,
    Channel,
    Finding,
    Kind,
    Sample,
    SampleResult,
    ScanRun,
    Stratum,
    TrapFamily,
)


def _sample(id, stratum, attack=(), trap=(), malicious=None):
    if malicious is None:
        malicious = stratum is Stratum.MALICIOUS
    return Sample(
        id=id,
        kind=Kind.MCP_SERVER,
        stratum=stratum,
        language="python",
        rationale="x" * 130,
        path=Path("."),
        artifact_path=Path("."),
        malicious=malicious,
        attack_classes=attack,
        trap_families=trap,
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
    run = ScanRun(
        scanner="perfect",
        results={
            "mal-1": _flag("mal-1", AttackClass.UNDECLARED_NETWORK),
            "mal-2": _flag("mal-2", AttackClass.SHADOWING),
        },
    )
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
    run = ScanRun(
        scanner="paranoid",
        results={sid: _flag(sid) for sid in ["mal-1", "mal-2", "trap-1", "trap-2", "benign-1"]},
    )
    s = score_run(samples, run)
    assert s.recall == 1.0  # catches both malicious
    assert s.fpr_on_traps == 1.0  # but flags every trap
    assert s.fpr_on_benign == 1.0
    assert s.precision == 0.4  # 2 tp / (2 tp + 3 fp: 2 traps + 1 benign)


def test_posture_findings_do_not_flag():
    samples = _corpus()
    run = ScanRun(
        scanner="posture-only",
        results={
            "trap-1": _flag("trap-1", channel=Channel.POSTURE),
        },
    )
    s = score_run(samples, run)
    assert s.false_positives == 0
    assert s.fpr_on_traps == 0.0
    assert s.total_posture_findings == 1


def test_benign_control_in_positive_stratum_is_a_negative():
    samples = [
        _sample(
            "control",
            Stratum.OBFUSCATED,
            attack=(AttackClass.DYNAMIC_CODE_LOADING,),
            malicious=False,
        )
    ]
    clean = score_run(samples, ScanRun(scanner="clean"))
    noisy = score_run(samples, ScanRun(scanner="noisy", results={"control": _flag("control")}))

    assert clean.true_negatives == 1
    assert clean.false_negatives == 0
    assert noisy.false_positives == 1
    assert noisy.true_positives == 0


def test_attribution_requires_right_reason():
    samples = _corpus()
    # Flags mal-1 but blames the wrong attack class.
    run = ScanRun(
        scanner="wrong-reason",
        results={
            "mal-1": _flag("mal-1", AttackClass.SHADOWING),  # actually undeclared_network
        },
    )
    s = score_run(samples, run)
    assert s.true_positives == 1
    assert s.correctly_attributed == 0


def test_unavailable_scanner_sinks_and_undefined_metrics_stay_none():
    samples = _corpus()
    good = ScanRun(scanner="good", results={"mal-1": _flag("mal-1"), "mal-2": _flag("mal-2")})
    absent = ScanRun(scanner="absent", available=False, unavailable_reason="not installed")
    scores = score_all(samples, [absent, good])
    assert scores[0].scanner == "good"  # available first
    assert scores[-1].scanner == "absent"
    assert scores[-1].fpr_on_traps is None  # undefined, not zero


def test_scan_errors_are_excluded_from_outcomes_and_reduce_coverage():
    samples = _corpus()[:3]
    run = ScanRun(
        scanner="partial",
        results={
            "mal-1": SampleResult(sample_id="mal-1", error="scanner crashed"),
            "trap-1": SampleResult(sample_id="trap-1", error="scanner crashed"),
        },
    )

    score = score_run(samples, run)

    assert score.errors == 2
    assert score.scored == 1
    assert score.true_positives == 0
    assert score.false_negatives == 1
    assert score.false_positives == 0
    assert score.true_negatives == 0
    assert score.fpr_on_traps is None
    assert score.coverage == 1 / 3


def test_wilson_interval_reports_uncertainty_for_small_samples():
    zero_of_35 = wilson95(0, 35)
    four_of_five = wilson95(4, 5)
    assert zero_of_35 is not None and zero_of_35[0] == 0.0
    assert zero_of_35[1] > 0.09
    assert four_of_five is not None and four_of_five[0] < 0.4
    assert four_of_five[1] > 0.96
    assert wilson95(0, 0) is None
