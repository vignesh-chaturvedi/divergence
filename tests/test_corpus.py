"""The corpus must always be valid. These are the guardrails on the ground truth."""

from pathlib import Path

import yaml

from divergence.bench.corpus import counts_by_stratum, validate
from divergence.bench.models import Stratum


def test_corpus_loads(samples):
    # The P0 strata are fixed at 80; the obfuscated stratum (P5) is additive.
    assert len(samples) >= 80


def test_p0_target_met(samples):
    counts = counts_by_stratum(samples)
    assert counts[Stratum.MALICIOUS] == 25
    assert counts[Stratum.FP_TRAP] == 35
    assert counts[Stratum.BENIGN_PLAIN] == 20


def test_explicit_truth_counts_include_benign_obfuscated_control(samples):
    positives = [sample for sample in samples if sample.is_positive]
    negatives = [sample for sample in samples if not sample.is_positive]
    control = next(sample for sample in samples if sample.id == "obf-006-benign-base64-decoder")

    assert len(positives) == 50
    assert len(negatives) == 60
    assert control.stratum is Stratum.OBFUSCATED
    assert not control.is_positive
    assert all(expected.channel.value == "posture" for expected in control.expected)


def test_expanded_obfuscated_design_was_frozen_and_matches_the_corpus(samples):
    obfuscated = [sample for sample in samples if sample.stratum is Stratum.OBFUSCATED]
    assert len(obfuscated) == 30
    assert sum(sample.is_positive for sample in obfuscated) == 25
    assert sum(not sample.is_positive for sample in obfuscated) == 5

    design_path = Path(__file__).resolve().parents[1] / "corpus" / "obfuscated-design.yaml"
    design = yaml.safe_load(design_path.read_text())
    assert design["status"] == "frozen-before-sandbox-measurement"
    assert set(design["samples"]) == {sample.id for sample in obfuscated}
    assert design["protocol"]["target_truth"] == {"malicious": 25, "benign_controls": 5}


def test_every_sample_is_valid(samples):
    violations = validate(samples)
    assert violations == [], "\n".join(str(v) for v in violations)


def test_sample_ids_are_unique(samples):
    ids = [s.id for s in samples]
    assert len(ids) == len(set(ids))


def test_positive_samples_declare_expected_findings(samples):
    for s in samples:
        if s.is_positive:
            assert s.expected, f"{s.id} declares no expected findings"
            assert s.attack_classes, f"{s.id} declares no attack classes"


def test_traps_declare_a_family(samples):
    for s in samples:
        if s.stratum is Stratum.FP_TRAP:
            assert s.trap_families, f"{s.id} is a trap with no declared family"


def test_expected_findings_reference_declared_classes(samples):
    for s in samples:
        for e in s.expected:
            assert e.attack_class in s.attack_classes
