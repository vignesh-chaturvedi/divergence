"""The corpus must always be valid. These are the guardrails on the ground truth."""

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
