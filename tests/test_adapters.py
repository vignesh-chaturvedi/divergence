"""Reference adapters and the runner. External adapters stay gated in this test run."""

from types import SimpleNamespace

import divergence.adapters.divergence as divergence_adapter
import divergence.adapters.external  # noqa: F401
from divergence import __version__
from divergence.adapters import available_adapters, get_adapter
from divergence.adapters.base import run_adapter
from divergence.adapters.reference import KeywordScanner, NullScanner
from divergence.bench.metrics import score_run
from divergence.core.sandbox import Dynamic
from divergence.core.vocabulary import AttackClass, Channel, Finding


def test_reference_adapters_registered():
    names = {a.name for a in available_adapters()}
    assert {"null", "keyword", "divergence+dynamic"} <= names


def test_reference_adapters_sort_first():
    ordered = available_adapters()
    assert ordered[0].kind == "reference"


def test_null_scanner_flags_nothing(samples):
    run = run_adapter(NullScanner(), samples)
    score = score_run(samples, run)
    assert score.true_positives == 0
    assert score.false_positives == 0
    assert score.fpr_on_traps == 0.0


def test_keyword_scanner_reproduces_high_fpr(samples):
    """The whole motivation: a keyword scanner over-flags traps badly."""
    run = run_adapter(KeywordScanner(), samples)
    score = score_run(samples, run)
    # It should catch a majority of malicious samples...
    assert score.recall > 0.5
    # ...while badly over-flagging the traps that look dangerous. That is the point.
    assert score.fpr_on_traps > 0.3


def test_external_adapters_gated_off_by_default(samples, monkeypatch):
    monkeypatch.delenv("DIVERGENCE_ALLOW_EXTERNAL", raising=False)
    run = run_adapter(get_adapter("snyk-agent-scan"), samples)
    assert run.available is False
    assert "opt-in" in run.unavailable_reason


def test_dynamic_adapter_is_explicitly_opt_in(samples, monkeypatch):
    monkeypatch.setattr(divergence_adapter, "availability", lambda: Dynamic(available=True))
    monkeypatch.delenv("DIVERGENCE_ALLOW_DYNAMIC", raising=False)
    run = run_adapter(get_adapter("divergence+dynamic"), samples)
    assert run.available is False
    assert "dynamic execution is opt-in" in run.unavailable_reason
    assert run.metadata["analysis_tier"] == "static+dynamic"


def test_dynamic_adapter_reports_platform_unavailability_before_opt_in(samples, monkeypatch):
    state = Dynamic(available=False, unavailable_reason="Darwin — Linux confinement required")
    monkeypatch.setattr(divergence_adapter, "availability", lambda: state)
    monkeypatch.delenv("DIVERGENCE_ALLOW_DYNAMIC", raising=False)

    run = run_adapter(get_adapter("divergence+dynamic"), samples)

    assert run.available is False
    assert run.version == __version__
    assert run.unavailable_reason == state.unavailable_reason


def test_dynamic_adapter_preserves_static_ledger_findings(samples, monkeypatch):
    scanner = divergence_adapter.DivergenceDynamicScanner()
    sample = samples[0]
    ordinary = Finding(sample_id=sample.id, channel=Channel.POSTURE, message="static posture")
    ledger = Finding(
        sample_id=sample.id,
        channel=Channel.RISK,
        attack_class=AttackClass.POST_APPROVAL_MUTATION,
        message="approval ledger changed",
        evidence="new executable content",
        claim="approved digest differs",
    )
    dynamic = Dynamic(available=True, entrypoints_invoked=1, syscalls_observed=1)
    monkeypatch.setattr(
        divergence_adapter,
        "scan_detailed",
        lambda *args, **kwargs: SimpleNamespace(
            artifact=object(), findings=(ordinary,), dynamic=dynamic
        ),
    )
    monkeypatch.setattr(scanner._static, "_ledger_findings", lambda *args: [ledger])

    findings = scanner.scan(sample)

    assert ordinary in findings
    assert ledger in findings


def test_runner_isolates_a_crashing_adapter(samples):
    class Boom:
        name, homepage, kind = "boom", "", "reference"

        def probe(self):
            return "1.0"

        def scan(self, sample):
            raise RuntimeError("kaboom")

    run = run_adapter(Boom(), samples)
    assert run.available is True
    # Every sample recorded an error rather than taking the run down.
    assert all(r.error and "kaboom" in r.error for r in run.results.values())
