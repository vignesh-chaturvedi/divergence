"""Reference adapters and the runner. External adapters stay gated in this test run."""

import os

from divergence.adapters import available_adapters, get_adapter
from divergence.adapters.base import run_adapter
from divergence.adapters.reference import KeywordScanner, NullScanner
from divergence.bench.metrics import score_run


def test_reference_adapters_registered():
    names = {a.name for a in available_adapters()}
    assert {"null", "keyword"} <= names


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
    run = run_adapter(get_adapter("mcp-scan"), samples)
    assert run.available is False
    assert "opt-in" in run.unavailable_reason


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
