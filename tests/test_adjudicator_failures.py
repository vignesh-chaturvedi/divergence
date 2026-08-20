"""A9 command failures remain supplemental and can never corrupt deterministic findings."""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

import divergence.core.adjudicator as adjudicator
from divergence.core.adjudicator import AdjudicatorUnavailable, CommandBackend, Verdict


def test_command_backend_rejects_empty_configuration():
    with pytest.raises(ValueError, match="command is empty"):
        CommandBackend("   ")


@pytest.mark.parametrize(
    "failure",
    [OSError("not executable"), subprocess.TimeoutExpired(["backend"], 1)],
)
def test_command_backend_normalises_execution_failures(monkeypatch, failure):
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(adjudicator.subprocess, "run", fail)
    with pytest.raises(AdjudicatorUnavailable, match="could not run"):
        CommandBackend("backend").adjudicate({"artifact": "sample"})


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [("provider denied request\nmore", "provider denied request"), ("", "no diagnostic")],
)
def test_command_backend_reports_nonzero_exit(monkeypatch, stderr, expected):
    proc = SimpleNamespace(returncode=7, stdout="", stderr=stderr)
    monkeypatch.setattr(adjudicator.subprocess, "run", lambda *args, **kwargs: proc)

    with pytest.raises(AdjudicatorUnavailable, match=expected):
        CommandBackend("backend").adjudicate({"artifact": "sample"})


@pytest.mark.parametrize(
    "stdout",
    [
        "[]",
        '{"verdict": "invented", "reasoning": "not valid"}',
        '{"verdict": "confirm", "reasoning": ""}',
    ],
)
def test_command_backend_rejects_invalid_contract_shapes(monkeypatch, stdout):
    proc = SimpleNamespace(returncode=0, stdout=stdout, stderr="")
    monkeypatch.setattr(adjudicator.subprocess, "run", lambda *args, **kwargs: proc)

    with pytest.raises(AdjudicatorUnavailable, match="invalid adjudicator response"):
        CommandBackend("backend").adjudicate({"artifact": "sample"})


def test_configured_backend_uses_env_command_and_caps_reasoning(monkeypatch):
    monkeypatch.setenv(adjudicator.COMMAND_ENV, "backend --mode strict")
    backend = adjudicator.configured_backend()
    assert isinstance(backend, CommandBackend)
    assert backend.argv == ("backend", "--mode", "strict")

    proc = SimpleNamespace(
        returncode=0,
        stdout='{"verdict": "uncertain", "reasoning": "' + "x" * 2100 + '"}',
        stderr="",
    )
    monkeypatch.setattr(adjudicator.subprocess, "run", lambda *args, **kwargs: proc)
    verdict, reasoning = backend.adjudicate({"artifact": "sample"})
    assert verdict is Verdict.UNCERTAIN
    assert len(reasoning) == 2000


def test_negative_selector_budget_is_rejected():
    with pytest.raises(ValueError, match="max_fraction"):
        adjudicator.select_contested([], max_fraction=-0.01)
