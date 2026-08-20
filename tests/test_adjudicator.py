from __future__ import annotations

import sys

import pytest

from divergence.core.adjudicator import (
    AdjudicatorUnavailable,
    CommandBackend,
    Verdict,
    adjudicate_findings,
    configured_backend,
    evidence_payload,
    select_contested,
)
from divergence.core.vocabulary import AttackClass, Channel, Finding


def _finding(index: int, confidence: float = 0.65) -> Finding:
    return Finding(
        sample_id=f"sample-{index:02d}",
        channel=Channel.RISK,
        attack_class=AttackClass.UNDECLARED_NETWORK,
        severity="high",
        message="network capability was not declared",
        evidence="tool.py:10",
        claim="description did not claim network access",
        confidence=confidence,
    )


class _Backend:
    name = "test"

    def __init__(self) -> None:
        self.payloads: list[dict[str, object]] = []

    def adjudicate(self, evidence: dict[str, object]) -> tuple[Verdict, str]:
        self.payloads.append(evidence)
        return Verdict.CONFIRM, "Both halves describe the same undeclared operation."


def test_hard_budget_never_rounds_above_five_percent():
    assert select_contested([_finding(i) for i in range(19)]) == []
    selected = select_contested([_finding(i) for i in range(40)])
    assert len(selected) == 2


def test_only_mid_confidence_risk_findings_are_contested():
    findings = [_finding(i, 0.65) for i in range(20)]
    findings[0] = _finding(0, 0.95)
    findings[1] = Finding(
        sample_id="posture",
        channel=Channel.POSTURE,
        confidence=0.65,
    )
    selected = select_contested(findings)
    assert len(selected) == 1
    assert selected[0].channel is Channel.RISK
    assert selected[0].confidence == 0.65


def test_adjudicator_receives_normalised_evidence_only():
    backend = _Backend()
    findings = [_finding(i) for i in range(20)]
    results = adjudicate_findings(findings, backend=backend)
    assert len(results) == 1
    assert results[0].verdict is Verdict.CONFIRM
    assert backend.payloads == [evidence_payload(results[0].finding)]
    assert set(backend.payloads[0]) == {
        "artifact",
        "channel",
        "attack_class",
        "severity",
        "message",
        "claim",
        "evidence",
        "confidence",
    }


def test_invalid_budget_is_rejected():
    with pytest.raises(ValueError, match="max_fraction"):
        select_contested([_finding(i) for i in range(20)], max_fraction=0.06)


def test_a9_has_no_implicit_network_backend(monkeypatch):
    monkeypatch.delenv("DIVERGENCE_ADJUDICATOR_COMMAND", raising=False)
    with pytest.raises(AdjudicatorUnavailable, match="disabled"):
        configured_backend()


def test_command_backend_uses_json_stdin_without_a_shell(tmp_path):
    script = tmp_path / "adjudicate.py"
    script.write_text(
        "import json, sys\n"
        "payload = json.load(sys.stdin)\n"
        "assert payload['attack_class'] == 'undeclared_network'\n"
        "json.dump({'verdict': 'dismiss', 'reasoning': 'Evidence is ambiguous.'}, sys.stdout)\n"
    )
    backend = CommandBackend(f"{sys.executable} {script}")
    verdict, reasoning = backend.adjudicate(evidence_payload(_finding(1)))
    assert verdict is Verdict.DISMISS
    assert reasoning == "Evidence is ambiguous."


def test_command_backend_rejects_malformed_output(tmp_path):
    script = tmp_path / "bad.py"
    script.write_text("print('not json')\n")
    backend = CommandBackend(f"{sys.executable} {script}")
    with pytest.raises(AdjudicatorUnavailable, match="invalid adjudicator response"):
        backend.adjudicate(evidence_payload(_finding(1)))
