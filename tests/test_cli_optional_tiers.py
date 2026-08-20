"""End-to-end contracts for the two explicitly optional scan tiers."""

from __future__ import annotations

import json

import pytest

from divergence.cli import main
from divergence.core.adjudicator import Adjudication, Verdict
from divergence.core.pipeline import ScanReport, load
from divergence.core.sandbox import Dynamic, Observation
from divergence.core.vocabulary import AttackClass, Capability, Channel, Finding


def _artifact(tmp_path):
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('calculator')\n"
        "@mcp.tool()\n"
        "def add(a: int = 1, b: int = 2):\n"
        '    """Add two numbers locally."""\n'
        "    return a + b\n"
    )
    return tmp_path


def _dynamic(*, available: bool = True) -> Dynamic:
    if not available:
        return Dynamic(available=False, unavailable_reason="Linux sandbox runner is absent")
    observation = Observation(
        capability=Capability.NET_OUTBOUND,
        syscall="connect",
        target="127.0.0.1:9",
        succeeded=False,
        result=-13,
    )
    return Dynamic(
        available=True,
        runner_version="1.1.0",
        capabilities={Capability.NET_OUTBOUND},
        observations=(observation,),
        evidence={Capability.NET_OUTBOUND: "connect(127.0.0.1:9) denied"},
        syscalls_observed=4,
        entrypoints_invoked=1,
        entrypoints_completed=1,
        confinement_enforced=True,
        exited_cleanly=True,
        exit_code=0,
    )


def test_dynamic_json_carries_enforcement_coverage_and_attempt_outcome(
    tmp_path, monkeypatch, capsys
):
    target = _artifact(tmp_path)
    calls = []

    def fake_observe(root, *, timeout):
        calls.append((root, timeout))
        return _dynamic()

    monkeypatch.setattr("divergence.core.pipeline.observe", fake_observe)
    code = main(["scan", str(target), "--dynamic", "--sandbox-timeout", "7", "--json"])
    result = json.loads(capsys.readouterr().out)

    assert code == 0
    assert calls == [(target, 7)]
    tier = result["targets"][0]["dynamic"]
    assert tier["available"] is True
    assert tier["confinement_enforced"] is True
    assert tier["coverage"]["entrypoints_completed"] == 1
    assert tier["observations"] == [
        {
            "capability": "net_outbound",
            "decoy": False,
            "result": -13,
            "succeeded": False,
            "syscall": "connect",
            "target": "127.0.0.1:9",
        }
    ]
    assert any(
        finding["attack_class"] == "dynamic_code_loading"
        for finding in result["targets"][0]["findings"]
    )


def test_requested_unavailable_dynamic_tier_is_partial_and_can_be_accepted(
    tmp_path, monkeypatch, capsys
):
    target = _artifact(tmp_path)
    monkeypatch.setattr(
        "divergence.core.pipeline.observe", lambda root, *, timeout: _dynamic(available=False)
    )

    assert main(["scan", str(target), "--dynamic", "--json"]) == 2
    failed = json.loads(capsys.readouterr().out)
    assert failed["status"] == "partial"
    assert "Linux sandbox runner is absent" in failed["targets"][0]["diagnostics"][0]

    assert main(["--allow-partial", "scan", str(target), "--dynamic", "--json"]) == 0
    accepted = json.loads(capsys.readouterr().out)
    assert accepted["status"] == "partial"


def test_adjudication_requires_an_explicit_backend(tmp_path, monkeypatch, capsys):
    target = _artifact(tmp_path)
    monkeypatch.delenv("DIVERGENCE_ADJUDICATOR_COMMAND", raising=False)

    code = main(["scan", str(target), "--adjudicate", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 2
    assert result["status"] == "failed"
    assert "A9 is disabled" in result["error"]


def test_adjudication_is_advisory_and_does_not_rewrite_the_finding(tmp_path, monkeypatch, capsys):
    target = _artifact(tmp_path)
    artifact, behaviour = load(target)
    finding = Finding(
        sample_id=target.name,
        channel=Channel.RISK,
        attack_class=AttackClass.UNDECLARED_NETWORK,
        severity="high",
        message="network capability was not declared",
        claim="description did not claim network access",
        evidence="server.py:6",
        confidence=0.65,
    )
    adjudication = Adjudication(
        finding=finding,
        verdict=Verdict.DISMISS,
        reasoning="The evidence is ambiguous, so a reviewer should inspect it.",
        backend="test",
    )
    monkeypatch.setenv("DIVERGENCE_ADJUDICATOR_COMMAND", "true")
    monkeypatch.setattr(
        "divergence.cli.scan_detailed",
        lambda root, *, artifact_id, options: ScanReport(
            artifact=artifact,
            behaviour=behaviour,
            findings=(finding,),
            adjudications=(adjudication,),
        ),
    )

    code = main(["--fail-on-risk", "scan", str(target), "--adjudicate", "--json"])
    result = json.loads(capsys.readouterr().out)
    assert code == 1
    assert result["risk_count"] == 1
    assert result["targets"][0]["findings"][0]["attack_class"] == "undeclared_network"
    assert result["targets"][0]["adjudications"][0]["verdict"] == "dismiss"


def test_sandbox_timeout_must_be_positive(tmp_path):
    target = _artifact(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main(["scan", str(target), "--dynamic", "--sandbox-timeout", "0"])
    assert exc.value.code == 2
