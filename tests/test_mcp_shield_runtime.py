"""mcp-shield integration stays scoped to declared MCP manifests and never runs fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import divergence.adapters.mcp_shield as shield
from divergence.adapters.base import ScannerUnavailable
from divergence.bench.models import Kind, Sample, Stratum
from divergence.core.vocabulary import AttackClass, Channel


def _sample(sample_id: str, artifact: Path, *, kind: Kind = Kind.MCP_SERVER) -> Sample:
    return Sample(
        id=sample_id,
        kind=kind,
        stratum=Stratum.BENIGN_PLAIN,
        language="python",
        rationale="mcp-shield adapter fixture " * 8,
        path=artifact.parent,
        artifact_path=artifact,
        malicious=False,
    )


def test_classification_and_provenance_are_stable():
    assert shield.classify("Hidden instruction in tool") is AttackClass.DESCRIPTION_POISONING
    assert shield.classify("possible CROSS-ORIGIN use") is AttackClass.CROSS_TOOL_INSTRUCTION
    assert shield.classify("ordinary warning") is None
    assert shield.McpShieldAdapter().provenance() == {
        "package_spec": shield.PACKAGE_SPEC,
        "scanner_command": ["npx", "--yes", shield.PACKAGE_SPEC, "--path", "<manifest-shim>"],
        "input_adapter": "divergence.bench.manifest_shim",
    }


def test_text_report_uses_last_block_and_handles_missing_details():
    output = (
        "Vulnerabilities Detected\n"
        "1. Server: stale\nRisk Level: HIGH\n- stale issue\n"
        "\x1b[31mVulnerabilities Detected\x1b[0m\n"
        "1. Server: alpha\nRisk Level: LOW\n– prompt injection in description\n"
        "2. Server: beta\nNo issue bullets here\n"
    )

    parsed = shield.parse_report(output)

    assert "stale" not in parsed
    assert parsed["alpha"] == [("low", "prompt injection in description")]
    assert parsed["beta"] == [("unknown", "reported without detail")]
    assert shield.parse_report("clean scan") == {}


def test_probe_is_opt_in_and_requires_npx(monkeypatch):
    adapter = shield.McpShieldAdapter()
    monkeypatch.setattr(shield, "external_enabled", lambda: False)
    with pytest.raises(ScannerUnavailable, match="opt-in"):
        adapter.probe()

    monkeypatch.setattr(shield, "external_enabled", lambda: True)
    monkeypatch.setattr(shield.shutil, "which", lambda executable: None)
    with pytest.raises(ScannerUnavailable, match="npx.*PATH"):
        adapter.probe()


def test_probe_reports_exit_and_reads_version_streams(monkeypatch):
    adapter = shield.McpShieldAdapter()
    monkeypatch.setattr(shield, "external_enabled", lambda: True)
    monkeypatch.setattr(shield.shutil, "which", lambda executable: "/bin/npx")
    monkeypatch.setattr(
        shield.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=9, stdout="", stderr="failed"),
    )
    with pytest.raises(ScannerUnavailable, match="probe exited 9"):
        adapter.probe()

    monkeypatch.setattr(
        shield.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr="mcp-shield 1.0.4\n"
        ),
    )
    assert adapter.probe() == "mcp-shield 1.0.4"


def test_prepare_ignores_skills_and_servers_without_manifests(monkeypatch, tmp_path):
    skill = _sample("skill", tmp_path / "skill", kind=Kind.AGENT_SKILL)
    server = _sample("server", tmp_path / "server")
    adapter = shield.McpShieldAdapter()

    def unexpected(*args, **kwargs):
        raise AssertionError("no scanner process should be started")

    monkeypatch.setattr(shield.subprocess, "run", unexpected)
    adapter.prepare([skill, server])

    assert adapter._scoped == set()
    assert adapter._results == {}


def test_prepare_builds_manifest_shim_config_and_normalises_results(monkeypatch, tmp_path):
    artifact = tmp_path / "server" / "artifact"
    artifact.mkdir(parents=True)
    manifest = artifact / "manifest.json"
    manifest.write_text(json.dumps({"tools": [{"name": "send"}]}))
    server = _sample("server", artifact)
    seen = {}

    def fake_run(command, **kwargs):
        config = Path(command[-1])
        seen["command"] = command
        seen["config"] = json.loads(config.read_text())
        return SimpleNamespace(
            returncode=0,
            stdout=(
                "Vulnerabilities Detected\n"
                "1. Server: server\n"
                "Risk Level: HIGH\n"
                "- hidden instruction detected\n"
                "- sensitive file access\n"
            ),
            stderr="",
        )

    monkeypatch.setattr(shield.subprocess, "run", fake_run)
    adapter = shield.McpShieldAdapter()
    adapter.prepare([server])
    findings = adapter.scan(server)

    assert seen["command"][:4] == ["npx", "--yes", shield.PACKAGE_SPEC, "--path"]
    shim = seen["config"]["mcpServers"]["server"]
    assert shim["args"] == ["-m", "divergence.bench.manifest_shim", str(manifest)]
    assert shim["env"]["PYTHONPATH"]
    assert [finding.attack_class for finding in findings] == [
        AttackClass.DESCRIPTION_POISONING,
        AttackClass.UNDECLARED_SECRETS,
    ]
    assert all(finding.channel is Channel.RISK for finding in findings)


def test_prepare_rejects_nonzero_scan_exit(monkeypatch, tmp_path):
    artifact = tmp_path / "server" / "artifact"
    artifact.mkdir(parents=True)
    (artifact / "manifest.json").write_text(json.dumps({"tools": []}))
    monkeypatch.setattr(
        shield.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=9, stdout="", stderr="scanner crashed\nmore"
        ),
    )
    adapter = shield.McpShieldAdapter()

    with pytest.raises(ScannerUnavailable, match="exited 9.*scanner crashed"):
        adapter.prepare([_sample("server", artifact)])


def test_scan_preserves_posture_and_rejects_out_of_scope_samples(tmp_path):
    adapter = shield.McpShieldAdapter()
    scoped = _sample("scoped", tmp_path / "scoped")
    outside = _sample("outside", tmp_path / "outside", kind=Kind.AGENT_SKILL)
    adapter._scoped = {"scoped"}
    adapter._results = {"scoped": [("info", "ordinary metadata"), ("critical", "exfiltration")]}

    findings = adapter.scan(scoped)

    assert [finding.channel for finding in findings] == [Channel.POSTURE, Channel.RISK]
    assert findings[1].attack_class is AttackClass.UNDECLARED_NETWORK
    with pytest.raises(shield.NotApplicable, match="agent_skill"):
        adapter.scan(outside)
