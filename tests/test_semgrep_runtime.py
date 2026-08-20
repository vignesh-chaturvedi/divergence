"""Pinned Semgrep execution and SARIF attribution remain reproducible and fail closed."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import divergence.adapters.semgrep_scanner as semgrep
from divergence.adapters.base import ScannerUnavailable
from divergence.bench.models import Kind, Sample, Stratum
from divergence.core.vocabulary import AttackClass, Channel


def _sample(sample_id: str, artifact: Path) -> Sample:
    return Sample(
        id=sample_id,
        kind=Kind.MCP_SERVER,
        stratum=Stratum.BENIGN_PLAIN,
        language="python",
        rationale="semgrep runtime fixture " * 8,
        path=artifact.parent,
        artifact_path=artifact,
        malicious=False,
    )


def test_split_by_sample_uses_longest_root_and_ignores_unlocated_results(tmp_path):
    outer = tmp_path / "outer"
    inner = outer / "inner"
    roots = {"outer": outer, "inner": inner}
    located = {
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(inner / "x.py")}}}]
    }
    missing_uri = {"locations": [{"physicalLocation": {}}]}
    sarif = {"runs": [{"results": [{}, missing_uri, located]}]}

    assert semgrep.split_by_sample(sarif, roots) == {"inner": [located]}


def test_provenance_names_required_snapshot_even_when_unconfigured(monkeypatch):
    monkeypatch.delenv(semgrep.RULESET_ENV, raising=False)
    provenance = semgrep.SemgrepAdapter().provenance()

    assert provenance["scanner_command"][:3] == ["uvx", semgrep.SEMGREP_SPEC, "scan"]
    assert provenance["ruleset"] is None
    assert provenance["ruleset_sha256"] is None
    assert provenance["ruleset_mutable"] is False


def test_probe_requires_opt_in_uvx_and_existing_local_rules(monkeypatch, tmp_path):
    adapter = semgrep.SemgrepAdapter()
    monkeypatch.setattr(semgrep, "external_enabled", lambda: False)
    with pytest.raises(ScannerUnavailable, match="opt-in"):
        adapter.probe()

    monkeypatch.setattr(semgrep, "external_enabled", lambda: True)
    monkeypatch.setattr(semgrep.shutil, "which", lambda executable: None)
    with pytest.raises(ScannerUnavailable, match="uvx.*PATH"):
        adapter.probe()

    monkeypatch.setattr(semgrep.shutil, "which", lambda executable: "/bin/uvx")
    monkeypatch.delenv(semgrep.RULESET_ENV, raising=False)
    with pytest.raises(ScannerUnavailable, match="no pinned rules snapshot"):
        adapter.probe()

    missing = tmp_path / "missing-rules"
    monkeypatch.setenv(semgrep.RULESET_ENV, str(missing))
    with pytest.raises(ScannerUnavailable, match="does not exist"):
        adapter.probe()


def test_probe_reports_nonzero_pinned_semgrep_exit(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    adapter = semgrep.SemgrepAdapter()
    monkeypatch.setattr(semgrep, "external_enabled", lambda: True)
    monkeypatch.setattr(semgrep.shutil, "which", lambda executable: "/bin/uvx")
    monkeypatch.setenv(semgrep.RULESET_ENV, str(rules))
    monkeypatch.setattr(
        semgrep.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=4, stdout="", stderr="failed"),
    )

    with pytest.raises(ScannerUnavailable, match="probe exited 4"):
        adapter.probe()


def test_prepare_requires_probe_but_empty_corpus_is_a_noop(tmp_path):
    adapter = semgrep.SemgrepAdapter()
    adapter.prepare([])
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    with pytest.raises(ScannerUnavailable, match="not configured during probe"):
        adapter.prepare([_sample("sample", artifact)])


def test_prepare_runs_one_pinned_scan_and_attributes_sarif(monkeypatch, tmp_path):
    corpus = tmp_path / "corpus"
    first_root = corpus / "first"
    second_root = corpus / "second"
    first_root.mkdir(parents=True)
    second_root.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    first = _sample("first", first_root)
    second = _sample("second", second_root)
    result = {
        "ruleId": "security.command_injection",
        "level": "error",
        "message": {"text": "shell invocation"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(first_root / "server.py")},
                    "region": {"startLine": 9},
                }
            }
        ],
    }
    seen = []

    def fake_run(command, **kwargs):
        seen.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"runs": [{"results": [result]}]}),
            stderr="",
        )

    monkeypatch.setattr(semgrep.subprocess, "run", fake_run)
    adapter = semgrep.SemgrepAdapter()
    adapter._ruleset = rules
    adapter.prepare([first, second])

    assert seen == [
        [
            "uvx",
            semgrep.SEMGREP_SPEC,
            "scan",
            "--sarif",
            "--quiet",
            "--no-git-ignore",
            "--config",
            str(rules),
            str(corpus),
        ]
    ]
    findings = adapter.scan(first)
    assert len(findings) == 1
    assert findings[0].attack_class is AttackClass.UNDECLARED_EXEC
    assert findings[0].channel is Channel.RISK
    assert findings[0].evidence == "semgrep:9"
    assert adapter.scan(second) == []


def test_prepare_rejects_invalid_sarif(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setattr(
        semgrep.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="not-json", stderr=""),
    )
    adapter = semgrep.SemgrepAdapter()
    adapter._ruleset = rules
    sample = _sample("sample", artifact)

    with pytest.raises(ScannerUnavailable, match="invalid SARIF JSON"):
        adapter.prepare([sample])


def test_prepare_rejects_nonzero_scan_exit(monkeypatch, tmp_path):
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setattr(
        semgrep.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=7, stdout="", stderr="invalid rules snapshot\nmore"
        ),
    )
    adapter = semgrep.SemgrepAdapter()
    adapter._ruleset = rules

    with pytest.raises(ScannerUnavailable, match="exited 7.*invalid rules snapshot"):
        adapter.prepare([_sample("sample", artifact)])


def test_scan_preserves_posture_and_evidence_without_a_line(tmp_path):
    sample = _sample("sample", tmp_path)
    adapter = semgrep.SemgrepAdapter()
    adapter._results = {
        "sample": [
            {
                "ruleId": "style.prompt_injection",
                "level": "note",
                "message": {"text": "x" * 250},
                "locations": [],
            }
        ]
    }

    finding = adapter.scan(sample)[0]

    assert finding.channel is Channel.POSTURE
    assert finding.attack_class is AttackClass.DESCRIPTION_POISONING
    assert finding.evidence == "semgrep"
    assert len(finding.message) == 200
