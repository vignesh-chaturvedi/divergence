"""Adapter orchestration must fail visibly without losing benchmark scope metadata."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import divergence.adapters.base as base
import divergence.adapters.external as external
from divergence.adapters.base import ScannerUnavailable, run_adapter
from divergence.adapters.external import ExternalAdapter
from divergence.bench.models import Kind, Sample, Stratum
from divergence.core.vocabulary import Channel, Finding


def _sample(sample_id: str = "sample", *, kind: Kind = Kind.MCP_SERVER) -> Sample:
    return Sample(
        id=sample_id,
        kind=kind,
        stratum=Stratum.BENIGN_PLAIN,
        language="python",
        rationale="adapter runtime fixture " * 8,
        path=Path("."),
        artifact_path=Path("artifact"),
        malicious=False,
    )


def _external_adapter(*, override=None) -> ExternalAdapter:
    def parse(stdout, sample):
        return [
            Finding(
                sample_id=sample.id,
                channel=Channel.RISK,
                message=json.loads(stdout)["message"],
            )
        ]

    return ExternalAdapter(
        name="fixture",
        homepage="https://example.invalid",
        probe_cmd=["fixture-bin", "--version"],
        scan_cmd=lambda sample: ["fixture-bin", "scan", str(sample.artifact_path)],
        parse=parse,
        install_hint="install fixture-bin",
        probe_override=override,
        provenance_metadata={"package_spec": "fixture@1.0.0"},
    )


def test_registry_rejects_duplicates_and_names_known_adapters(monkeypatch):
    monkeypatch.setattr(base, "registry", {})
    first = _external_adapter()
    second = _external_adapter()

    assert base.register(first) is first
    assert base.get_adapter("fixture") is first
    with pytest.raises(ValueError, match="duplicate adapter name"):
        base.register(second)
    with pytest.raises(KeyError, match="Known: fixture"):
        base.get_adapter("missing")

    monkeypatch.setattr(base, "registry", {})
    with pytest.raises(KeyError, match="none registered"):
        base.get_adapter("missing")


def test_adapter_sort_and_metadata_ignore_invalid_optional_provenance(monkeypatch):
    class Fixture:
        homepage = ""

        def __init__(self, name, kind, provenance):
            self.name = name
            self.kind = kind
            self.provenance = provenance

        def probe(self):
            return "1"

        def scan(self, sample):
            return []

    reference = Fixture("z-reference", "reference", lambda: {"pin": "one"})
    external_adapter = Fixture("a-external", "external", lambda: "invalid")
    monkeypatch.setattr(
        base,
        "registry",
        {reference.name: reference, external_adapter.name: external_adapter},
    )

    assert base.available_adapters() == [reference, external_adapter]
    assert base._metadata(reference)["pin"] == "one"
    assert "pin" not in base._metadata(external_adapter)


def test_runner_marks_prepare_unavailability_as_whole_run_unavailable():
    class Fixture:
        name, homepage, kind, version = "fixture", "", "external", "pinned"

        def probe(self):
            return "1.0"

        def prepare(self, samples):
            raise ScannerUnavailable("rules snapshot missing")

        def scan(self, sample):
            raise AssertionError("scan must not run")

    run = run_adapter(Fixture(), [_sample()])

    assert run.available is False
    assert run.unavailable_reason == "rules snapshot missing"
    assert run.results == {}


def test_runner_marks_unexpected_prepare_crash_unavailable():
    class Fixture:
        name, homepage, kind = "fixture", "", "reference"

        def probe(self):
            return "1.0"

        def prepare(self, samples):
            raise RuntimeError("pre-pass crashed")

        def scan(self, sample):
            return []

    run = run_adapter(Fixture(), [_sample()])

    assert run.available is False
    assert run.unavailable_reason == "prepare failed: RuntimeError: pre-pass crashed"
    assert run.results == {}


def test_runner_scan_unavailability_discards_partial_results():
    class Fixture:
        name, homepage, kind = "fixture", "", "external"

        def probe(self):
            return "1.0"

        def scan(self, sample):
            if sample.id == "second":
                raise ScannerUnavailable("hosted service stopped")
            return []

    run = run_adapter(Fixture(), [_sample("first"), _sample("second")])

    assert run.available is False
    assert run.unavailable_reason == "hosted service stopped"
    assert run.results == {}


def test_runner_records_not_applicable_as_scope_not_error():
    class NotApplicable(Exception):
        pass

    class Fixture:
        name, homepage, kind = "fixture", "", "external"

        def probe(self):
            return "1.0"

        def scan(self, sample):
            raise NotApplicable("skills unsupported")

    run = run_adapter(Fixture(), [_sample(kind=Kind.AGENT_SKILL)])

    assert run.results["sample"].not_applicable is True
    assert run.results["sample"].error is None


def test_external_opt_in_and_provenance(monkeypatch):
    adapter = _external_adapter(override=lambda: "override-version")
    assert adapter.probe() == "override-version"
    assert adapter.provenance() == {
        "probe_command": ["fixture-bin", "--version"],
        "package_spec": "fixture@1.0.0",
    }

    monkeypatch.setenv(external.OPT_IN_ENV, " YES ")
    assert external.external_enabled() is True
    monkeypatch.setenv(external.OPT_IN_ENV, "no")
    assert external.external_enabled() is False


def test_external_probe_requires_opt_in_and_executable(monkeypatch):
    adapter = _external_adapter()
    monkeypatch.setattr(external, "external_enabled", lambda: False)
    with pytest.raises(ScannerUnavailable, match="opt-in"):
        adapter.probe()

    monkeypatch.setattr(external, "external_enabled", lambda: True)
    monkeypatch.setattr(external.shutil, "which", lambda executable: None)
    with pytest.raises(ScannerUnavailable, match="not on PATH.*install fixture-bin"):
        adapter.probe()


@pytest.mark.parametrize(
    "failure",
    [subprocess.TimeoutExpired(["fixture-bin"], 1), OSError("cannot execute")],
)
def test_external_probe_normalises_process_failures(monkeypatch, failure):
    adapter = _external_adapter()
    monkeypatch.setattr(external, "external_enabled", lambda: True)
    monkeypatch.setattr(external.shutil, "which", lambda executable: "/bin/fixture")

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(external.subprocess, "run", fail)
    with pytest.raises(ScannerUnavailable, match="probe failed"):
        adapter.probe()


@pytest.mark.parametrize(
    ("proc", "message"),
    [
        (
            SimpleNamespace(returncode=7, stdout="", stderr="permission denied\nmore"),
            "permission denied",
        ),
        (SimpleNamespace(returncode=7, stdout="", stderr=""), "no output"),
    ],
)
def test_external_probe_exposes_first_diagnostic(monkeypatch, proc, message):
    adapter = _external_adapter()
    monkeypatch.setattr(external, "external_enabled", lambda: True)
    monkeypatch.setattr(external.shutil, "which", lambda executable: "/bin/fixture")
    monkeypatch.setattr(external.subprocess, "run", lambda *args, **kwargs: proc)

    with pytest.raises(ScannerUnavailable, match=message):
        adapter.probe()


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected"),
    [("1.2.3\nextra", "", "1.2.3"), ("", "2.0.0\n", "2.0.0")],
)
def test_external_probe_reads_stdout_or_stderr(monkeypatch, stdout, stderr, expected):
    adapter = _external_adapter()
    monkeypatch.setattr(external, "external_enabled", lambda: True)
    monkeypatch.setattr(external.shutil, "which", lambda executable: "/bin/fixture")
    proc = SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
    monkeypatch.setattr(external.subprocess, "run", lambda *args, **kwargs: proc)
    assert adapter.probe() == expected


def test_external_scan_runs_pinned_command_and_parser(monkeypatch):
    adapter = _external_adapter()
    sample = _sample()
    seen = []

    def fake_run(command, **kwargs):
        seen.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"message": "normalised"}', stderr="")

    monkeypatch.setattr(external.subprocess, "run", fake_run)
    findings = adapter.scan(sample)

    assert seen[0][0] == ["fixture-bin", "scan", "artifact"]
    assert findings[0].message == "normalised"


def test_external_scan_exposes_nonzero_exit_as_an_error(monkeypatch):
    adapter = _external_adapter()
    monkeypatch.setattr(
        external.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=3, stdout="", stderr="scan failed\nmore"
        ),
    )

    with pytest.raises(RuntimeError, match="exited 3.*scan failed"):
        adapter.scan(_sample())


def test_flat_issue_parser_accepts_fallback_shapes_and_skips_junk():
    sample = _sample()
    payload = {
        "findings": [
            "not-an-object",
            {
                "level": "notice",
                "rule": "credential_access",
                "description": "reads a token",
                "evidence": "env:TOKEN",
            },
        ]
    }

    findings = external.parse_flat_json_issues(json.dumps(payload), sample)

    assert len(findings) == 1
    assert findings[0].channel is Channel.POSTURE
    assert findings[0].message == "reads a token"
    assert findings[0].evidence == "env:TOKEN"


def test_sarif_parser_handles_default_fields_and_partial_location():
    sample = _sample()
    payload = {
        "runs": [
            {
                "results": [
                    {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"}}}]},
                    {"message": None},
                ]
            }
        ]
    }

    findings = external.parse_sarif(json.dumps(payload), sample)

    assert len(findings) == 2
    assert findings[0].severity == "warning"
    assert findings[0].evidence == "x.py"
    assert findings[1].evidence == ""


def test_snyk_probe_requires_opt_in_uvx_and_token(monkeypatch):
    monkeypatch.setattr(external, "external_enabled", lambda: False)
    with pytest.raises(ScannerUnavailable, match="opt-in"):
        external._snyk_probe()

    monkeypatch.setattr(external, "external_enabled", lambda: True)
    monkeypatch.setattr(external.shutil, "which", lambda executable: None)
    with pytest.raises(ScannerUnavailable, match="uvx not on PATH"):
        external._snyk_probe()

    monkeypatch.setattr(external.shutil, "which", lambda executable: "/bin/uvx")
    monkeypatch.delenv("SNYK_TOKEN", raising=False)
    with pytest.raises(ScannerUnavailable, match="hosted API"):
        external._snyk_probe()

    monkeypatch.setenv("SNYK_TOKEN", "test-token")
    assert external._snyk_probe() == "snyk-agent-scan 0.6.0 (token present)"
