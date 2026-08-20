"""End-to-end tests through the shipped command line.

These exist because of a bug the whole suite missed: `divergence scan` ran the
declared-interface checks and never called the divergence engine, from P3 until the v1
checkpoint. Every benchmark number was correct and the shipped command was missing the
project's headline capability, because unit tests called the analyzers directly and the
benchmark went through the adapter. Nothing exercised the path a user actually runs.

The rule these encode: **if the benchmark says an artifact is caught, the CLI must catch
it too.**
"""

import json
from pathlib import Path

import pytest

from divergence.cli import main

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "samples"
FLEET = Path(__file__).resolve().parent.parent / "corpus" / "fleets" / "installed-config"


def _run(argv, capsys) -> tuple[int, str]:
    code = main(argv)
    return code, capsys.readouterr().out


def test_scan_reports_the_same_verdict_as_the_benchmark(samples, capsys):
    """The guard against CLI and adapter drifting apart again.

    Every malicious sample the benchmark adapter flags must also be flagged by the
    command a user runs.
    """
    from divergence.adapters.divergence import DivergenceScanner
    from divergence.core.acquire import acquire
    from divergence.core.vocabulary import Channel

    scanner = DivergenceScanner()
    mismatches = []

    for sample in samples:
        if not sample.is_positive:
            continue

        # Rug-pull samples ship two version snapshots and are caught by the ledger, which
        # the benchmark drives by approving v1 and diffing v2 in one pass. A single CLI
        # invocation cannot do that by design — a real user approves at time T and
        # rescans later. That flow has its own test below; this one would be comparing
        # different operations.
        if acquire(sample.artifact_path).snapshots:
            continue

        adapter_flagged = any(f.channel is Channel.RISK for f in scanner.scan(sample))
        if not adapter_flagged:
            continue

        _, out = _run(["scan", str(sample.artifact_path)], capsys)
        if "RISK — none" in out:
            mismatches.append(sample.id)

    assert mismatches == [], (
        "the CLI missed artifacts the benchmark reports as caught: " + ", ".join(mismatches)
    )


def test_scan_stays_silent_on_traps(samples, capsys):
    offenders = []
    for sample in samples:
        if sample.is_positive:
            continue
        _, out = _run(["scan", str(sample.artifact_path)], capsys)
        if "RISK — none" not in out:
            offenders.append(sample.id)
    assert offenders == [], "the CLI flagged benign artifacts: " + ", ".join(offenders)


def test_inspect_prints_the_declared_surface(capsys):
    target = (
        CORPUS / "mcp_server" / "malicious" / "mcp-mal-008-readonly-annotation-lie" / "artifact"
    )
    code, out = _run(["inspect", str(target)], capsys)
    assert code == 0
    assert "get_config" in out
    assert "readOnlyHint" in out


def test_scan_writes_valid_sarif(tmp_path, capsys):
    target = (
        CORPUS / "mcp_server" / "malicious" / "mcp-mal-008-readonly-annotation-lie" / "artifact"
    )
    out_file = tmp_path / "r.sarif"
    _run(["scan", str(target), "--sarif", str(out_file)], capsys)

    doc = json.loads(out_file.read_text())
    assert doc["version"] == "2.1.0"
    assert any(r["level"] == "error" for r in doc["runs"][0]["results"])


def test_fail_on_risk_sets_a_non_zero_exit(capsys):
    target = (
        CORPUS / "mcp_server" / "malicious" / "mcp-mal-008-readonly-annotation-lie" / "artifact"
    )
    assert _run(["--fail-on-risk", "scan", str(target)], capsys)[0] == 1


def test_clean_artifact_exits_zero_even_with_fail_on_risk(capsys):
    target = CORPUS / "mcp_server" / "fp_trap" / "trap-priv-001-shell-executor" / "artifact"
    assert _run(["--fail-on-risk", "scan", str(target)], capsys)[0] == 0


def test_posture_alone_never_fails_a_build(capsys):
    """A build that fails on capability recreates the alert fatigue this removes."""
    target = (
        CORPUS / "agent_skill" / "fp_trap" / "trap-wild-001-general-assistant-star" / "artifact"
    )
    code, out = _run(["--fail-on-risk", "scan", str(target)], capsys)
    assert code == 0
    assert "POSTURE" in out


def test_fleet_command_runs_and_writes_sarif(tmp_path, capsys):
    out_file = tmp_path / "f.sarif"
    code, out = _run(
        ["--allow-partial", "fleet", str(FLEET / "fleet.yaml"), "--sarif", str(out_file)],
        capsys,
    )
    assert code == 0
    assert "shadowing" in out
    assert json.loads(out_file.read_text())["version"] == "2.1.0"


def test_approve_then_diff_detects_a_mutation(tmp_path, capsys):
    ledger = tmp_path / "ledger.db"
    sample = CORPUS / "mcp_server" / "malicious" / "mcp-mal-007-formatter-rug-pull" / "artifact"

    _run(["--ledger", str(ledger), "approve", str(sample / "snapshots" / "v1.2.0")], capsys)

    # The later snapshot resolves under the same name, so the ledger compares them.
    import shutil

    staged = tmp_path / "v1.2.0"
    shutil.copytree(sample / "snapshots" / "v1.3.0", staged)

    code, out = _run(["--ledger", str(ledger), "diff", str(staged)], capsys)
    assert "mutated after approval" in out


def test_unknown_target_fails_loudly(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["scan", "/nonexistent/path/xyz"])
    assert exc.value.code == 2


def test_version_is_exposed(capsys):
    from divergence import __version__

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_unresolved_config_is_partial_by_default_and_can_be_accepted(tmp_path, capsys):
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {"remote": {"command": "npx", "args": ["pkg"]}}}))
    assert _run(["scan", str(config)], capsys)[0] == 2
    assert _run(["--allow-partial", "scan", str(config)], capsys)[0] == 0


def test_json_scan_output_is_structured_and_terminal_safe(tmp_path, capsys):
    target = tmp_path / "artifact"
    target.mkdir()
    (target / "manifest.json").write_text(
        json.dumps({"tools": [{"name": "bad\x1b[31m", "description": "Return a value."}]})
    )
    code, output = _run(["scan", str(target), "--json"], capsys)
    result = json.loads(output)
    assert code == 0
    assert result["status"] == "complete"
    assert "\x1b" not in output
    assert "\\x1b" in output


def test_incomplete_exit_takes_precedence_over_fail_on_risk(tmp_path, capsys):
    malicious = (
        CORPUS / "mcp_server" / "malicious" / "mcp-mal-008-readonly-annotation-lie" / "artifact"
    )
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "liar": {"command": "python", "args": [str(malicious / "server.py")]},
                    "remote": {"command": "npx", "args": ["package"]},
                }
            }
        )
    )
    assert _run(["--fail-on-risk", "scan", str(config)], capsys)[0] == 2
    assert (
        _run(
            ["--allow-partial", "--fail-on-risk", "scan", str(config)],
            capsys,
        )[0]
        == 1
    )
