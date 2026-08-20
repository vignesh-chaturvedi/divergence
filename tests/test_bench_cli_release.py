"""Release-critical `divergence-bench` exit codes and artifact-writing behavior."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import divergence.bench.cli as cli
import divergence.bench.sandbox_gate as sandbox_gate
from divergence.bench.capability_score import CapabilityReport
from divergence.bench.corpus import CorpusError
from divergence.bench.models import (
    AttackClass,
    Kind,
    Sample,
    Stratum,
    TrapFamily,
)


def _sample(
    sample_id: str,
    *,
    attack_classes=(),
    trap_families=(),
) -> Sample:
    return Sample(
        id=sample_id,
        kind=Kind.MCP_SERVER,
        stratum=Stratum.MALICIOUS,
        language="python",
        rationale="benchmark CLI fixture " * 8,
        path=Path("."),
        artifact_path=Path("."),
        malicious=True,
        attack_classes=attack_classes,
        trap_families=trap_families,
    )


def test_load_translates_corpus_errors_to_cli_exit(monkeypatch, capsys):
    expected = [_sample("ok")]
    monkeypatch.setattr(cli, "load_corpus", lambda root: expected)
    assert cli._load(Path("ok")) is expected

    def fail(root):
        raise CorpusError("manifest truth is invalid")

    monkeypatch.setattr(cli, "load_corpus", fail)
    with pytest.raises(SystemExit) as exc:
        cli._load(Path("bad"))
    assert exc.value.code == 2
    assert "corpus error: manifest truth is invalid" in capsys.readouterr().err


def test_validate_reports_violations_and_target_shortfalls(monkeypatch, capsys):
    samples = [_sample("one")]
    monkeypatch.setattr(cli, "_load", lambda root: samples)
    monkeypatch.setattr(cli.report, "corpus_summary", lambda items: "summary")
    monkeypatch.setattr(cli, "validate", lambda items: ["one: unsafe destination"])

    args = SimpleNamespace(corpus=Path("."), check_p0_target=False)
    assert cli.cmd_validate(args) == 1
    assert "1 violation(s)" in capsys.readouterr().err

    monkeypatch.setattr(cli, "validate", lambda items: [])
    args.check_p0_target = True
    monkeypatch.setattr(cli, "counts_by_stratum", lambda items: {Stratum.MALICIOUS: 24})
    assert cli.cmd_validate(args) == 1
    error = capsys.readouterr().err
    assert "P0 target not yet met" in error
    assert "malicious: 24/25 (1 short)" in error


def test_validate_accepts_clean_corpus_with_and_without_p0_gate(monkeypatch, capsys):
    samples = [_sample("one")]
    monkeypatch.setattr(cli, "_load", lambda root: samples)
    monkeypatch.setattr(cli, "validate", lambda items: [])
    monkeypatch.setattr(cli.report, "corpus_summary", lambda items: "summary")
    args = SimpleNamespace(corpus=Path("."), check_p0_target=False)
    assert cli.cmd_validate(args) == 0

    args.check_p0_target = True
    monkeypatch.setattr(cli, "counts_by_stratum", lambda items: dict(cli.P0_TARGET))
    assert cli.cmd_validate(args) == 0
    assert "P0 corpus target met" in capsys.readouterr().out


def test_describe_renders_attack_trap_and_unclassified_samples(monkeypatch, capsys):
    samples = [
        _sample("attack", attack_classes=(AttackClass.UNDECLARED_NETWORK,)),
        _sample("trap", trap_families=(TrapFamily.IMPERATIVE_LANGUAGE,)),
        _sample("plain"),
    ]
    monkeypatch.setattr(cli, "_load", lambda root: samples)
    monkeypatch.setattr(cli.report, "corpus_summary", lambda items: "summary")

    assert cli.cmd_describe(SimpleNamespace(corpus=Path("."))) == 0

    output = capsys.readouterr().out
    assert "undeclared_network" in output
    assert "imperative_language" in output
    assert "plain" in output and "—" in output


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (CapabilityReport(), 2),
        (CapabilityReport(samples_scored=1, true_positives=1), 0),
        (CapabilityReport(samples_scored=1, false_positives=1), 1),
    ],
)
def test_capability_gate_exit_codes(monkeypatch, capsys, report, expected):
    monkeypatch.setattr(cli, "_load", lambda root: [_sample("one")])
    monkeypatch.setattr(cli, "score_capabilities", lambda samples: report)
    monkeypatch.setattr(cli, "render_capabilities", lambda value: "capability report")

    assert cli.cmd_capabilities(SimpleNamespace(corpus=Path("."))) == expected
    captured = capsys.readouterr()
    if report.samples_scored:
        assert "capability report" in captured.out
    else:
        assert "no samples carry verified" in captured.err


@pytest.mark.parametrize(
    ("gate", "required", "expected"),
    [
        (SimpleNamespace(available=False, catch_rate=None, control_clean=False), False, 0),
        (SimpleNamespace(available=False, catch_rate=None, control_clean=False), True, 2),
        (SimpleNamespace(available=True, catch_rate=None, control_clean=True), True, 1),
        (SimpleNamespace(available=True, catch_rate=0.49, control_clean=True), True, 1),
        (SimpleNamespace(available=True, catch_rate=0.75, control_clean=False), True, 1),
        (SimpleNamespace(available=True, catch_rate=0.5, control_clean=True), True, 0),
    ],
)
def test_sandbox_gate_exit_codes_without_executing_artifacts(
    monkeypatch, capsys, gate, required, expected
):
    monkeypatch.setattr(cli, "_load", lambda root: [_sample("one")])
    monkeypatch.setattr(sandbox_gate, "run_gate", lambda samples, timeout: gate)
    monkeypatch.setattr(sandbox_gate, "render", lambda report: "gate report")
    args = SimpleNamespace(corpus=Path("."), timeout=12, require_available=required)

    assert cli.cmd_sandbox_gate(args) == expected
    assert "gate report" in capsys.readouterr().out


def test_bench_rejects_dirty_corpus_unless_explicitly_overridden(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_load", lambda root: [_sample("one")])
    monkeypatch.setattr(cli, "validate", lambda samples: ["bad manifest"])
    args = SimpleNamespace(
        corpus=Path("."),
        ignore_violations=False,
        scanner=None,
        detail=False,
        markdown=None,
        json=None,
    )

    assert cli.cmd_bench(args) == 2
    assert "run `validate` first" in capsys.readouterr().err


def test_bench_selected_scanners_write_generated_json_and_markdown(monkeypatch, capsys, tmp_path):
    samples = [_sample("one")]
    adapter = object()
    run = object()
    scores = [object()]
    monkeypatch.setattr(cli, "_load", lambda root: samples)
    monkeypatch.setattr(cli, "validate", lambda items: ["ignored"])
    monkeypatch.setattr(cli, "get_adapter", lambda name: adapter)
    monkeypatch.setattr(cli, "run_adapter", lambda selected, items: run)
    monkeypatch.setattr(cli, "score_all", lambda items, runs: scores)
    monkeypatch.setattr(cli.report, "corpus_summary", lambda items: "corpus")
    monkeypatch.setattr(cli.report, "comparison_table", lambda items: "comparison")
    monkeypatch.setattr(cli.report, "per_stratum_table", lambda items: "strata")
    monkeypatch.setattr(cli.report, "trap_family_table", lambda items: "traps")
    monkeypatch.setattr(cli.report, "attack_class_table", lambda items: "attacks")
    monkeypatch.setattr(cli.report, "markdown_table", lambda items: "generated markdown")
    monkeypatch.setattr(cli.report, "to_json", lambda items, values: '{"generated": true}\n')
    markdown = tmp_path / "nested" / "bench.md"
    output_json = tmp_path / "nested" / "bench.json"
    args = SimpleNamespace(
        corpus=Path("."),
        ignore_violations=True,
        scanner=["selected"],
        detail=True,
        markdown=markdown,
        json=output_json,
    )

    assert cli.cmd_bench(args) == 0

    assert markdown.read_text() == "generated markdown\n"
    assert output_json.read_text() == '{"generated": true}\n'
    rendered = capsys.readouterr().out
    for section in ("corpus", "comparison", "strata", "traps", "attacks"):
        assert section in rendered


def test_bench_uses_full_roster_and_skips_empty_detail_sections(monkeypatch, capsys):
    samples = [_sample("one")]
    adapters = [object(), object()]
    monkeypatch.setattr(cli, "_load", lambda root: samples)
    monkeypatch.setattr(cli, "validate", lambda items: [])
    monkeypatch.setattr(cli, "available_adapters", lambda: adapters)
    monkeypatch.setattr(cli, "run_adapter", lambda adapter, items: adapter)
    monkeypatch.setattr(cli, "score_all", lambda items, runs: runs)
    monkeypatch.setattr(cli.report, "corpus_summary", lambda items: "corpus")
    monkeypatch.setattr(cli.report, "comparison_table", lambda items: "comparison")
    monkeypatch.setattr(cli.report, "per_stratum_table", lambda items: "")
    monkeypatch.setattr(cli.report, "trap_family_table", lambda items: "")
    monkeypatch.setattr(cli.report, "attack_class_table", lambda items: "")
    args = SimpleNamespace(
        corpus=Path("."),
        ignore_violations=False,
        scanner=None,
        detail=True,
        markdown=None,
        json=None,
    )

    assert cli.cmd_bench(args) == 0
    assert "comparison" in capsys.readouterr().out


def test_bench_fails_visibly_when_an_available_scanner_has_errors(monkeypatch, capsys):
    samples = [_sample("one")]
    score = SimpleNamespace(scanner="broken", available=True, errors=1)
    monkeypatch.setattr(cli, "_load", lambda root: samples)
    monkeypatch.setattr(cli, "validate", lambda items: [])
    monkeypatch.setattr(cli, "available_adapters", lambda: [object()])
    monkeypatch.setattr(cli, "run_adapter", lambda adapter, items: object())
    monkeypatch.setattr(cli, "score_all", lambda items, runs: [score])
    monkeypatch.setattr(cli.report, "corpus_summary", lambda items: "corpus")
    monkeypatch.setattr(cli.report, "comparison_table", lambda items: "comparison")
    monkeypatch.setattr(cli.report, "per_stratum_table", lambda items: "")
    args = SimpleNamespace(
        corpus=Path("."),
        ignore_violations=False,
        scanner=None,
        detail=False,
        markdown=None,
        json=None,
        allow_errors=False,
    )

    assert cli.cmd_bench(args) == 1
    assert "benchmark incomplete" in capsys.readouterr().err

    args.allow_errors = True
    assert cli.cmd_bench(args) == 0


def test_main_builds_parser_and_routes_global_corpus_before_verb(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(cli, "cmd_describe", lambda args: seen.append(args.corpus) or 9)

    assert cli.main(["--corpus", str(tmp_path), "describe"]) == 9
    assert seen == [tmp_path]

    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2
