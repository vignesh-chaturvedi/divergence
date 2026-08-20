"""SARIF release validation rejects malformed uploads with actionable diagnostics."""

from __future__ import annotations

import json

from divergence.core.sarif import (
    SCHEMA,
    _main,
    _repo_relative,
    _split_location,
    check,
    to_sarif,
)
from divergence.core.vocabulary import Channel, Finding


def test_location_helpers_handle_empty_and_outside_checkout_paths(tmp_path):
    assert _split_location("") == ("", None)
    assert _split_location("server.py:not-a-line") == ("", None)
    assert _repo_relative("server.py", None) == "server.py"

    outside = tmp_path / "outside"
    expected = (outside / "server.py").as_posix().lstrip("/")
    assert _repo_relative("server.py", outside) == expected


def test_anchor_locates_prose_findings_without_fabricating_evidence_path():
    finding = Finding(
        sample_id="fleet",
        channel=Channel.RISK,
        message="cross-artifact conflict",
        evidence="16 artifacts participate",
    )

    result = to_sarif([finding], anchor="fleet.yaml")["runs"][0]["results"][0]

    assert result["ruleId"] == "divergence/risk/divergence"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "fleet.yaml"
    assert "region" not in result["locations"][0]["physicalLocation"]


def test_check_handles_unreadable_invalid_and_missing_runs(tmp_path):
    missing = tmp_path / "missing.sarif"
    invalid = tmp_path / "invalid.sarif"
    invalid.write_text("not-json")
    no_runs = tmp_path / "no-runs.sarif"
    no_runs.write_text(json.dumps({"version": "wrong", "$schema": "wrong", "runs": []}))

    assert "unreadable" in check(missing)[0]
    assert "unreadable" in check(invalid)[0]
    problems = check(no_runs)
    assert any("$schema" in problem for problem in problems)
    assert any("version" in problem for problem in problems)
    assert any("runs must be a non-empty array" in problem for problem in problems)


def test_check_reports_every_malformed_run_result_and_location_shape(tmp_path):
    path = tmp_path / "malformed.sarif"
    locations = [
        42,
        {},
        {"physicalLocation": {}},
        {"physicalLocation": {"artifactLocation": {"uri": ""}}},
        {"physicalLocation": {"artifactLocation": {"uri": 123}}},
        {"physicalLocation": {"artifactLocation": {"uri": "https:remote"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "/absolute.py"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "has space.py"}}},
        {"physicalLocation": {"artifactLocation": {"uri": "valid.py"}}},
    ]
    path.write_text(
        json.dumps(
            {
                "$schema": SCHEMA,
                "version": "2.1.0",
                "runs": [
                    "not-an-object",
                    {"tool": [], "results": "not-an-array"},
                    {
                        "tool": {"driver": {"name": "Divergence"}},
                        "results": [
                            "not-an-object",
                            {
                                "ruleId": "",
                                "level": "fatal",
                                "message": [],
                                "locations": "not-an-array",
                            },
                            {
                                "ruleId": "divergence/risk/test",
                                "level": "warning",
                                "message": {"text": "test"},
                                "locations": locations,
                            },
                        ],
                    },
                ],
            }
        )
    )

    problems = check(path)

    expected_fragments = (
        "run must be an object",
        "tool.driver.name",
        "results must be an array",
        "result must be an object",
        "no ruleId",
        "invalid level",
        "message.text",
        "locations must be an array",
        "must be an object",
        "physicalLocation must be an object",
        "artifactLocation must be an object",
        "location with no uri",
        "location uri must be a string",
        "looks like a scheme",
        "is absolute",
        "contains a space",
    )
    for fragment in expected_fragments:
        assert any(fragment in problem for problem in problems), fragment
    assert not any("valid.py" in problem for problem in problems)


def test_sarif_validator_cli_reports_failure_and_success(tmp_path, capsys):
    bad = tmp_path / "bad.sarif"
    bad.write_text("{}")
    assert _main(["--check", str(bad)]) == 1
    failure = capsys.readouterr().out
    assert "problem(s)" in failure and "runs must be" in failure

    good = tmp_path / "good.sarif"
    good.write_text(json.dumps(to_sarif([])))
    assert _main(["--check", str(good)]) == 0
    assert f"{good}: ok" in capsys.readouterr().out
