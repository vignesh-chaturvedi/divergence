"""The v1.1 evidence files remain tied to this exact corpus and release contract."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from divergence.bench.cli import DEFAULT_CORPUS
from divergence.bench.corpus import load_corpus
from divergence.bench.report import BENCHMARK_SCHEMA, corpus_sha256, package_source_sha256

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "benchmarks" / "v1.1"


def _load(name: str) -> dict:
    return json.loads((EVIDENCE / name).read_text())


def _scanners(document: dict) -> dict[str, dict]:
    return {scanner["name"]: scanner for scanner in document["scanners"]}


def _assert_no_available_scanner_errors(document: dict) -> None:
    assert all(
        not scanner["available"] or scanner["errors"] == 0 for scanner in document["scanners"]
    )


def test_frozen_results_match_the_current_corpus_and_truth_counts():
    expected_digest = corpus_sha256(load_corpus(DEFAULT_CORPUS))

    for name in ("static-external.json", "static-dynamic-linux-aarch64.json"):
        document = _load(name)
        assert document["schema"] == BENCHMARK_SCHEMA
        assert document["project"] == {
            "distribution": "divergence-mcp",
            "version": "1.1.0",
            "source_sha256": package_source_sha256(),
        }
        assert set(document["runtime"]["dependencies"]) == {
            "PyYAML",
            "tree-sitter",
            "tree-sitter-bash",
            "tree-sitter-python",
            "tree-sitter-typescript",
        }
        assert document["corpus"]["sha256"] == expected_digest
        assert document["corpus"]["total"] == 110
        assert document["corpus"]["malicious"] == 50
        assert document["corpus"]["benign"] == 60
        _assert_no_available_scanner_errors(document)


def test_frozen_static_and_external_raw_counts_are_not_hand_rounded():
    scanners = _scanners(_load("static-external.json"))

    assert (
        scanners["divergence"]["true_positives"],
        scanners["divergence"]["false_positives"],
    ) == (
        27,
        0,
    )
    assert (
        scanners["divergence+fleet"]["true_positives"],
        scanners["divergence+fleet"]["false_positives"],
    ) == (27, 0)
    assert (scanners["semgrep"]["true_positives"], scanners["semgrep"]["false_positives"]) == (
        30,
        7,
    )
    assert scanners["semgrep"]["estimates"]["fpr_on_traps"]["numerator"] == 5
    assert scanners["mcp-shield"]["estimates"]["recall"]["denominator"] == 33
    assert scanners["snyk-agent-scan"]["available"] is False
    assert "SNYK_TOKEN" in scanners["snyk-agent-scan"]["unavailable_reason"]


def test_semgrep_snapshot_and_release_json_are_checkout_independent():
    lock = yaml.safe_load((EVIDENCE / "semgrep-rules.lock.yaml").read_text())
    document = _load("static-external.json")
    semgrep = _scanners(document)["semgrep"]

    assert semgrep["provenance"]["package_spec"] == lock["scanner"]
    assert semgrep["provenance"]["ruleset_sha256"] == lock["snapshot_sha256"]
    assert semgrep["provenance"]["ruleset"] == "semgrep-rules-snapshot"
    assert "/Users/" not in json.dumps(document)


def test_frozen_dynamic_row_is_additive_and_carries_per_sample_coverage():
    scanners = _scanners(_load("static-dynamic-linux-aarch64.json"))
    static = scanners["divergence"]
    dynamic = scanners["divergence+dynamic"]
    coverage = dynamic["provenance"]["coverage"]

    assert dynamic["true_positives"] == 49
    assert dynamic["false_positives"] == 0
    assert dynamic["true_positives"] >= static["true_positives"]
    assert len(coverage) == 110
    assert sum(item["ran"] for item in coverage.values()) == 83
    assert all("limitations" in item for item in coverage.values())


def test_frozen_linux_sandbox_evidence_proves_the_required_controls():
    probe = _load("sandbox-probe-linux-aarch64.json")
    gate = (EVIDENCE / "sandbox-gate-linux-aarch64.txt").read_text()

    assert probe["schema"] == "divergence.sandbox.probe/1"
    assert probe["runner_version"] == "1.1.0"
    assert probe["platform"] == "linux"
    assert probe["available"] is True
    assert probe["unprivileged_identity"] is True
    assert probe["landlock_abi"] >= probe["required_landlock_abi"] == 4
    assert probe["seccomp_available"] is True
    assert "payloads caught      24/25  (96%)" in gate
    assert "gate (>= 50%)        PASS" in gate
    assert "control stayed clean yes" in gate
