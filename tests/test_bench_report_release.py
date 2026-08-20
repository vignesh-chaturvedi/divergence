"""Release-facing benchmark renderers preserve uncertainty, scope, and provenance."""

from __future__ import annotations

import json
from pathlib import Path

from divergence.bench.metrics import Score, StratumScore
from divergence.bench.models import AttackClass, Kind, Sample, Stratum, TrapFamily
from divergence.bench.report import (
    _bar,
    attack_class_table,
    comparison_table,
    corpus_sha256,
    corpus_summary,
    estimate,
    estimate_text,
    markdown_table,
    package_source_sha256,
    pct,
    per_stratum_table,
    to_json,
    trap_family_table,
)


def _sample(
    sample_id: str,
    *,
    kind: Kind = Kind.MCP_SERVER,
    stratum: Stratum = Stratum.MALICIOUS,
    malicious: bool = True,
    path: Path = Path("."),
    artifact_path: Path = Path("."),
) -> Sample:
    return Sample(
        id=sample_id,
        kind=kind,
        stratum=stratum,
        language="python",
        rationale="release renderer fixture " * 8,
        path=path,
        artifact_path=artifact_path,
        malicious=malicious,
    )


def _complete_score() -> Score:
    return Score(
        scanner="complete",
        version="1.2.3",
        scored=5,
        true_positives=1,
        false_negatives=1,
        false_positives=1,
        true_negatives=2,
        correctly_attributed=1,
        total_risk_findings=2,
        total_posture_findings=3,
        duration_s=1.25,
        metadata={"package_spec": "scanner@1.2.3"},
        by_stratum={
            Stratum.MALICIOUS: StratumScore(Stratum.MALICIOUS, total=2, flagged=1),
            Stratum.FP_TRAP: StratumScore(Stratum.FP_TRAP, total=2, flagged=1),
            Stratum.BENIGN_PLAIN: StratumScore(Stratum.BENIGN_PLAIN, total=1, flagged=0),
        },
        recall_by_attack_class={AttackClass.UNDECLARED_NETWORK: (1, 2)},
        fpr_by_trap_family={TrapFamily.WILDCARD_PERMISSIONS: (1, 2)},
    )


def test_scalar_rendering_never_turns_unknown_into_zero():
    assert pct(None) == "—"
    assert pct(0.125) == "12.5%"
    assert estimate(0, 0) == {
        "numerator": 0,
        "denominator": 0,
        "rate": None,
        "wilson95": None,
    }
    assert estimate_text(0, 0) == "—"
    assert "2/5 (40.0%; 95% CI" in estimate_text(2, 5)
    assert _bar(None) == " " * 12
    assert "█" in _bar(0.5)
    assert "█" in _bar(0.5, invert=True)


def test_console_and_markdown_tables_distinguish_unavailable_scanners():
    available = _complete_score()
    unavailable = Score(
        scanner="offline",
        version="9.9.9",
        available=False,
        unavailable_reason="token deliberately absent",
    )

    console = comparison_table([available, unavailable])
    markdown = markdown_table([available, unavailable])

    assert "complete" in console and "50.0%" in console
    assert "offline" in console and "not run" in console
    assert "**1/2 (50.0%; 95% CI" in markdown
    assert "| `offline` | `9.9.9` | not run |" in markdown


def test_detail_tables_cover_missing_cells_without_manufacturing_rates():
    complete = _complete_score()
    alternate = Score(
        scanner="alternate",
        by_stratum={Stratum.OBFUSCATED: StratumScore(Stratum.OBFUSCATED, total=1, flagged=0)},
        recall_by_attack_class={AttackClass.SHADOWING: (0, 1)},
        fpr_by_trap_family={TrapFamily.IMPERATIVE_LANGUAGE: (0, 1)},
    )
    unavailable = Score(scanner="offline", available=False)

    assert per_stratum_table([unavailable]) == ""
    assert trap_family_table([unavailable, Score(scanner="empty")]) == ""
    assert attack_class_table([unavailable, Score(scanner="empty")]) == ""

    strata = per_stratum_table([complete, alternate])
    traps = trap_family_table([complete, alternate])
    attacks = attack_class_table([complete, alternate])
    assert "malicious" in strata and "obfuscated" in strata and "—" in strata
    assert "wildcard_permissions" in traps and "imperative_language" in traps
    assert "1/2 50.0%" in traps and "—" in traps
    assert "undeclared_network" in attacks and "shadowing" in attacks
    assert "1/2" in attacks and "—" in attacks


def test_corpus_summary_reports_kind_and_explicit_truth():
    samples = [
        _sample("risk"),
        _sample(
            "control",
            kind=Kind.AGENT_SKILL,
            stratum=Stratum.OBFUSCATED,
            malicious=False,
        ),
    ]

    rendered = corpus_summary(samples)

    assert "malicious" in rendered and "1 servers, 0 skills" in rendered
    assert "obfuscated" in rendered and "0 servers, 1 skills" in rendered
    assert "1 risk-positive, 1 benign/control" in rendered


def test_corpus_digest_covers_dataset_manifest_and_artifact_bytes(tmp_path):
    dataset = tmp_path / "dataset"
    sample_root = dataset / "samples" / "server" / "sample-1"
    artifact = sample_root / "artifact"
    artifact.mkdir(parents=True)
    (dataset / "dataset.yaml").write_text("version: 1\n")
    design = dataset / "obfuscated-design.yaml"
    design.write_text("status: frozen\n")
    (sample_root / "sample.yaml").write_text("id: sample-1\n")
    implementation = artifact / "server.py"
    implementation.write_text("print('one')\n")
    sample = _sample("sample-1", path=sample_root, artifact_path=artifact)

    first = corpus_sha256([sample])
    implementation.write_text("print('two')\n")
    second = corpus_sha256([sample])
    design.write_text("status: reviewed\n")
    third = corpus_sha256([sample])

    assert corpus_sha256([]) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert len(first) == 64 and first != second and second != third


def test_package_source_digest_is_path_independent_and_content_bound(tmp_path):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    for root in (first_root, second_root):
        (root / "nested").mkdir(parents=True)
        (root / "__init__.py").write_text("VERSION = 1\n")
        (root / "nested" / "module.py").write_text("VALUE = 2\n")
        (root / "data" / "corpus").mkdir(parents=True)
        (root / "data" / "corpus" / "fixture.py").write_text("ARTIFACT = 'ignored'\n")

    first = package_source_sha256(first_root)
    assert first == package_source_sha256(second_root)

    (second_root / "data" / "corpus" / "fixture.py").write_text("ARTIFACT = 'changed'\n")
    assert first == package_source_sha256(second_root)

    (second_root / "nested" / "module.py").write_text("VALUE = 3\n")
    assert first != package_source_sha256(second_root)


def test_json_report_serialises_detail_maps_and_unavailable_rows(tmp_path):
    sample_root = tmp_path / "lonely"
    artifact = sample_root / "artifact"
    artifact.mkdir(parents=True)
    (sample_root / "sample.yaml").write_text("id: lonely\n")
    sample = _sample("lonely", path=sample_root, artifact_path=artifact)
    score = _complete_score()
    unavailable = Score(scanner="offline", available=False, unavailable_reason="no token")

    payload = json.loads(to_json([sample], [score, unavailable]))

    rendered = payload["scanners"][0]
    assert rendered["provenance"] == {"package_spec": "scanner@1.2.3"}
    assert rendered["by_stratum"]["fp_trap"] == {"total": 2, "flagged": 1}
    assert rendered["recall_by_attack_class"]["undeclared_network"] == {
        "hits": 1,
        "total": 2,
    }
    assert rendered["fpr_by_trap_family"]["wildcard_permissions"] == {
        "hits": 1,
        "total": 2,
    }
    assert payload["scanners"][1]["available"] is False
