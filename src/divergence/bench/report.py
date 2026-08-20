"""Rendering the baseline comparison table.

The column order is the argument. FPR-on-traps sits immediately after the scanner name,
before precision, recall or F1, because a reader who stops after two columns should
still have seen the number that matters.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
from pathlib import Path

from divergence import __version__
from divergence.bench.metrics import Score, wilson95
from divergence.bench.models import Sample, Stratum

BAR_WIDTH = 12
BENCHMARK_SCHEMA = "divergence-benchmark/v1"
DATASET_ID = "divergence-corpus-v1.1"
RUNTIME_DISTRIBUTIONS = (
    "PyYAML",
    "tree-sitter",
    "tree-sitter-bash",
    "tree-sitter-python",
    "tree-sitter-typescript",
)


def pct(value: float | None) -> str:
    """Undefined must not render as zero — that would read as a perfect score."""
    return "—" if value is None else f"{value * 100:.1f}%"


def estimate(successes: int, total: int) -> dict:
    interval = wilson95(successes, total)
    return {
        "numerator": successes,
        "denominator": total,
        "rate": successes / total if total else None,
        "wilson95": (None if interval is None else {"low": interval[0], "high": interval[1]}),
    }


def estimate_text(successes: int, total: int) -> str:
    interval = wilson95(successes, total)
    if not total or interval is None:
        return "—"
    return (
        f"{successes}/{total} ({successes / total * 100:.1f}%; "
        f"95% CI {interval[0] * 100:.1f}–{interval[1] * 100:.1f}%)"
    )


def _bar(value: float | None, invert: bool = False) -> str:
    """A coarse visual for scanning a column quickly. `invert` means lower is better."""
    if value is None:
        return " " * BAR_WIDTH
    filled = round(value * BAR_WIDTH)
    glyph = "█"
    if invert:
        # For FPR, a full bar is a bad result — show it as such.
        return (glyph * filled).ljust(BAR_WIDTH, "·")
    return (glyph * filled).ljust(BAR_WIDTH, "·")


def corpus_summary(samples: list[Sample]) -> str:
    lines = ["Corpus", "──────"]
    total = len(samples)
    for stratum in Stratum:
        count = sum(1 for s in samples if s.stratum is stratum)
        if not count:
            continue
        servers = sum(1 for s in samples if s.stratum is stratum and s.kind.value == "mcp_server")
        skills = count - servers
        lines.append(f"  {stratum.value:<14} {count:>4}   ({servers} servers, {skills} skills)")
    lines.append(f"  {'total':<14} {total:>4}")
    positives = sum(1 for s in samples if s.is_positive)
    lines.append(
        f"  {'truth labels':<14} {positives} risk-positive, {total - positives} benign/control"
    )
    return "\n".join(lines)


def comparison_table(scores: list[Score]) -> str:
    """The P0 deliverable: one table, every scanner, headline metric first."""
    header = (
        f"{'scanner':<18} {'version':<14} {'FPR-traps':>10} {'':<13} {'precision':>10} "
        f"{'recall':>8} {'F1':>7} {'FPR-benign':>11} {'attrib':>8} {'cover':>7} {'err':>5}"
    )
    rule = "─" * len(header)
    lines = [
        "Baseline comparison  —  lower FPR-on-traps is better, it is the headline",
        rule,
        header,
        rule,
    ]

    for s in scores:
        if not s.available:
            lines.append(
                f"{s.scanner:<18} {s.version[:14]:<14} {'not run':>10}   "
                f"{s.unavailable_reason[:54]}"
            )
            continue

        lines.append(
            f"{s.scanner:<18} {s.version[:14]:<14} {pct(s.fpr_on_traps):>10} "
            f"{_bar(s.fpr_on_traps, invert=True):<13} "
            f"{pct(s.precision):>10} {pct(s.recall):>8} {pct(s.f1):>7} "
            f"{pct(s.fpr_on_benign):>11} {pct(s.attribution_rate):>8} "
            f"{pct(s.coverage):>7} {s.errors:>5}"
        )

    lines.append(rule)
    return "\n".join(lines)


def per_stratum_table(scores: list[Score]) -> str:
    """Flag rate by stratum. Makes it obvious when a scanner just flags everything."""
    available = [s for s in scores if s.available]
    if not available:
        return ""

    strata = [st for st in Stratum if any(st in s.by_stratum for s in available)]
    header = f"{'scanner':<18}" + "".join(f"{st.value:>16}" for st in strata)
    rule = "─" * len(header)
    lines = ["Flag rate by stratum", rule, header, rule]

    for s in available:
        row = f"{s.scanner:<18}"
        for st in strata:
            entry = s.by_stratum.get(st)
            cell = "—" if entry is None else f"{entry.flagged}/{entry.total} {pct(entry.flag_rate)}"
            row += f"{cell:>16}"
        lines.append(row)

    lines.append(rule)
    return "\n".join(lines)


def trap_family_table(scores: list[Score]) -> str:
    """Which kind of trap breaks which scanner. This is the diagnostic view."""
    available = [s for s in scores if s.available and s.fpr_by_trap_family]
    if not available:
        return ""

    families = sorted({f for s in available for f in s.fpr_by_trap_family}, key=lambda f: f.value)
    header = f"{'scanner':<18}" + "".join(f"{f.value[:20]:>22}" for f in families)
    rule = "─" * len(header)
    lines = ["False positives by trap family", rule, header, rule]

    for s in available:
        row = f"{s.scanner:<18}"
        for fam in families:
            hits, total = s.fpr_by_trap_family.get(fam, (0, 0))
            cell = "—" if not total else f"{hits}/{total} {pct(hits / total)}"
            row += f"{cell:>22}"
        lines.append(row)

    lines.append(rule)
    return "\n".join(lines)


def attack_class_table(scores: list[Score]) -> str:
    """Per-class recall. A scanner can look fine overall and be blind to a whole family."""
    available = [s for s in scores if s.available and s.recall_by_attack_class]
    if not available:
        return ""

    classes = sorted(
        {c for s in available for c in s.recall_by_attack_class}, key=lambda c: c.value
    )
    lines = [
        "Recall by attack class",
        "─" * 96,
        f"{'attack class':<30}" + "".join(f"{s.scanner:>18}" for s in available),
        "─" * 78,
    ]

    for cls in classes:
        row = f"{cls.value:<30}"
        for s in available:
            hits, total = s.recall_by_attack_class.get(cls, (0, 0))
            row += f"{('—' if not total else f'{hits}/{total}'):>18}"
        lines.append(row)

    lines.append("─" * 96)
    return "\n".join(lines)


def markdown_table(scores: list[Score]) -> str:
    """The comparison table as Markdown, for the writeup.

    Generated rather than transcribed. A published number that drifts from the JSON it
    came from is worse than no number, and hand-copying six rows across three documents is
    exactly how that happens.
    """
    lines = [
        "| Scanner | Version | FPR-on-traps (Wilson 95% CI) | Precision | Recall (Wilson 95% CI) | F1 | FPR-benign | Attribution |",
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]

    for s in scores:
        if not s.available:
            lines.append(f"| `{s.scanner}` | `{s.version}` | not run | — | — | — | — | — |")
            continue
        lines.append(
            f"| `{s.scanner}` | `{s.version}` | **{estimate_text(s.trap_false_positives, s.trap_total)}** | "
            f"{pct(s.precision)} | {estimate_text(s.true_positives, s.true_positives + s.false_negatives)} | "
            f"{pct(s.f1)} | {pct(s.fpr_on_benign)} | "
            f"{pct(s.attribution_rate)} |"
        )

    return "\n".join(lines)


def corpus_sha256(samples: list[Sample]) -> str:
    """Hash manifests and artifact bytes without embedding checkout-specific paths."""
    digest = hashlib.sha256()
    if samples:
        for parent in (samples[0].path, *samples[0].path.parents):
            if parent.name != "samples":
                continue
            for name in ("dataset.yaml", "obfuscated-design.yaml"):
                metadata = parent.parent / name
                if metadata.is_file():
                    digest.update(name.encode())
                    digest.update(b"\0")
                    digest.update(metadata.read_bytes())
                    digest.update(b"\0")
            break
    for sample in sorted(samples, key=lambda item: item.id):
        files = [sample.path / "sample.yaml"]
        files.extend(path for path in sample.artifact_path.rglob("*") if path.is_file())
        for path in sorted(files, key=lambda item: item.relative_to(sample.path).as_posix()):
            relative = path.relative_to(sample.path).as_posix()
            digest.update(sample.id.encode())
            digest.update(b"\0")
            digest.update(relative.encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()


def package_source_sha256(package_root: Path | None = None) -> str:
    """Bind benchmark evidence to the exact analyzer source, independent of checkout path."""
    root = package_root or Path(__file__).resolve().parents[1]
    digest = hashlib.sha256()
    paths = (
        path
        for path in root.rglob("*.py")
        if path.relative_to(root).parts[0] != "data"
        and "__pycache__" not in path.relative_to(root).parts
    )
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def runtime_dependency_versions() -> dict[str, str]:
    """Record parser/runtime versions that can affect benchmark extraction."""
    return {name: importlib.metadata.version(name) for name in RUNTIME_DISTRIBUTIONS}


def to_json(samples: list[Sample], scores: list[Score]) -> str:
    """Machine-readable results, for regression-checking the table across commits."""
    payload = {
        "schema": BENCHMARK_SCHEMA,
        "project": {
            "distribution": "divergence-mcp",
            "version": __version__,
            "source_sha256": package_source_sha256(),
        },
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "dependencies": runtime_dependency_versions(),
        },
        "corpus": {
            "dataset": DATASET_ID,
            "license": "Apache-2.0",
            "origin": "synthetic",
            "sha256": corpus_sha256(samples),
            "total": len(samples),
            "malicious": sum(1 for s in samples if s.is_positive),
            "benign": sum(1 for s in samples if not s.is_positive),
            "by_stratum": {st.value: sum(1 for s in samples if s.stratum is st) for st in Stratum},
        },
        "scanners": [
            {
                "name": s.scanner,
                "version": s.version,
                "available": s.available,
                "unavailable_reason": s.unavailable_reason,
                "fpr_on_traps": s.fpr_on_traps,
                "fpr_on_benign": s.fpr_on_benign,
                "fpr_on_all_negatives": s.fpr_on_all_negatives,
                "precision": s.precision,
                "recall": s.recall,
                "f1": s.f1,
                "attribution_rate": s.attribution_rate,
                "true_positives": s.true_positives,
                "false_positives": s.false_positives,
                "false_negatives": s.false_negatives,
                "true_negatives": s.true_negatives,
                "errors": s.errors,
                "duration_s": s.duration_s,
                "provenance": s.metadata,
                "scored": s.scored,
                "skipped_not_applicable": s.skipped,
                "coverage": s.coverage,
                "risk_findings": s.total_risk_findings,
                "posture_findings": s.total_posture_findings,
                "estimates": {
                    "fpr_on_traps": estimate(s.trap_false_positives, s.trap_total),
                    "recall": estimate(s.true_positives, s.true_positives + s.false_negatives),
                },
                "by_stratum": {
                    st.value: {"total": v.total, "flagged": v.flagged}
                    for st, v in sorted(s.by_stratum.items(), key=lambda kv: kv[0].value)
                },
                "recall_by_attack_class": {
                    c.value: {"hits": h, "total": t}
                    for c, (h, t) in sorted(
                        s.recall_by_attack_class.items(), key=lambda kv: kv[0].value
                    )
                },
                "fpr_by_trap_family": {
                    f.value: {"hits": h, "total": t}
                    for f, (h, t) in sorted(
                        s.fpr_by_trap_family.items(), key=lambda kv: kv[0].value
                    )
                },
            }
            for s in scores
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=False)
