"""Rendering the baseline comparison table.

The column order is the argument. FPR-on-traps sits immediately after the scanner name,
before precision, recall or F1, because a reader who stops after two columns should
still have seen the number that matters.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from divergence.bench.metrics import Score
from divergence.bench.models import Sample, Stratum

BAR_WIDTH = 12


def pct(value: float | None) -> str:
    """Undefined must not render as zero — that would read as a perfect score."""
    return "—" if value is None else f"{value * 100:.1f}%"


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
        lines.append(
            f"  {stratum.value:<14} {count:>4}   ({servers} servers, {skills} skills)"
        )
    lines.append(f"  {'total':<14} {total:>4}")
    return "\n".join(lines)


def comparison_table(scores: list[Score]) -> str:
    """The P0 deliverable: one table, every scanner, headline metric first."""
    header = (
        f"{'scanner':<18} {'FPR-traps':>10} {'':<13} {'precision':>10} "
        f"{'recall':>8} {'F1':>7} {'FPR-benign':>11} {'attrib':>8} {'err':>5}"
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
            lines.append(f"{s.scanner:<18} {'not run':>10}   {s.unavailable_reason[:54]}")
            continue

        lines.append(
            f"{s.scanner:<18} {pct(s.fpr_on_traps):>10} "
            f"{_bar(s.fpr_on_traps, invert=True):<13} "
            f"{pct(s.precision):>10} {pct(s.recall):>8} {pct(s.f1):>7} "
            f"{pct(s.fpr_on_benign):>11} {pct(s.attribution_rate):>8} {s.errors:>5}"
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
    lines = ["Recall by attack class", "─" * 96, f"{'attack class':<30}" + "".join(f"{s.scanner:>18}" for s in available), "─" * 78]

    for cls in classes:
        row = f"{cls.value:<30}"
        for s in available:
            hits, total = s.recall_by_attack_class.get(cls, (0, 0))
            row += f"{('—' if not total else f'{hits}/{total}'):>18}"
        lines.append(row)

    lines.append("─" * 96)
    return "\n".join(lines)


def to_json(samples: list[Sample], scores: list[Score]) -> str:
    """Machine-readable results, for regression-checking the table across commits."""
    payload = {
        "corpus": {
            "total": len(samples),
            "by_stratum": {
                st.value: sum(1 for s in samples if s.stratum is st) for st in Stratum
            },
        },
        "scanners": [
            {
                "name": s.scanner,
                "available": s.available,
                "unavailable_reason": s.unavailable_reason,
                "fpr_on_traps": s.fpr_on_traps,
                "fpr_on_benign": s.fpr_on_benign,
                "precision": s.precision,
                "recall": s.recall,
                "f1": s.f1,
                "attribution_rate": s.attribution_rate,
                "true_positives": s.true_positives,
                "false_positives": s.false_positives,
                "false_negatives": s.false_negatives,
                "true_negatives": s.true_negatives,
                "errors": s.errors,
                "risk_findings": s.total_risk_findings,
                "posture_findings": s.total_posture_findings,
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
