"""`divergence-bench` — the P0 command line.

Three verbs:

    validate   every sample is well-formed, rationalised and inert
    bench      run every registered scanner, print the comparison table
    describe   show what the corpus contains, without running anything
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Importing these registers the adapters. Explicit, so the registry never depends on
# import order elsewhere.
import divergence.adapters.divergence  # noqa: F401
import divergence.adapters.external  # noqa: F401
import divergence.adapters.mcp_shield  # noqa: F401
import divergence.adapters.reference  # noqa: F401
import divergence.adapters.semgrep_scanner  # noqa: F401
from divergence.adapters import available_adapters, get_adapter
from divergence.adapters.base import run_adapter
from divergence.bench import report
from divergence.bench.capability_score import render as render_capabilities
from divergence.bench.capability_score import score_capabilities
from divergence.bench.corpus import CorpusError, counts_by_stratum, load_corpus, validate
from divergence.bench.metrics import score_all
from divergence.bench.models import Stratum


def _default_corpus() -> Path:
    """Resolve the corpus both from a checkout and from an installed wheel."""
    package_root = Path(__file__).resolve().parents[1]
    bundled = package_root / "data" / "corpus" / "samples"
    if bundled.is_dir():
        return bundled

    checkout = Path(__file__).resolve().parents[3] / "corpus" / "samples"
    return checkout if checkout.is_dir() else bundled


DEFAULT_CORPUS = _default_corpus()

# The P0 target from §07 of the spec: 80 samples, 25 malicious, 35 traps, 20 benign.
P0_TARGET = {
    Stratum.MALICIOUS: 25,
    Stratum.FP_TRAP: 35,
    Stratum.BENIGN_PLAIN: 20,
}


def _load(root: Path):
    try:
        return load_corpus(root)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


def cmd_validate(args) -> int:
    samples = _load(args.corpus)
    violations = validate(samples)

    print(report.corpus_summary(samples))
    print()

    if violations:
        print(f"{len(violations)} violation(s):\n", file=sys.stderr)
        for v in violations:
            print(f"  {v}", file=sys.stderr)
        return 1

    print(f"✓ {len(samples)} samples valid — all rationalised, all inert.")

    if args.check_p0_target:
        counts = counts_by_stratum(samples)
        short = {st: need - counts.get(st, 0) for st, need in P0_TARGET.items()}
        missing = {st: n for st, n in short.items() if n > 0}
        if missing:
            print("\nP0 target not yet met:", file=sys.stderr)
            for st, n in missing.items():
                print(
                    f"  {st.value}: {counts.get(st, 0)}/{P0_TARGET[st]} ({n} short)",
                    file=sys.stderr,
                )
            return 1
        print("✓ P0 corpus target met (25 malicious / 35 traps / 20 benign).")

    return 0


def cmd_describe(args) -> int:
    samples = _load(args.corpus)
    print(report.corpus_summary(samples))
    print()
    print(f"{'id':<40} {'kind':<13} {'stratum':<14} {'lang':<11} classes")
    print("─" * 110)
    for s in samples:
        classes = (
            ",".join(a.value for a in s.attack_classes)
            or ",".join(f.value for f in s.trap_families)
            or "—"
        )
        print(
            f"{s.id:<40} {s.kind.value:<13} {s.stratum.value:<14} {s.language:<11} {classes[:40]}"
        )
    return 0


def cmd_capabilities(args) -> int:
    """The P2 gate: B_s extraction scored against hand-verified ground truth."""
    samples = _load(args.corpus)
    report_ = score_capabilities(samples)

    if report_.samples_scored == 0:
        print("no samples carry verified capability ground truth", file=sys.stderr)
        return 2

    print(render_capabilities(report_))

    # Over-claiming manufactures divergence that is not there, so it fails the gate.
    return 1 if report_.false_positives else 0


def cmd_sandbox_gate(args) -> int:
    """P5 gate: what execution reveals that static analysis could not."""
    from divergence.bench.sandbox_gate import render as render_gate
    from divergence.bench.sandbox_gate import run_gate

    samples = _load(args.corpus)
    report_ = run_gate(samples, timeout=args.timeout)
    print(render_gate(report_))

    if not report_.available:
        # Local macOS development remains static-only by default. The Linux P5 gate uses
        # --require-available so missing or unverified confinement can never look green.
        return 2 if args.require_available else 0
    rate = report_.catch_rate
    return 0 if (rate is not None and rate >= 0.5 and report_.control_clean) else 1


def cmd_bench(args) -> int:
    samples = _load(args.corpus)

    violations = validate(samples)
    if violations and not args.ignore_violations:
        print(
            f"corpus has {len(violations)} violation(s) — run `validate` first, "
            "or pass --ignore-violations",
            file=sys.stderr,
        )
        return 2

    adapters = [get_adapter(n) for n in args.scanner] if args.scanner else available_adapters()

    runs = [run_adapter(a, samples) for a in adapters]
    scores = score_all(samples, runs)

    print(report.corpus_summary(samples))
    print()
    print(report.comparison_table(scores))
    print()
    print(report.per_stratum_table(scores))

    if args.detail:
        for extra in (report.trap_family_table(scores), report.attack_class_table(scores)):
            if extra:
                print()
                print(extra)

    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(report.markdown_table(scores) + "\n")
        print(f"\nwrote {args.markdown}")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(report.to_json(samples, scores))
        print(f"\nwrote {args.json}")

    failed = [
        getattr(score, "scanner", "unknown")
        for score in scores
        if getattr(score, "available", True) and getattr(score, "errors", 0)
    ]
    if failed and not getattr(args, "allow_errors", False):
        print(
            "benchmark incomplete: available scanner errors in " + ", ".join(failed),
            file=sys.stderr,
        )
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="divergence-bench",
        description="The Divergence benchmark — precision measured against traps, not just recall.",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
        help="corpus root (default: the dataset bundled with divergence-mcp)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="check every corpus invariant")
    p_val.add_argument(
        "--check-p0-target", action="store_true", help="also assert the P0 stratum counts"
    )
    p_val.set_defaults(func=cmd_validate)

    p_desc = sub.add_parser("describe", help="list the corpus without running anything")
    p_desc.set_defaults(func=cmd_describe)

    p_cap = sub.add_parser(
        "capabilities", help="score B_s extraction against verified ground truth"
    )
    p_cap.set_defaults(func=cmd_capabilities)

    p_gate = sub.add_parser(
        "sandbox-gate", help="P5 gate: B_dynamic vs B_static on the obfuscated stratum"
    )
    p_gate.add_argument("--timeout", type=int, default=25)
    p_gate.add_argument(
        "--require-available",
        action="store_true",
        help="fail when the sandbox/confinement boundary is unavailable (required in Linux CI)",
    )
    p_gate.set_defaults(func=cmd_sandbox_gate)

    p_bench = sub.add_parser("bench", help="run scanners and print the comparison table")
    p_bench.add_argument("--scanner", action="append", help="limit to one scanner (repeatable)")
    p_bench.add_argument("--json", type=Path, help="also write machine-readable results here")
    p_bench.add_argument("--markdown", type=Path, help="also write the table as Markdown")
    p_bench.add_argument(
        "--detail", action="store_true", help="per-class and per-trap-family tables"
    )
    p_bench.add_argument("--ignore-violations", action="store_true", help="bench a dirty corpus")
    p_bench.add_argument(
        "--allow-errors",
        action="store_true",
        help="write a partial table despite scanner errors (default: fail visibly)",
    )
    p_bench.set_defaults(func=cmd_bench)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
