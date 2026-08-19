"""`divergence` — the P1 command line.

    divergence inspect <target>    print the declared surface, run nothing
    divergence scan    <target>    findings, split into risk and posture
    divergence approve <target>    record a fingerprint in the ledger
    divergence diff    <target>    compare against the approved fingerprint

A target is a directory, a skill bundle, or a local MCP client config. Everything is
offline and deterministic: no model runs, nothing is executed, nothing leaves the host.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from divergence.core.acquire import Artifact
from divergence.core.fleet import analyze_fleet, build_fleet, load_fleet
from divergence.core.ledger import Ledger
from divergence.core.pipeline import load, scan as scan_artifact
from divergence.core.sarif import dumps as sarif_dumps
from divergence.core.resolve import ResolutionError, ResolvedTarget, resolve
from divergence.core.vocabulary import Channel, Finding

DEFAULT_LEDGER = Path.home() / ".local" / "share" / "divergence" / "ledger.db"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _resolve_or_exit(target: str) -> list[ResolvedTarget]:
    try:
        return resolve(target)
    except ResolutionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


def _print_unresolved(t: ResolvedTarget) -> None:
    print(f"  {t.name}: unresolved — {t.unresolved_reason}")


def _describe(artifact: Artifact) -> None:
    print(f"  kind         {artifact.kind}")
    if artifact.provenance.name:
        p = artifact.provenance
        signed = {True: "signed", False: "unsigned", None: "signature unknown"}[p.signed]
        print(f"  package      {p.name} {p.version} · {p.author or 'no author'} · {signed}")
        if p.typosquat_distance:
            print(f"  typosquat    distance {p.typosquat_distance} from {p.nearest_popular_name}")

    if artifact.skill:
        s = artifact.skill
        print(f"  skill        {s.name}")
        print(f"  allowed-tools {s.allowed_tools if s.allowed_tools is not None else '<absent — unrestricted>'}")
        print(f"  description  {s.description[:100]}")

    for tool in artifact.tools:
        hints = ", ".join(f"{k}={v}" for k, v in sorted(tool.annotations.items())) or "none"
        params = ", ".join(sorted(tool.schema_properties)) or "none"
        print(f"  tool         {tool.name}")
        print(f"    params     {params}")
        print(f"    annotations {hints}")
        print(f"    describes  {' '.join(tool.description.split())[:110]}")

    if artifact.snapshots:
        print(f"  snapshots    {', '.join(s.label for s in artifact.snapshots)}")
    print(f"  bundle       {len(artifact.bundle_files)} file(s)")


def _print_findings(findings: list[Finding]) -> int:
    """Print risk and posture in separate blocks. They must never read as one list."""
    risk = sorted(
        (f for f in findings if f.channel is Channel.RISK),
        key=lambda f: _SEVERITY_ORDER.get(f.severity, 9),
    )
    posture = [f for f in findings if f.channel is Channel.POSTURE]

    if risk:
        print("\n  RISK — divergence between what it says and what it does")
        for f in risk:
            cls = f.attack_class.value if f.attack_class else "divergence"
            print(f"    [{f.severity}] {cls}")
            print(f"      {f.message}")
            print(f"      claim:    {f.claim}")
            print(f"      evidence: {f.evidence}")
    else:
        print("\n  RISK — none")

    if posture:
        print("\n  POSTURE — capability, not a verdict")
        for f in posture:
            print(f"    [{f.severity}] {f.message}")
            if f.evidence:
                print(f"      {f.evidence}")

    return len(risk)


def cmd_inspect(args) -> int:
    for t in _resolve_or_exit(args.target):
        print(f"\n{t.name}  ({t.source})")
        if not t.resolved:
            _print_unresolved(t)
            continue
        _describe(t.artifact)
    return 0


def cmd_scan(args) -> int:
    total_risk = 0
    collected: list[Finding] = []
    sarif_roots: dict[str, Path] = {}
    for t in _resolve_or_exit(args.target):
        print(f"\n{t.name}  ({t.source})")
        if not t.resolved:
            _print_unresolved(t)
            continue

        artifact = t.artifact
        artifact, behaviour, findings = scan_artifact(artifact.root, artifact_id=t.name)
        sarif_roots[t.name] = artifact.root

        if args.ledger_check:
            ledger = Ledger(args.ledger)
            findings += ledger.diff(artifact, artifact_id=t.name, observed_capabilities=behaviour.capabilities)

        caps = ", ".join(sorted(c.value for c in behaviour.capabilities)) or "none"
        print(f"  capabilities {caps}")
        for entrypoint in behaviour.entrypoints:
            for sink in entrypoint.tainted_sinks:
                print(
                    f"  flow         {entrypoint.name}({', '.join(sink.tainted_by)}) "
                    f"-> {sink.capability.value} at {sink.location}"
                )
        if behaviour.unresolved:
            print(f"  unresolved   {len(behaviour.unresolved)} call(s) not followed")
        collected += findings
        total_risk += _print_findings(findings)

    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(sarif_dumps(collected, roots=sarif_roots))
        print(f"\nwrote {args.sarif}")

    print(f"\n{total_risk} risk finding(s).")
    # Non-zero exit on risk so this drops into CI without a wrapper.
    return 1 if (total_risk and args.fail_on_risk) else 0


def _repo_relative_str(path: Path) -> str:
    """Path relative to the working directory, for use as a SARIF anchor."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return path.name


def cmd_fleet(args) -> int:
    """Cross-artifact analysis over an installed set.

    Accepts a fleet manifest or an MCP client config. The config path is the real one: the
    attacks A7 exists for are invisible until you look at everything installed at once.
    """
    target = Path(args.target)

    if target.name == "fleet.yaml" or target.suffix in (".yaml", ".yml"):
        fleet = load_fleet(target)
    else:
        targets = _resolve_or_exit(args.target)
        entries = [(t.name, t.artifact.root) for t in targets if t.resolved]
        for t in targets:
            if not t.resolved:
                _print_unresolved(t)
        if not entries:
            print("error: no analysable artifacts in this config", file=sys.stderr)
            return 2
        fleet = build_fleet(entries, name=target.stem)

    print(f"{fleet.name}  ({len(fleet.members)} artifacts)")
    for member in fleet.members:
        caps = ", ".join(sorted(c.value for c in member.behaviour.capabilities)) or "none"
        print(f"  {member.id:<28} {caps}")

    findings = analyze_fleet(fleet)
    risk_count = _print_findings(findings)

    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(
            sarif_dumps(
                findings,
                roots={m.id: m.root for m in fleet.members},
                anchor=_repo_relative_str(target),
            )
        )
        print(f"\nwrote {args.sarif}")

    print(f"\n{risk_count} cross-artifact risk finding(s).")
    return 1 if (risk_count and args.fail_on_risk) else 0


def cmd_approve(args) -> int:
    ledger = Ledger(args.ledger)
    for t in _resolve_or_exit(args.target):
        if not t.resolved:
            _print_unresolved(t)
            continue
        _, behaviour = load(t.artifact.root)
        ledger.record(t.artifact, artifact_id=t.name, observed_capabilities=behaviour.capabilities)
        print(f"approved {t.name}  fingerprint {ledger.fingerprint(t.artifact, behaviour.capabilities)[:16]}")
    print(f"\nledger: {args.ledger}")
    return 0


def cmd_diff(args) -> int:
    ledger = Ledger(args.ledger)
    total_risk = 0
    for t in _resolve_or_exit(args.target):
        print(f"\n{t.name}")
        if not t.resolved:
            _print_unresolved(t)
            continue
        _, behaviour = load(t.artifact.root)
        findings = ledger.diff(t.artifact, artifact_id=t.name, observed_capabilities=behaviour.capabilities)
        if not findings:
            print("  unchanged since approval")
            continue
        total_risk += _print_findings(findings)
    return 1 if (total_risk and args.fail_on_risk) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="divergence",
        description=(
            "Measure the gap between what an MCP server or agent skill claims to do and "
            "what it actually does. Offline, deterministic, executes nothing."
        ),
    )
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER, help="ledger database path")
    parser.add_argument(
        "--fail-on-risk", action="store_true", help="exit non-zero when risk findings exist"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inspect", help="print the declared surface")
    p.add_argument("target")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("scan", help="flag contradictions")
    p.add_argument("target")
    p.add_argument("--ledger-check", action="store_true", help="also diff against the ledger")
    p.add_argument("--sarif", type=Path, help="also write SARIF 2.1.0 to this path")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser(
        "fleet", help="cross-artifact analysis over an installed set or fleet manifest"
    )
    p.add_argument("target")
    p.add_argument("--sarif", type=Path, help="also write SARIF 2.1.0 to this path")
    p.set_defaults(func=cmd_fleet)

    p = sub.add_parser("approve", help="record a fingerprint for later diffing")
    p.add_argument("target")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("diff", help="compare against the approved fingerprint")
    p.add_argument("target")
    p.set_defaults(func=cmd_diff)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
