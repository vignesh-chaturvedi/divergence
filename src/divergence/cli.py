"""`divergence` — the P1 command line.

    divergence inspect <target>    print the declared surface, run nothing
    divergence scan    <target>    findings, split into risk and posture
    divergence approve <target>    record a fingerprint in the ledger
    divergence diff    <target>    compare against the approved fingerprint

A target is a directory, a skill bundle, or a local MCP client config. Static analysis is
offline and deterministic. Remote acquisition, sandbox execution, and evidence-only A9
adjudication are separate explicit opt-ins.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from divergence import __version__
from divergence.core.acquire import Artifact
from divergence.core.adjudicator import (
    Adjudication,
    AdjudicatorUnavailable,
)
from divergence.core.adjudicator import (
    configured_backend as configured_adjudicator,
)
from divergence.core.fleet import FleetError, analyze_fleet, build_fleet, load_fleet
from divergence.core.ledger import Ledger
from divergence.core.pipeline import ScanOptions, load, scan_detailed
from divergence.core.resolve import ResolutionError, ResolvedTarget, resolve
from divergence.core.sandbox import DEFAULT_TIMEOUT, Dynamic
from divergence.core.sarif import dumps as sarif_dumps
from divergence.core.vocabulary import Channel, Finding

DEFAULT_LEDGER = Path.home() / ".local" / "share" / "divergence" / "ledger.db"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _safe(value: object) -> str:
    """Render untrusted artifact text without terminal control sequences."""
    text = str(value)
    return "".join(
        char if ord(char) >= 32 and not 0x7F <= ord(char) <= 0x9F else f"\\x{ord(char):02x}"
        for char in text
    )


def _resolve_or_exit(target: str, args=None) -> list[ResolvedTarget]:
    try:
        return resolve(
            target,
            allow_remote=bool(getattr(args, "allow_network", False)),
            cache_dir=getattr(args, "acquisition_cache", None),
        )
    except ResolutionError as exc:
        print(f"error: {_safe(exc)}", file=sys.stderr)
        raise SystemExit(2) from None


def _print_unresolved(t: ResolvedTarget) -> None:
    print(f"  {_safe(t.name)}: {t.status.value} — {_safe(t.unresolved_reason)}")


def _describe(artifact: Artifact) -> None:
    print(f"  kind         {_safe(artifact.kind)}")
    if artifact.provenance.name:
        p = artifact.provenance
        signed = {True: "signed", False: "unsigned", None: "signature unknown"}[p.signed]
        print(
            f"  package      {_safe(p.name)} {_safe(p.version)} · "
            f"{_safe(p.author or 'no author')} · {signed}"
        )
        if p.typosquat_distance:
            print(
                f"  typosquat    distance {p.typosquat_distance} from "
                f"{_safe(p.nearest_popular_name)}"
            )

    if artifact.skill:
        s = artifact.skill
        print(f"  skill        {_safe(s.name)}")
        print(
            "  allowed-tools "
            + _safe(s.allowed_tools if s.allowed_tools is not None else "<absent — unrestricted>")
        )
        print(f"  description  {_safe(s.description[:100])}")

    for tool in artifact.tools:
        hints = ", ".join(f"{k}={v}" for k, v in sorted(tool.annotations.items())) or "none"
        params = ", ".join(sorted(tool.schema_properties)) or "none"
        print(f"  tool         {_safe(tool.name)}")
        print(f"    params     {_safe(params)}")
        print(f"    annotations {_safe(hints)}")
        print(f"    describes  {_safe(' '.join(tool.description.split())[:110])}")

    if artifact.snapshots:
        print(f"  snapshots    {_safe(', '.join(s.label for s in artifact.snapshots))}")
    print(f"  bundle       {len(artifact.bundle_files)} file(s)")
    for diagnostic in artifact.diagnostics:
        print(f"  partial      {_safe(diagnostic)}")


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
            print(f"    [{_safe(f.severity)}] {_safe(cls)}")
            print(f"      {_safe(f.message)}")
            print(f"      claim:    {_safe(f.claim)}")
            print(f"      evidence: {_safe(f.evidence)}")
    else:
        print("\n  RISK — none")

    if posture:
        print("\n  POSTURE — capability, not a verdict")
        for f in posture:
            print(f"    [{_safe(f.severity)}] {_safe(f.message)}")
            if f.evidence:
                print(f"      {_safe(f.evidence)}")

    return len(risk)


def cmd_inspect(args) -> int:
    incomplete = 0
    for t in _resolve_or_exit(args.target, args):
        print(f"\n{_safe(t.name)}  ({_safe(t.source)})")
        if not t.resolved:
            _print_unresolved(t)
            incomplete += 1
            continue
        artifact = t.artifact
        assert artifact is not None
        _describe(artifact)
        incomplete += bool(artifact.diagnostics)
    return 2 if incomplete and not args.allow_partial else 0


def _finding_json(finding: Finding) -> dict:
    return {
        "sample_id": _safe(finding.sample_id),
        "channel": finding.channel.value,
        "attack_class": finding.attack_class.value if finding.attack_class else None,
        "severity": _safe(finding.severity),
        "message": _safe(finding.message),
        "claim": _safe(finding.claim),
        "evidence": _safe(finding.evidence),
        "confidence": finding.confidence,
    }


def _dynamic_json(dynamic: Dynamic | None) -> dict | None:
    """Render the optional observation tier without dropping its coverage qualifiers."""
    if dynamic is None:
        return None
    return {
        "available": dynamic.available,
        "unavailable_reason": _safe(dynamic.unavailable_reason),
        "runner_version": _safe(dynamic.runner_version),
        "ran": dynamic.ran,
        "confinement_enforced": dynamic.confinement_enforced,
        "capabilities": sorted(capability.value for capability in dynamic.capabilities),
        "coverage": {
            "note": _safe(dynamic.coverage_note),
            "syscalls_observed": dynamic.syscalls_observed,
            "observations_dropped": dynamic.observations_dropped,
            "entrypoints_invoked": dynamic.entrypoints_invoked,
            "entrypoints_completed": dynamic.entrypoints_completed,
            "entrypoints_failed": dynamic.entrypoints_failed,
            "exited_cleanly": dynamic.exited_cleanly,
            "exit_code": dynamic.exit_code,
            "timed_out": dynamic.timed_out,
        },
        "observations": [
            {
                "capability": observation.capability.value,
                "syscall": _safe(observation.syscall),
                "target": _safe(observation.target),
                "decoy": observation.decoy,
                "succeeded": observation.succeeded,
                "result": observation.result,
            }
            for observation in dynamic.observations
        ],
        "limitations": [_safe(item) for item in dynamic.limitations],
    }


def _adjudication_json(adjudication: Adjudication) -> dict:
    """Keep A9 advisory: serialize its assessment beside, never over, the finding."""
    return {
        "finding": _finding_json(adjudication.finding),
        "verdict": adjudication.verdict.value,
        "reasoning": _safe(adjudication.reasoning),
        "backend": _safe(adjudication.backend),
    }


def _dynamic_diagnostics(dynamic: Dynamic | None) -> list[str]:
    """Explain why a requested dynamic result is partial rather than silently clean."""
    if dynamic is None:
        return []
    if not dynamic.available:
        return [dynamic.coverage_note]

    diagnostics = []
    if not dynamic.confinement_enforced:
        diagnostics.append("sandbox did not confirm fail-closed confinement")
    if not dynamic.ran:
        diagnostics.append(dynamic.coverage_note)
    elif dynamic.timed_out:
        diagnostics.append("sandbox timed out; dynamic coverage is partial")
    if dynamic.entrypoints_failed:
        diagnostics.append(
            f"{dynamic.entrypoints_failed} sandbox entrypoint(s) failed; dynamic coverage is partial"
        )
    return diagnostics


def cmd_scan(args) -> int:
    total_risk = 0
    incomplete = 0
    collected: list[Finding] = []
    sarif_roots: dict[str, Path] = {}
    records: list[dict] = []

    adjudicator = None
    if args.adjudicate:
        try:
            adjudicator = configured_adjudicator()
        except AdjudicatorUnavailable as exc:
            message = f"A9 adjudication unavailable: {_safe(exc)}"
            if args.json:
                print(json.dumps({"version": __version__, "status": "failed", "error": message}))
            else:
                print(f"error: {message}", file=sys.stderr)
            return 2

    options = ScanOptions(
        dynamic=args.dynamic,
        sandbox_timeout=args.sandbox_timeout,
        adjudicate=args.adjudicate,
        adjudicator_backend=adjudicator,
    )
    for t in _resolve_or_exit(args.target, args):
        if not args.json:
            print(f"\n{_safe(t.name)}  ({_safe(t.source)})")
        if not t.resolved:
            if not args.json:
                _print_unresolved(t)
            records.append(
                {
                    "name": _safe(t.name),
                    "source": _safe(t.source),
                    "status": t.status.value,
                    "reason": _safe(t.unresolved_reason),
                    "findings": [],
                }
            )
            incomplete += 1
            continue

        artifact = t.artifact
        assert artifact is not None
        try:
            report = scan_detailed(artifact.root, artifact_id=t.name, options=options)
        except AdjudicatorUnavailable as exc:
            # A configured backend can still fail or violate its response contract. The
            # deterministic findings remain valid, but the explicitly requested tier did
            # not complete, so this invocation is a failed analysis rather than a clean one.
            message = f"A9 adjudication failed: {_safe(exc)}"
            if args.json:
                print(
                    json.dumps(
                        {"version": __version__, "status": "failed", "error": message},
                        sort_keys=True,
                    )
                )
            else:
                print(f"error: {message}", file=sys.stderr)
            return 2

        artifact = report.artifact
        behaviour = report.behaviour
        findings = list(report.findings)
        sarif_roots[t.name] = artifact.root

        target_diagnostics = (
            list(artifact.diagnostics)
            + list(behaviour.parse_errors)
            + _dynamic_diagnostics(report.dynamic)
        )
        if args.ledger_check:
            ledger = Ledger(args.ledger)
            if ledger.has_record(t.name):
                findings += ledger.diff(
                    artifact,
                    artifact_id=t.name,
                    observed_capabilities=behaviour.capabilities,
                )
            else:
                target_diagnostics.append("no approval baseline recorded for ledger check")
        if behaviour.unresolved:
            target_diagnostics.append(f"{len(behaviour.unresolved)} call(s) could not be followed")
        if target_diagnostics:
            incomplete += 1

        caps = sorted(c.value for c in behaviour.capabilities)
        if not args.json:
            print(f"  capabilities {_safe(', '.join(caps) or 'none')}")
            if report.dynamic is not None:
                dynamic_caps = ", ".join(
                    sorted(capability.value for capability in report.dynamic.capabilities)
                )
                state = "available" if report.dynamic.available else "unavailable"
                print(f"  dynamic     {_safe(state)} · {_safe(dynamic_caps or 'none observed')}")
                print(f"  coverage    {_safe(report.dynamic.coverage_note)}")
            for entrypoint in behaviour.entrypoints:
                for sink in entrypoint.tainted_sinks:
                    print(
                        f"  flow         {_safe(entrypoint.name)}"
                        f"({_safe(', '.join(sink.tainted_by))}) -> {sink.capability.value} "
                        f"at {_safe(sink.location)}"
                    )
            for diagnostic in target_diagnostics:
                print(f"  partial      {_safe(diagnostic)}")
        collected += findings
        risk_count = sum(f.channel is Channel.RISK for f in findings)
        total_risk += risk_count
        if not args.json:
            _print_findings(findings)
            if report.adjudications:
                print("\n  ADJUDICATION — advisory; deterministic findings are unchanged")
                for adjudication in report.adjudications:
                    attack_class = (
                        adjudication.finding.attack_class.value
                        if adjudication.finding.attack_class
                        else "divergence"
                    )
                    print(
                        f"    [{adjudication.verdict.value}] {_safe(attack_class)} "
                        f"via {_safe(adjudication.backend)}"
                    )
                    print(f"      {_safe(adjudication.reasoning)}")
        records.append(
            {
                "name": _safe(t.name),
                "source": _safe(t.source),
                "status": "partial" if target_diagnostics else "complete",
                "diagnostics": [_safe(item) for item in target_diagnostics],
                "capabilities": caps,
                "findings": [_finding_json(finding) for finding in findings],
                "dynamic": _dynamic_json(report.dynamic),
                "adjudications": [
                    _adjudication_json(adjudication) for adjudication in report.adjudications
                ],
            }
        )

    if args.sarif:
        args.sarif.parent.mkdir(parents=True, exist_ok=True)
        args.sarif.write_text(sarif_dumps(collected, roots=sarif_roots))
        if not args.json:
            print(f"\nwrote {_safe(args.sarif)}")

    if args.json:
        print(
            json.dumps(
                {
                    "version": __version__,
                    "status": "partial" if incomplete else "complete",
                    "risk_count": total_risk,
                    "incomplete_count": incomplete,
                    "targets": records,
                },
                sort_keys=True,
            )
        )
    else:
        print(f"\n{total_risk} risk finding(s); {incomplete} partial target(s).")
    # Non-zero exit on risk so this drops into CI without a wrapper.
    if incomplete and not args.allow_partial:
        return 2
    return 1 if total_risk and args.fail_on_risk else 0


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
    resolution_incomplete = 0

    try:
        if target.name == "fleet.yaml" or target.suffix in (".yaml", ".yml"):
            fleet = load_fleet(target)
        else:
            targets = _resolve_or_exit(args.target, args)
            entries = []
            for resolved in targets:
                if resolved.artifact is not None:
                    entries.append((resolved.name, resolved.artifact.root))
            for t in targets:
                if not t.resolved:
                    _print_unresolved(t)
                    resolution_incomplete += 1
            if not entries:
                print("error: no analysable artifacts in this config", file=sys.stderr)
                return 2
            fleet = build_fleet(entries, name=target.stem)
    except FleetError as exc:
        print(f"error: {_safe(exc)}", file=sys.stderr)
        return 2

    print(f"{_safe(fleet.name)}  ({len(fleet.members)} artifacts)")
    for member in fleet.members:
        caps = ", ".join(sorted(c.value for c in member.behaviour.capabilities)) or "none"
        print(f"  {_safe(member.id):<28} {_safe(caps)}")

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
        print(f"\nwrote {_safe(args.sarif)}")

    print(f"\n{risk_count} cross-artifact risk finding(s).")
    incomplete = resolution_incomplete + sum(
        bool(
            member.artifact.diagnostics
            or member.behaviour.parse_errors
            or member.behaviour.unresolved
        )
        for member in fleet.members
    )
    if incomplete:
        print(f"{incomplete} partial artifact(s).")
    if incomplete and not args.allow_partial:
        return 2
    return 1 if risk_count and args.fail_on_risk else 0


def cmd_approve(args) -> int:
    ledger = Ledger(args.ledger)
    incomplete = 0
    for t in _resolve_or_exit(args.target, args):
        if not t.resolved:
            _print_unresolved(t)
            incomplete += 1
            continue
        resolved_artifact = t.artifact
        assert resolved_artifact is not None
        artifact, behaviour = load(resolved_artifact.root)
        diagnostics = (
            list(artifact.diagnostics)
            + list(behaviour.parse_errors)
            + ([f"{len(behaviour.unresolved)} unresolved calls"] if behaviour.unresolved else [])
        )
        if diagnostics:
            incomplete += 1
            action = "partial accepted for" if args.allow_partial else "not approved"
            print(f"{action} {_safe(t.name)}: " + _safe("; ".join(diagnostics)))
            if not args.allow_partial:
                continue
        ledger.record(artifact, artifact_id=t.name, observed_capabilities=behaviour.capabilities)
        print(
            f"approved {_safe(t.name)}  fingerprint "
            f"{ledger.fingerprint(artifact, behaviour.capabilities)[:16]}"
        )
    print(f"\nledger: {_safe(args.ledger)}")
    return 2 if incomplete and not args.allow_partial else 0


def cmd_diff(args) -> int:
    ledger = Ledger(args.ledger)
    total_risk = 0
    incomplete = 0
    for t in _resolve_or_exit(args.target, args):
        print(f"\n{_safe(t.name)}")
        if not t.resolved:
            _print_unresolved(t)
            incomplete += 1
            continue
        resolved_artifact = t.artifact
        assert resolved_artifact is not None
        artifact, behaviour = load(resolved_artifact.root)
        if artifact.diagnostics or behaviour.parse_errors or behaviour.unresolved:
            incomplete += 1
            print("  partial analysis; mutation comparison may be incomplete")
        if not ledger.has_record(t.name):
            incomplete += 1
            print("  no approval baseline recorded")
            continue
        findings = ledger.diff(
            artifact, artifact_id=t.name, observed_capabilities=behaviour.capabilities
        )
        if not findings:
            print("  unchanged since approval")
            continue
        total_risk += _print_findings(findings)
    if incomplete and not args.allow_partial:
        return 2
    return 1 if total_risk and args.fail_on_risk else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="divergence",
        description=(
            "Measure the gap between what an MCP server or agent skill claims to do and "
            "what it actually does. Offline and non-executing by default; remote acquisition, "
            "sandbox execution, and adjudication require explicit opt-ins."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER, help="ledger database path")
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="explicitly allow download-only npm, PyPI, or GitHub acquisition",
    )
    parser.add_argument(
        "--acquisition-cache",
        type=Path,
        help="cache directory for explicitly acquired remote packages",
    )
    parser.add_argument(
        "--fail-on-risk", action="store_true", help="exit non-zero when risk findings exist"
    )
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="accept visibly partial analysis instead of exiting with status 2",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inspect", help="print the declared surface")
    p.add_argument("target")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("scan", help="flag contradictions")
    p.add_argument("target")
    p.add_argument("--ledger-check", action="store_true", help="also diff against the ledger")
    p.add_argument("--sarif", type=Path, help="also write SARIF 2.1.0 to this path")
    p.add_argument("--json", action="store_true", help="emit one deterministic JSON result")
    p.add_argument(
        "--dynamic",
        action="store_true",
        help="execute in the verified Linux sandbox and include B_dynamic (explicit opt-in)",
    )
    p.add_argument(
        "--sandbox-timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"per-artifact sandbox timeout (default: {DEFAULT_TIMEOUT})",
    )
    p.add_argument(
        "--adjudicate",
        action="store_true",
        help="adjudicate the capped contested subset through the configured A9 command backend",
    )
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
    if getattr(args, "sandbox_timeout", DEFAULT_TIMEOUT) <= 0:
        parser.error("--sandbox-timeout must be positive")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
