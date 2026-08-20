"""SARIF 2.1.0 output.

§07 lists SARIF among the v1 deliverables, and §10 explains why: Divergence is not a
policy engine. It emits findings and lets existing tooling decide what to block. SARIF is
how that handoff happens — GitHub code scanning, GitLab, and most CI security dashboards
consume it directly.

The mapping that matters is the **channel split**. Posture findings are emitted at `note`
level and carry `"divergence.channel": "posture"` in their properties, so a consumer can
filter them out entirely. A tool that surfaced posture as a build failure would recreate
exactly the alert fatigue this project exists to remove.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from divergence import __version__
from divergence.core.vocabulary import Channel, Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"

# SARIF levels. Only risk findings can reach `error`; posture is always `note`.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "unknown": "warning",
}

_HELP = (
    "Divergence reports the gap between what an artifact claims and what it does. "
    "Only `risk` findings indicate a contradiction; `posture` findings describe "
    "capability and are informational by design."
)


def _level(finding: Finding) -> str:
    if finding.channel is Channel.POSTURE:
        return "note"
    return _SEVERITY_TO_LEVEL.get(finding.severity, "warning")


def _rule_id(finding: Finding) -> str:
    base = finding.attack_class.value if finding.attack_class else "divergence"
    return f"divergence/{finding.channel.value}/{base}"


# A path, and nothing else. No spaces, no commas, no angle brackets, and crucially no
# colon — GitHub code scanning reads a leading `word:` as a URI *scheme* and rejects the
# entire upload when it does not match the checkout's `file` scheme.
_PATH_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._\-/]*$")


def _looks_like_path(candidate: str) -> bool:
    return bool(candidate) and bool(_PATH_RE.match(candidate))


def _split_location(evidence: str) -> tuple[str, int | None]:
    """Split a `file:line` evidence string into a path and a line, or into nothing.

    Not every finding is anchored to a file. Fleet analysis reports things like
    `'code-review-pro: publisher=unknown, signed=None'` — a perfectly good piece of
    evidence that is not a location. Returning it as one made GitHub parse
    `code-review-pro:` as a URI scheme and refuse the whole SARIF file.

    So this returns a path only when the evidence actually is one. Prose is the caller's
    problem, and the caller keeps it in `properties` rather than discarding it.
    """
    if not evidence:
        return "", None

    head, _, tail = evidence.rpartition(":")
    if head and tail.isdigit() and _looks_like_path(head):
        return head, int(tail)

    return (evidence, None) if _looks_like_path(evidence) else ("", None)


def _repo_relative(uri: str, root: Path | None) -> str:
    """Rebase an artifact-relative path onto the repository.

    Evidence locations are relative to the artifact being scanned — `scripts/collect.py`,
    not `corpus/.../artifact/scripts/collect.py`. A code-scanning alert pointing at a path
    that does not exist in the checkout is an alert nobody can act on.
    """
    if root is None:
        return uri

    candidate = Path(root) / uri
    try:
        return candidate.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (ValueError, OSError):
        return candidate.as_posix().lstrip("/")


def _rules(findings: list[Finding]) -> list[dict]:
    seen: dict[str, dict] = {}
    for finding in findings:
        rule_id = _rule_id(finding)
        if rule_id in seen:
            continue
        name = finding.attack_class.value if finding.attack_class else "divergence"
        seen[rule_id] = {
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": name.replace("_", " ")},
            "fullDescription": {"text": _HELP},
            "defaultConfiguration": {"level": _level(finding)},
            "properties": {
                "divergence.channel": finding.channel.value,
                # Posture rules are tagged so a consumer can drop them wholesale.
                "tags": ["divergence", finding.channel.value],
            },
        }
    return list(seen.values())


def _result(finding: Finding, roots: dict[str, Path] | None, anchor: str) -> dict:
    uri, line = _split_location(finding.evidence)
    if uri:
        uri = _repo_relative(uri, (roots or {}).get(finding.sample_id))

    result = {
        "ruleId": _rule_id(finding),
        "level": _level(finding),
        "message": {"text": finding.message},
        "properties": {
            "divergence.channel": finding.channel.value,
            "divergence.severity": finding.severity,
            "divergence.confidence": finding.confidence,
            # Both halves of the contradiction travel with the finding. §04: no finding
            # ships without them, and a SARIF consumer showing only the message would
            # otherwise strip the half that makes it reviewable.
            "divergence.claim": finding.claim,
            "divergence.artifact": finding.sample_id,
            # Always carried, whether or not it was location-shaped. A finding that loses
            # its evidence stops being reviewable, which is the one thing §04 forbids.
            "divergence.evidence": finding.evidence,
        },
    }

    # Fall back to the anchor — the file that was scanned — so a finding whose evidence is
    # prose still lands somewhere real in the repository instead of nowhere.
    location_uri = uri or anchor
    if location_uri:
        physical: dict = {"artifactLocation": {"uri": location_uri}}
        if uri and line is not None:
            physical["region"] = {"startLine": line}
        result["locations"] = [{"physicalLocation": physical}]

    return result


def to_sarif(
    findings: list[Finding],
    *,
    roots: dict[str, Path] | None = None,
    anchor: str = "",
    version: str = __version__,
) -> dict:
    """Render findings as a SARIF 2.1.0 log.

    `roots` maps an artifact id to the directory its evidence paths are relative to, so
    locations come out relative to the repository rather than to the artifact. `anchor` is
    a repo-relative file used for findings whose evidence is not a location at all.
    """
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Divergence",
                        "informationUri": "https://github.com/vignesh-chaturvedi/divergence",
                        "version": version,
                        "rules": _rules(findings),
                    }
                },
                "results": [_result(f, roots, anchor) for f in findings],
            }
        ],
    }


def dumps(findings: list[Finding], **kwargs) -> str:
    return json.dumps(to_sarif(findings, **kwargs), indent=2, sort_keys=False)


# --- validation -----------------------------------------------------------------------


def check(path: Path) -> list[str]:
    """Validate required SARIF 2.1.0 structure and GitHub's stricter URI contract.

    GitHub code scanning once refused an upload that parsed perfectly well because one
    `artifactLocation.uri` looked like a URI scheme.  The previous checker consequently
    focused only on paths and would itself crash on valid JSON of the wrong shape.  Keep
    the consumer-specific checks, but first verify the required document/run/tool/result
    types so a green check is meaningful and malformed input always yields diagnostics.
    """
    problems: list[str] = []

    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [f"unreadable: {exc}"]

    if not isinstance(doc, dict):
        return ["document root must be an object"]

    if doc.get("$schema") not in (None, SCHEMA):
        problems.append(f"$schema is {doc.get('$schema')!r}, expected {SCHEMA!r}")
    if doc.get("version") != VERSION:
        problems.append(f"version is {doc.get('version')!r}, expected {VERSION!r}")

    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        problems.append("runs must be a non-empty array")
        return problems

    for run_index, run in enumerate(runs):
        run_where = f"runs[{run_index}]"
        if not isinstance(run, dict):
            problems.append(f"{run_where}: run must be an object")
            continue

        driver = (
            (run.get("tool") or {}).get("driver") if isinstance(run.get("tool"), dict) else None
        )
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
            problems.append(f"{run_where}: tool.driver.name must be a string")

        results = run.get("results", [])
        if not isinstance(results, list):
            problems.append(f"{run_where}: results must be an array")
            continue

        for result_index, result in enumerate(results):
            where = f"runs[{run_index}].results[{result_index}]"

            if not isinstance(result, dict):
                problems.append(f"{where}: result must be an object")
                continue

            if not isinstance(result.get("ruleId"), str) or not result["ruleId"]:
                problems.append(f"{where}: no ruleId")

            level = result.get("level")
            if level not in {None, "none", "note", "warning", "error"}:
                problems.append(f"{where}: invalid level {level!r}")

            message = result.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("text"), str):
                problems.append(f"{where}: message.text must be a string")

            locations = result.get("locations", [])
            if not isinstance(locations, list):
                problems.append(f"{where}: locations must be an array")
                continue

            for location_index, loc in enumerate(locations):
                if not isinstance(loc, dict):
                    problems.append(f"{where}.locations[{location_index}]: must be an object")
                    continue
                physical = loc.get("physicalLocation")
                if not isinstance(physical, dict):
                    problems.append(
                        f"{where}.locations[{location_index}]: physicalLocation must be an object"
                    )
                    continue
                artifact_location = physical.get("artifactLocation")
                if not isinstance(artifact_location, dict):
                    problems.append(
                        f"{where}.locations[{location_index}]: artifactLocation must be an object"
                    )
                    continue
                uri = artifact_location.get("uri", "")
                if not uri:
                    problems.append(f"{where}: location with no uri")
                elif not isinstance(uri, str):
                    problems.append(f"{where}: location uri must be a string")
                elif re.match(r"^[A-Za-z][A-Za-z0-9+.\-]*:", uri):
                    problems.append(
                        f"{where}: uri {uri!r} starts with what looks like a scheme — "
                        "code scanning will reject the upload"
                    )
                elif uri.startswith("/"):
                    problems.append(f"{where}: uri {uri!r} is absolute, must be repo-relative")
                elif " " in uri:
                    problems.append(f"{where}: uri {uri!r} contains a space")

    return problems


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="divergence.core.sarif")
    parser.add_argument("--check", type=Path, required=True, help="SARIF file to validate")
    args = parser.parse_args(argv)

    problems = check(args.check)
    if problems:
        print(f"{args.check}: {len(problems)} problem(s)")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print(f"{args.check}: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
