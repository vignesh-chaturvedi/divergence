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
from pathlib import Path

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


def _split_location(evidence: str) -> tuple[str, int | None]:
    """Split a `file:line` evidence string, tolerating either half being absent."""
    if not evidence:
        return "", None
    head, _, tail = evidence.rpartition(":")
    if head and tail.isdigit():
        return head, int(tail)
    return evidence, None


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


def _result(finding: Finding, base: Path | None) -> dict:
    uri, line = _split_location(finding.evidence)

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
        },
    }

    if uri:
        physical: dict = {"artifactLocation": {"uri": uri}}
        if line is not None:
            physical["region"] = {"startLine": line}
        result["locations"] = [{"physicalLocation": physical}]

    return result


def to_sarif(findings: list[Finding], *, base: Path | None = None, version: str = "0.1.0") -> dict:
    """Render findings as a SARIF 2.1.0 log."""
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
                "results": [_result(f, base) for f in findings],
            }
        ],
    }


def dumps(findings: list[Finding], **kwargs) -> str:
    return json.dumps(to_sarif(findings, **kwargs), indent=2, sort_keys=False)
