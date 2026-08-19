"""Adapters for third-party open-source scanners.

These are wired but **gated**. Each one is a real subprocess adapter — probe command,
run command, output parser — and none of them will fetch or execute anything until the
opt-in is set:

    DIVERGENCE_ALLOW_EXTERNAL=1 make bench

Without it every external adapter reports `not run` with a reason, appears in the
comparison table as a blank row, and touches nothing. This is deliberate: running these
tools means downloading and executing third-party code, and a benchmark that does that
silently on `make bench` is a benchmark nobody should run.

The parsers are written against each tool's documented output shape and are exercised
by fixture tests in `tests/test_external_parsers.py`, so they are verified without any
of these tools being installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from divergence.adapters.base import ScannerUnavailable, register
from divergence.bench.models import AttackClass, Channel, Finding, Sample

OPT_IN_ENV = "DIVERGENCE_ALLOW_EXTERNAL"
TIMEOUT_S = 120


def external_enabled() -> bool:
    return os.environ.get(OPT_IN_ENV, "").strip().lower() in {"1", "true", "yes"}


# Best-effort mapping from the vocabulary these tools use to ours. Anything unmapped
# stays None, which costs the tool attribution credit but never detection credit — we
# do not want our own taxonomy to penalise a scanner for naming things differently.
_CLASS_ALIASES: dict[str, AttackClass] = {
    "prompt_injection": AttackClass.DESCRIPTION_POISONING,
    "prompt-injection": AttackClass.DESCRIPTION_POISONING,
    "tool_poisoning": AttackClass.DESCRIPTION_POISONING,
    "toxic_description": AttackClass.DESCRIPTION_POISONING,
    "schema_injection": AttackClass.SCHEMA_POISONING,
    "tool_shadowing": AttackClass.SHADOWING,
    "cross_origin": AttackClass.CROSS_TOOL_INSTRUCTION,
    "cross_origin_violation": AttackClass.CROSS_TOOL_INSTRUCTION,
    "exfiltration": AttackClass.UNDECLARED_NETWORK,
    "data_exfiltration": AttackClass.UNDECLARED_NETWORK,
    "credential_access": AttackClass.UNDECLARED_SECRETS,
    "command_injection": AttackClass.UNDECLARED_EXEC,
    "obfuscation": AttackClass.DYNAMIC_CODE_LOADING,
    "rug_pull": AttackClass.POST_APPROVAL_MUTATION,
    "toolchain_drift": AttackClass.POST_APPROVAL_MUTATION,
}


def map_attack_class(raw: str | None) -> AttackClass | None:
    if not raw:
        return None
    key = str(raw).strip().lower().replace(" ", "_").replace("-", "_")
    if key in _CLASS_ALIASES:
        return _CLASS_ALIASES[key]
    try:
        return AttackClass(key)
    except ValueError:
        return None


def _severity_is_posture(severity: str) -> bool:
    """Most tools have no posture channel. The few that do signal it as info/low/note."""
    return severity.strip().lower() in {"info", "informational", "note", "low", "notice"}


@dataclass
class ExternalAdapter:
    """A third-party scanner driven as a subprocess.

    `parse` receives the process stdout and returns normalised findings. Splitting the
    parser out is what lets it be unit-tested against captured fixtures with the tool
    itself absent.
    """

    name: str
    homepage: str
    probe_cmd: list[str]
    scan_cmd: Callable[[Sample], list[str]]
    parse: Callable[[str, Sample], list[Finding]]
    install_hint: str = ""
    kind: str = field(default="external", init=False)

    def probe(self) -> str:
        if not external_enabled():
            raise ScannerUnavailable(
                f"not run — third-party execution is opt-in. Set {OPT_IN_ENV}=1 to enable."
            )

        exe = self.probe_cmd[0]
        if shutil.which(exe) is None:
            raise ScannerUnavailable(f"{exe!r} not on PATH. {self.install_hint}".strip())

        try:
            proc = subprocess.run(
                self.probe_cmd, capture_output=True, text=True, timeout=TIMEOUT_S
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise ScannerUnavailable(f"probe failed: {exc}") from None

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            raise ScannerUnavailable(
                f"probe exited {proc.returncode}: {detail[0] if detail else 'no output'}"
            )

        return (proc.stdout or proc.stderr).strip().splitlines()[0][:80] or "unknown"

    def scan(self, sample: Sample) -> list[Finding]:
        proc = subprocess.run(
            self.scan_cmd(sample), capture_output=True, text=True, timeout=TIMEOUT_S
        )
        return self.parse(proc.stdout, sample)


# --- parsers ---------------------------------------------------------------------
# Each is written against the tool's documented JSON shape and pinned by a fixture test.


def parse_sarif(stdout: str, sample: Sample) -> list[Finding]:
    """SARIF 2.1.0 — the interchange format Divergence itself will emit."""
    try:
        doc = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            level = str(result.get("level", "warning"))
            rule = str(result.get("ruleId", ""))
            message = str((result.get("message") or {}).get("text", ""))

            locations = result.get("locations") or []
            evidence = ""
            if locations:
                phys = (locations[0].get("physicalLocation") or {})
                uri = ((phys.get("artifactLocation") or {}).get("uri", ""))
                line = ((phys.get("region") or {}).get("startLine", ""))
                evidence = f"{uri}:{line}".strip(":")

            findings.append(
                Finding(
                    sample_id=sample.id,
                    channel=Channel.POSTURE if _severity_is_posture(level) else Channel.RISK,
                    attack_class=map_attack_class(rule),
                    severity=level,
                    message=message,
                    evidence=evidence,
                )
            )
    return findings


def parse_flat_json_issues(stdout: str, sample: Sample) -> list[Finding]:
    """`{"issues": [{"type": ..., "severity": ..., "message": ...}]}` and close variants."""
    try:
        doc = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        return []

    if isinstance(doc, list):
        issues = doc
    else:
        issues = doc.get("issues") or doc.get("findings") or doc.get("results") or []

    findings: list[Finding] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        severity = str(issue.get("severity") or issue.get("level") or "unknown")
        raw_class = issue.get("type") or issue.get("category") or issue.get("rule")
        findings.append(
            Finding(
                sample_id=sample.id,
                channel=Channel.POSTURE if _severity_is_posture(severity) else Channel.RISK,
                attack_class=map_attack_class(raw_class),
                severity=severity,
                message=str(issue.get("message") or issue.get("description") or ""),
                evidence=str(issue.get("location") or issue.get("evidence") or ""),
            )
        )
    return findings


# --- the roster ------------------------------------------------------------------

register(
    ExternalAdapter(
        name="mcp-scan",
        homepage="https://github.com/invariantlabs-ai/mcp-scan",
        probe_cmd=["uvx", "mcp-scan@latest", "--version"],
        scan_cmd=lambda s: ["uvx", "mcp-scan@latest", "scan", "--json", str(s.artifact_path)],
        parse=parse_flat_json_issues,
        install_hint="Requires uv. Runs via `uvx mcp-scan@latest`.",
    )
)

register(
    ExternalAdapter(
        name="mcp-shield",
        homepage="https://github.com/riseandignite/mcp-shield",
        probe_cmd=["npx", "--yes", "mcp-shield", "--version"],
        scan_cmd=lambda s: ["npx", "--yes", "mcp-shield", "--path", str(s.artifact_path), "--json"],
        parse=parse_flat_json_issues,
        install_hint="Requires Node. Runs via `npx mcp-shield`.",
    )
)

register(
    ExternalAdapter(
        name="semgrep",
        homepage="https://semgrep.dev",
        probe_cmd=["semgrep", "--version"],
        scan_cmd=lambda s: ["semgrep", "scan", "--sarif", "--quiet", "--config", "auto", str(s.artifact_path)],
        parse=parse_sarif,
        install_hint="Install with `uv tool install semgrep`.",
    )
)

register(
    ExternalAdapter(
        name="mcp-scanner",
        homepage="https://github.com/cisco-ai-defense/mcp-scanner",
        probe_cmd=["uvx", "mcp-scanner", "--version"],
        scan_cmd=lambda s: ["uvx", "mcp-scanner", "--path", str(s.artifact_path), "--format", "json"],
        parse=parse_flat_json_issues,
        install_hint="Requires uv. Cisco AI Defense scanner.",
    )
)
