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
    probe_override: Callable[[], str] | None = None
    kind: str = field(default="external", init=False)

    def probe(self) -> str:
        # Some scanners have preconditions a version check cannot express — a required
        # account token, a hosted API. Those get to answer for themselves.
        if self.probe_override is not None:
            return self.probe_override()

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

# mcp-shield has a dedicated adapter in `adapters/mcp_shield.py`: it analyses a live
# server rather than a directory, so it needs the manifest shim and a one-pass run.

# semgrep has a dedicated adapter in `adapters/semgrep_scanner.py`: rule loading
# dominates its cost, so it runs once over the whole corpus rather than per sample.

# `mcp-scan`, the most-cited scanner in this space, is now published as `snyk-agent-scan`
# and is a Snyk product. Three things about it are worth recording, because together they
# decide whether it can be in a reproducible benchmark at all:
#
#   1. It analyses a *live* server from a client config, so it needs the manifest shim.
#   2. It transmits tool descriptions to a hosted Snyk analysis API — there is no offline
#      mode; `--analysis-url` only redirects the verification server.
#   3. **It requires a `SNYK_TOKEN` from a Snyk account.** Without one it exits before
#      scanning anything.
#
# (3) is the binding constraint. A benchmark that cannot be reproduced without a vendor
# account is not reproducible, so this adapter reports itself unavailable rather than
# silently scoring zero. If a token is present in the environment it will run.
# See docs/adr/0006.


def _snyk_probe() -> str:
    if not external_enabled():
        raise ScannerUnavailable(
            f"not run — third-party execution is opt-in. Set {OPT_IN_ENV}=1 to enable."
        )
    if shutil.which("uvx") is None:
        raise ScannerUnavailable("uvx not on PATH")
    if not os.environ.get("SNYK_TOKEN"):
        raise ScannerUnavailable(
            "requires a SNYK_TOKEN from a Snyk account, and transmits tool descriptions "
            "to a hosted API — cannot be part of an offline reproducible benchmark"
        )
    return "snyk-agent-scan (token present)"


register(
    ExternalAdapter(
        name="snyk-agent-scan",
        homepage="https://github.com/snyk/agent-scan",
        probe_cmd=["uvx", "snyk-agent-scan@latest", "--help"],
        scan_cmd=lambda s: ["uvx", "snyk-agent-scan@latest", "scan", "--json"],
        parse=parse_flat_json_issues,
        install_hint=(
            "Requires a SNYK_TOKEN and transmits tool descriptions to a hosted Snyk API."
        ),
        probe_override=_snyk_probe,
    )
)
