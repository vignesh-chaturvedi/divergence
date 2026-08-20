"""Adapter for mcp-shield, driven through the manifest shim.

mcp-shield analyses **live** MCP servers: it reads a client config, launches each server,
calls `tools/list`, and reasons about the tool descriptions it gets back. The corpus is
static source, so the two only meet through `bench/manifest_shim.py`, which serves each
sample's declared manifest without executing its implementation.

Two consequences worth stating plainly, because both affect how the comparison should be
read:

- **Skills are out of scope.** mcp-shield has no notion of an agent skill. Those samples
  are reported `not_applicable` rather than as misses — counting them would manufacture a
  recall gap out of a scope difference and flatter this project's numbers.
- **It sees the manifest, not the handler.** That is what it analyses anyway, so the shim
  is faithful. But behavioural attacks whose payload lives in the implementation are
  invisible to it by design, not by defect.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from divergence.adapters.base import ScannerUnavailable, register
from divergence.adapters.external import OPT_IN_ENV, external_enabled
from divergence.bench.models import Kind, Sample
from divergence.core.vocabulary import AttackClass, Channel, Finding

TIMEOUT_S = 900
PACKAGE_SPEC = "mcp-shield@1.0.4"

_ISSUE_CLASSES: list[tuple[str, AttackClass]] = [
    ("hidden instruction", AttackClass.DESCRIPTION_POISONING),
    ("prompt injection", AttackClass.DESCRIPTION_POISONING),
    ("cross-origin", AttackClass.CROSS_TOOL_INSTRUCTION),
    ("shadow", AttackClass.SHADOWING),
    ("exfiltration", AttackClass.UNDECLARED_NETWORK),
    ("sensitive file", AttackClass.UNDECLARED_SECRETS),
    ("tool poisoning", AttackClass.DESCRIPTION_POISONING),
]

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\[[0-9]*[A-Z]")
_SERVER_RE = re.compile(r"^\s*\d+\.\s*Server:\s*(\S+)", re.M)
_RISK_RE = re.compile(r"Risk Level:\s*(\w+)")


def classify(issue_text: str) -> AttackClass | None:
    low = issue_text.lower()
    for needle, attack_class in _ISSUE_CLASSES:
        if needle in low:
            return attack_class
    return None


def parse_report(stdout: str) -> dict[str, list[tuple[str, str]]]:
    """Parse mcp-shield's human-readable report into {server_id: [(risk, issue), ...]}.

    There is no `--json` flag, so the text is the interface. Split out from the subprocess
    call so it can be tested against a captured fixture with the tool absent — the same
    reasoning as every other adapter here.
    """
    clean = _ANSI_RE.sub("", stdout)

    # The report repeats as it streams; the vulnerabilities block is the last section.
    marker = clean.rfind("Vulnerabilities Detected")
    if marker == -1:
        return {}
    block = clean[marker:]

    results: dict[str, list[tuple[str, str]]] = {}
    entries = list(_SERVER_RE.finditer(block))

    for index, match in enumerate(entries):
        server = match.group(1).strip()
        end = entries[index + 1].start() if index + 1 < len(entries) else len(block)
        section = block[match.end() : end]

        risk_match = _RISK_RE.search(section)
        risk = risk_match.group(1).lower() if risk_match else "unknown"

        issues = [
            line.strip().lstrip("–-— ").strip()
            for line in section.splitlines()
            if line.strip().startswith(("–", "-", "—")) and len(line.strip()) > 2
        ]
        if not issues:
            issues = ["reported without detail"]

        results.setdefault(server, []).extend((risk, issue) for issue in issues)

    return results


class McpShieldAdapter:
    """mcp-shield, run once over a generated shim config."""

    name = "mcp-shield"
    homepage = "https://github.com/riseandignite/mcp-shield"
    kind = "external"

    def __init__(self) -> None:
        self._results: dict[str, list[tuple[str, str]]] = {}
        self._scoped: set[str] = set()

    def provenance(self) -> dict[str, object]:
        return {
            "package_spec": PACKAGE_SPEC,
            "scanner_command": ["npx", "--yes", PACKAGE_SPEC, "--path", "<manifest-shim>"],
            "input_adapter": "divergence.bench.manifest_shim",
        }

    def probe(self) -> str:
        if not external_enabled():
            raise ScannerUnavailable(
                f"not run — third-party execution is opt-in. Set {OPT_IN_ENV}=1 to enable."
            )
        if shutil.which("npx") is None:
            raise ScannerUnavailable("'npx' not on PATH. Requires Node.")

        proc = subprocess.run(
            ["npx", "--yes", PACKAGE_SPEC, "--version"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            raise ScannerUnavailable(f"probe exited {proc.returncode}")
        return (proc.stdout or proc.stderr).strip().splitlines()[0][:40]

    def prepare(self, samples: list[Sample]) -> None:
        """Build a shim config for every MCP-server sample and scan it in one pass."""
        self._results = {}
        self._scoped = set()

        servers: dict[str, dict] = {}
        repo_src = str(Path(__file__).resolve().parents[2])

        for sample in samples:
            if sample.kind is not Kind.MCP_SERVER:
                continue
            manifest = sample.artifact_path / "manifest.json"
            if not manifest.is_file():
                continue

            self._scoped.add(sample.id)
            servers[sample.id] = {
                "command": sys.executable,
                "args": ["-m", "divergence.bench.manifest_shim", str(manifest)],
                "env": {"PYTHONPATH": repo_src},
            }

        if not servers:
            return

        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "shim-config.json"
            config.write_text(json.dumps({"mcpServers": servers}, indent=2))

            proc = subprocess.run(
                ["npx", "--yes", PACKAGE_SPEC, "--path", str(config)],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_S,
            )

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            raise ScannerUnavailable(
                f"mcp-shield scan exited {proc.returncode}: "
                f"{detail[0][:300] if detail else 'no output'}"
            )

        self._results = parse_report(proc.stdout + "\n" + proc.stderr)

    def scan(self, sample: Sample) -> list[Finding]:
        if sample.id not in self._scoped:
            raise NotApplicable(f"mcp-shield does not analyse {sample.kind.value}")

        findings: list[Finding] = []
        for risk, issue in self._results.get(sample.id, []):
            findings.append(
                Finding(
                    sample_id=sample.id,
                    channel=Channel.POSTURE if risk in ("info", "low") else Channel.RISK,
                    attack_class=classify(issue),
                    severity=risk,
                    message=issue,
                    evidence="mcp-shield: tools/list",
                    claim="mcp-shield report",
                )
            )
        return findings


class NotApplicable(Exception):
    """Raised when a scanner structurally cannot analyse an artifact kind."""


register(McpShieldAdapter())
