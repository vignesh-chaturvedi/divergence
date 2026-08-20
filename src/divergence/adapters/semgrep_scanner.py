"""Adapter for semgrep, run once over the whole corpus.

Semgrep is not an MCP scanner — it is a general static-analysis tool with a security
ruleset. It is in the comparison precisely *because* of that: it represents what you get
from applying conventional application-security tooling to this problem, which is the
approach §01 argues cannot work here. Its results are a useful floor for "generic SAST
applied to agent artifacts".

Run in a single invocation rather than per sample: loading the ruleset dominates the cost,
so 80 invocations would take minutes for no additional signal. Results are split back out
by file path.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from divergence.adapters.base import ScannerUnavailable, register
from divergence.adapters.external import OPT_IN_ENV, external_enabled, map_attack_class
from divergence.bench.models import Sample
from divergence.core.vocabulary import Channel, Finding

RULESET_ENV = "DIVERGENCE_SEMGREP_RULESET"
SEMGREP_SPEC = "semgrep@1.173.0"
TIMEOUT_S = 1800

_POSTURE_LEVELS = {"note", "info", "informational"}


def ruleset_sha256(root: Path) -> str:
    """Hash a local rules file/directory without checkout-specific path prefixes."""
    root = root.resolve()
    files = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
    digest = hashlib.sha256()
    for path in files:
        relative = path.name if root.is_file() else path.relative_to(root).as_posix()
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def split_by_sample(sarif: dict, roots: dict[str, Path]) -> dict[str, list[dict]]:
    """Attribute each SARIF result to the sample whose directory contains it."""
    by_sample: dict[str, list[dict]] = {}

    # Longest path first, so a nested sample wins over an ancestor.
    ordered = sorted(roots.items(), key=lambda kv: len(str(kv[1])), reverse=True)

    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations") or []
            if not locations:
                continue
            uri = (
                (locations[0].get("physicalLocation") or {})
                .get("artifactLocation", {})
                .get("uri", "")
            )
            if not uri:
                continue

            for sample_id, root in ordered:
                if str(root) in uri or uri.startswith(str(root).lstrip("/")):
                    by_sample.setdefault(sample_id, []).append(result)
                    break

    return by_sample


class SemgrepAdapter:
    name = "semgrep"
    homepage = "https://semgrep.dev"
    kind = "external"

    def __init__(self) -> None:
        self._results: dict[str, list[dict]] = {}
        self._ruleset: Path | None = None

    def _configured_ruleset(self) -> Path | None:
        raw = os.environ.get(RULESET_ENV, "").strip()
        return Path(raw).expanduser().resolve() if raw else None

    def provenance(self) -> dict[str, object]:
        ruleset = self._ruleset or self._configured_ruleset()
        digest = ruleset_sha256(ruleset) if ruleset and ruleset.exists() else None
        # A content hash makes the snapshot reproducible; an absolute checkout path does
        # not. Keep release JSON free of workstation-specific usernames and directories.
        ruleset_ref = ruleset.name if ruleset else None
        return {
            "scanner_command": [
                "uvx",
                SEMGREP_SPEC,
                "scan",
                "--sarif",
                "--quiet",
                "--no-git-ignore",
                "--config",
                ruleset_ref or f"${RULESET_ENV}",
                "<corpus>",
            ],
            "ruleset": ruleset_ref,
            "ruleset_sha256": digest,
            "ruleset_mutable": False,
            "ruleset_policy": "explicit local snapshot required",
            "package_spec": SEMGREP_SPEC,
        }

    def probe(self) -> str:
        if not external_enabled():
            raise ScannerUnavailable(
                f"not run — third-party execution is opt-in. Set {OPT_IN_ENV}=1 to enable."
            )
        if shutil.which("uvx") is None:
            raise ScannerUnavailable(
                "'uvx' not on PATH; it is required to run the pinned Semgrep package."
            )
        ruleset = self._configured_ruleset()
        if ruleset is None:
            raise ScannerUnavailable(
                f"no pinned rules snapshot configured. Set {RULESET_ENV} to a local file "
                "or directory; remote registry aliases are intentionally rejected."
            )
        if not ruleset.exists() or not (ruleset.is_file() or ruleset.is_dir()):
            raise ScannerUnavailable(f"configured Semgrep rules path does not exist: {ruleset}")
        self._ruleset = ruleset
        proc = subprocess.run(
            ["uvx", SEMGREP_SPEC, "--version"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode != 0:
            raise ScannerUnavailable(f"probe exited {proc.returncode}")
        version = proc.stdout.strip().splitlines()[0][:20]
        return f"{version}; rules={ruleset_sha256(ruleset)[:12]}"

    def prepare(self, samples: list[Sample]) -> None:
        self._results = {}
        roots = {s.id: s.artifact_path.resolve() for s in samples}
        if not roots:
            return

        common = os.path.commonpath([str(p) for p in roots.values()])
        if self._ruleset is None:
            raise ScannerUnavailable("Semgrep rules snapshot was not configured during probe")

        proc = subprocess.run(
            [
                "uvx",
                SEMGREP_SPEC,
                "scan",
                "--sarif",
                "--quiet",
                "--no-git-ignore",
                "--config",
                str(self._ruleset),
                common,
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT_S,
        )

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            raise ScannerUnavailable(
                f"Semgrep scan exited {proc.returncode}: "
                f"{detail[0][:300] if detail else 'no output'}"
            )

        try:
            sarif = json.loads(proc.stdout)
        except (json.JSONDecodeError, TypeError):
            raise ScannerUnavailable("Semgrep scan emitted invalid SARIF JSON") from None
        if not isinstance(sarif, dict) or not isinstance(sarif.get("runs"), list):
            raise ScannerUnavailable("Semgrep scan emitted an invalid SARIF document")

        self._results = split_by_sample(sarif, roots)

    def scan(self, sample: Sample) -> list[Finding]:
        findings: list[Finding] = []

        for result in self._results.get(sample.id, []):
            level = str(result.get("level", "warning")).lower()
            rule = str(result.get("ruleId", ""))
            message = str((result.get("message") or {}).get("text", ""))[:200]

            region = (
                (result.get("locations") or [{}])[0].get("physicalLocation", {}).get("region", {})
            )
            line = region.get("startLine", "")

            findings.append(
                Finding(
                    sample_id=sample.id,
                    channel=Channel.POSTURE if level in _POSTURE_LEVELS else Channel.RISK,
                    attack_class=map_attack_class(rule.rsplit(".", 1)[-1]),
                    severity=level,
                    message=message,
                    evidence=f"semgrep:{line}" if line else "semgrep",
                    claim="semgrep rule match",
                )
            )

        return findings


register(SemgrepAdapter())
