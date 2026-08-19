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

import json
import os
import shutil
import subprocess
from pathlib import Path

from divergence.adapters.base import ScannerUnavailable, register
from divergence.adapters.external import OPT_IN_ENV, external_enabled, map_attack_class
from divergence.bench.models import Sample
from divergence.core.vocabulary import Channel, Finding

RULESET = "p/security-audit"
TIMEOUT_S = 1800

_POSTURE_LEVELS = {"note", "info", "informational"}


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

    def probe(self) -> str:
        if not external_enabled():
            raise ScannerUnavailable(
                f"not run — third-party execution is opt-in. Set {OPT_IN_ENV}=1 to enable."
            )
        if shutil.which("semgrep") is None:
            raise ScannerUnavailable(
                "'semgrep' not on PATH. Install with `uv tool install semgrep`."
            )
        proc = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            raise ScannerUnavailable(f"probe exited {proc.returncode}")
        return proc.stdout.strip().splitlines()[0][:20]

    def prepare(self, samples: list[Sample]) -> None:
        self._results = {}
        roots = {s.id: s.artifact_path.resolve() for s in samples}
        if not roots:
            return

        common = os.path.commonpath([str(p) for p in roots.values()])

        proc = subprocess.run(
            [
                "semgrep", "scan", "--sarif", "--quiet", "--no-git-ignore",
                "--config", RULESET, common,
            ],
            capture_output=True, text=True, timeout=TIMEOUT_S,
        )

        try:
            sarif = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            sarif = {}

        self._results = split_by_sample(sarif, roots)

    def scan(self, sample: Sample) -> list[Finding]:
        findings: list[Finding] = []

        for result in self._results.get(sample.id, []):
            level = str(result.get("level", "warning")).lower()
            rule = str(result.get("ruleId", ""))
            message = str((result.get("message") or {}).get("text", ""))[:200]

            region = (
                (result.get("locations") or [{}])[0]
                .get("physicalLocation", {})
                .get("region", {})
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
