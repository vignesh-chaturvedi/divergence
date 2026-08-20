"""The Divergence scanner itself, as a benchmark adapter.

At P1 this is the deterministic core and nothing else: acquisition, the declared-interface
analyzer, and the manifest ledger. No model runs, so the marginal cost of a scan is zero
and the results are reproducible offline by construction.

Registering it as an adapter means it is scored by exactly the same code path as every
third-party baseline. There is no privileged route for our own numbers.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from divergence import __version__
from divergence.adapters.base import ScannerUnavailable, register
from divergence.bench.models import Sample
from divergence.core.fleet import analyze_fleet, build_fleet
from divergence.core.ledger import Ledger
from divergence.core.pipeline import (
    ScanOptions,
    dedupe,
    load,
    scan_detailed,
)
from divergence.core.pipeline import (
    scan as scan_artifact,
)
from divergence.core.sandbox import availability, find_binary
from divergence.core.vocabulary import Finding

DYNAMIC_OPT_IN_ENV = "DIVERGENCE_ALLOW_DYNAMIC"


class DivergenceScanner:
    """A1 acquisition + A2 declared interface + A3 ledger + A4 behaviour + A6 divergence.

    With `fleet=True`, A7's cross-artifact analyzers run once over the whole set and their
    findings are merged per artifact. Kept as a flag rather than folded in silently, so the
    contribution of fleet analysis is a number the writeup can report rather than an
    unattributed lift.
    """

    homepage = "https://github.com/vignesh-chaturvedi/divergence"
    kind = "reference"

    def __init__(self, *, fleet: bool = False) -> None:
        self.fleet = fleet
        self.name = "divergence+fleet" if fleet else "divergence"
        self._fleet_findings: dict[str, list[Finding]] = {}

    def probe(self) -> str:
        return __version__

    def provenance(self) -> dict[str, object]:
        return {
            "distribution": "divergence-mcp",
            "analysis_tier": "static+fleet" if self.fleet else "static",
            "scanner_command": ["divergence", "fleet" if self.fleet else "scan", "<artifact>"],
        }

    def prepare(self, samples: list[Sample]) -> None:
        """Run A7 over the whole set once. Only meaningful across artifacts."""
        self._fleet_findings = {}
        if not self.fleet:
            return

        built = build_fleet([(s.id, s.artifact_path) for s in samples], name="corpus")
        for finding in analyze_fleet(built):
            self._fleet_findings.setdefault(finding.sample_id, []).append(finding)

    def scan(self, sample: Sample) -> list[Finding]:
        artifact, _, findings = scan_artifact(sample.artifact_path, artifact_id=sample.id)

        findings += self._ledger_findings(sample, artifact)
        findings += self._fleet_findings.get(sample.id, [])

        return dedupe(findings)

    def _ledger_findings(self, sample: Sample, artifact) -> list[Finding]:
        """Drive A3 over an artifact that ships more than one version.

        Approve the earliest snapshot, then diff the latest against it. A rug pull is
        invisible without this: each snapshot on its own is internally consistent, and
        the finding lives entirely in the transition between them.

        The ledger is temporary and per-scan so a benchmark run stays reproducible — a
        persistent database would make the second `make bench` disagree with the first.
        """
        if len(artifact.snapshots) < 2:
            return []

        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "ledger.db")
            approved, _ = load(artifact.snapshots[0].root)
            current, _ = load(artifact.snapshots[-1].root)

            ledger.record(approved, artifact_id=sample.id)
            return ledger.diff(current, artifact_id=sample.id)


class DivergenceDynamicScanner:
    """Static Divergence plus opt-in, fail-closed B_dynamic observation."""

    name = "divergence+dynamic"
    homepage = "https://github.com/vignesh-chaturvedi/divergence"
    kind = "reference"
    version = __version__

    def __init__(self) -> None:
        self._coverage: dict[str, dict[str, object]] = {}
        self._static = DivergenceScanner()

    def probe(self) -> str:
        state = availability()
        if not state.available:
            raise ScannerUnavailable(state.unavailable_reason)
        if os.environ.get(DYNAMIC_OPT_IN_ENV, "").strip().lower() not in {"1", "true", "yes"}:
            raise ScannerUnavailable(
                f"not run — dynamic execution is opt-in. Set {DYNAMIC_OPT_IN_ENV}=1 to enable."
            )
        return __version__

    def prepare(self, samples: list[Sample]) -> None:
        self._coverage = {}

    def scan(self, sample: Sample) -> list[Finding]:
        report = scan_detailed(
            sample.artifact_path,
            artifact_id=sample.id,
            options=ScanOptions(dynamic=True),
        )
        dynamic = report.dynamic
        if dynamic is None or not dynamic.available:
            reason = dynamic.unavailable_reason if dynamic else "no dynamic result"
            raise ScannerUnavailable(reason)

        self._coverage[sample.id] = {
            "syscalls_observed": dynamic.syscalls_observed,
            "entrypoints_invoked": dynamic.entrypoints_invoked,
            "exited_cleanly": dynamic.exited_cleanly,
            "timed_out": dynamic.timed_out,
            "ran": dynamic.ran,
            "limitations": list(dynamic.limitations),
        }
        # The benchmark's static row also models multi-snapshot approval-ledger changes.
        # Dynamic observation is additive: opting in must never discard a deterministic
        # finding merely because that finding lives across versions rather than inside the
        # current snapshot.
        findings = list(report.findings)
        findings += self._static._ledger_findings(sample, report.artifact)
        return dedupe(findings)

    def provenance(self) -> dict[str, object]:
        state = availability()
        binary = find_binary()
        binary_sha256 = None
        if binary:
            try:
                binary_sha256 = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
            except OSError:
                pass
        return {
            "distribution": "divergence-mcp",
            "analysis_tier": "static+dynamic",
            "opt_in_environment": DYNAMIC_OPT_IN_ENV,
            "sandbox_binary": binary,
            "sandbox_binary_sha256": binary_sha256,
            "sandbox_available": state.available,
            "sandbox_unavailable_reason": state.unavailable_reason,
            "coverage": dict(sorted(self._coverage.items())),
        }


register(DivergenceScanner())
register(DivergenceScanner(fleet=True))
register(DivergenceDynamicScanner())
