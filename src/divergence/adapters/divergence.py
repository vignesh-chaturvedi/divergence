"""The Divergence scanner itself, as a benchmark adapter.

At P1 this is the deterministic core and nothing else: acquisition, the declared-interface
analyzer, and the manifest ledger. No model runs, so the marginal cost of a scan is zero
and the results are reproducible offline by construction.

Registering it as an adapter means it is scored by exactly the same code path as every
third-party baseline. There is no privileged route for our own numbers.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from divergence.adapters.base import register
from divergence.core.fleet import analyze_fleet, build_fleet
from divergence.core.pipeline import dedupe, load, scan as scan_artifact
from divergence.core.ledger import Ledger
from divergence.bench.models import Sample
from divergence.core.vocabulary import Finding


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
        return "0.1.0-p4"

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


register(DivergenceScanner())
register(DivergenceScanner(fleet=True))
