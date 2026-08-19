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
from divergence.core.pipeline import load
from divergence.core.declared import analyze_declared
from divergence.core.engine import analyze_divergence
from divergence.core.ledger import Ledger
from divergence.bench.models import Sample
from divergence.core.vocabulary import Finding


class DivergenceScanner:
    """A1 acquisition + A2 declared interface + A3 ledger + A4 behaviour + A6 divergence."""

    name = "divergence"
    homepage = "https://github.com/vignesh-chaturvedi/divergence"
    kind = "reference"

    def probe(self) -> str:
        return "0.1.0-p3"

    def scan(self, sample: Sample) -> list[Finding]:
        artifact, behaviour = load(sample.artifact_path)

        findings = analyze_declared(artifact, behaviour, sample_id=sample.id)
        findings += analyze_divergence(artifact, behaviour, sample_id=sample.id)
        findings += self._ledger_findings(sample, artifact)

        return findings

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
