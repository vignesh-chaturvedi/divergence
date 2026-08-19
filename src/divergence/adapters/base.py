"""The adapter contract.

Kept deliberately small. A scanner that only produces a boolean per sample is still a
valid baseline — it will simply score badly on attribution, which is itself a finding
worth publishing.
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

from divergence.bench.models import Finding, Sample, SampleResult, ScanRun


class ScannerUnavailable(Exception):
    """Raised by `probe()` when the underlying tool is not installed or not runnable.

    This is an ordinary outcome, not a crash. An unavailable baseline still appears in
    the comparison table, marked as not run — omitting it would quietly flatter whatever
    scanners *did* run.
    """


@runtime_checkable
class Adapter(Protocol):
    """What every baseline scanner must provide."""

    name: str
    homepage: str
    kind: str  # "reference" for in-repo strawmen, "external" for third-party tools

    def probe(self) -> str:
        """Return the tool's version string, or raise ScannerUnavailable."""
        ...

    def scan(self, sample: Sample) -> list[Finding]:
        """Run the scanner over one sample and normalise its output."""
        ...


registry: dict[str, Adapter] = {}


def register(adapter: Adapter) -> Adapter:
    """Add an adapter to the registry. Decorator-friendly."""
    if adapter.name in registry:
        raise ValueError(f"duplicate adapter name: {adapter.name}")
    registry[adapter.name] = adapter
    return adapter


def get_adapter(name: str) -> Adapter:
    if name not in registry:
        known = ", ".join(sorted(registry)) or "none registered"
        raise KeyError(f"unknown scanner {name!r}. Known: {known}")
    return registry[name]


def available_adapters() -> list[Adapter]:
    """Every registered adapter, reference implementations first, then alphabetical."""
    return sorted(registry.values(), key=lambda a: (a.kind != "reference", a.name))


def run_adapter(adapter: Adapter, samples: list[Sample]) -> ScanRun:
    """Drive one adapter across the corpus, isolating its failures.

    A scanner that throws on one sample must not take down the whole run — a partial
    baseline is still a baseline, and the error count appears in the table.
    """
    started = time.perf_counter()

    try:
        version = adapter.probe()
    except ScannerUnavailable as exc:
        return ScanRun(
            scanner=adapter.name,
            available=False,
            unavailable_reason=str(exc),
            duration_s=time.perf_counter() - started,
        )

    run = ScanRun(scanner=adapter.name, version=version, available=True)

    for sample in samples:
        sample_started = time.perf_counter()
        try:
            findings = tuple(adapter.scan(sample))
            error = None
        except Exception as exc:  # noqa: BLE001 — a baseline crashing is data, not a bug
            findings, error = (), f"{type(exc).__name__}: {exc}"

        run.results[sample.id] = SampleResult(
            sample_id=sample.id,
            findings=findings,
            error=error,
            duration_s=time.perf_counter() - sample_started,
        )

    run.duration_s = time.perf_counter() - started
    return run
