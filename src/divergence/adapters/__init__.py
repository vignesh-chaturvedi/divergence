"""Baseline scanner adapters.

An adapter's only job is to run some scanner over a corpus sample and collapse whatever
that scanner emits into `Finding` objects. Everything else — scoring, ranking, the
comparison table — is shared, so adding a competitor is a single file.
"""

from divergence.adapters.base import (
    Adapter,
    ScannerUnavailable,
    available_adapters,
    get_adapter,
    register,
    registry,
)

__all__ = [
    "Adapter",
    "ScannerUnavailable",
    "available_adapters",
    "get_adapter",
    "register",
    "registry",
]
