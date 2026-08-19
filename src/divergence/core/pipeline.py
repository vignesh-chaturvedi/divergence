"""One way to load an artifact for analysis.

`acquire` and `extract` must be called together and in order: the declared surface names
the handlers, and B_s extraction needs those names to find handlers that no decorator
marks. Leaving that to each call site is a footgun — a caller that forgets produces an
artifact whose capabilities all look unreachable, and reports nothing.
"""

from __future__ import annotations

from pathlib import Path

from divergence.core.acquire import Artifact, acquire
from divergence.core.behaviour import Behaviour, extract


def load(root: Path | str) -> tuple[Artifact, Behaviour]:
    """Acquire the declared surface and extract B_s against it."""
    artifact = acquire(Path(root))
    behaviour = extract(
        artifact.root, entrypoint_names=frozenset(t.name for t in artifact.tools)
    )
    return artifact, behaviour
