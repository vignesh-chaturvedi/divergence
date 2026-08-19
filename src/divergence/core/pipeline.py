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
from divergence.core.declared import analyze_declared
from divergence.core.engine import analyze_divergence
from divergence.core.vocabulary import Finding


def load(root: Path | str) -> tuple[Artifact, Behaviour]:
    """Acquire the declared surface and extract B_s against it."""
    artifact = acquire(Path(root))
    behaviour = extract(
        artifact.root, entrypoint_names=frozenset(t.name for t in artifact.tools)
    )
    return artifact, behaviour


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse repeats of the same class on the same artifact, keeping the strongest.

    Several analyzers legitimately reach the same conclusion by different routes. Saying
    it twice is noise.
    """
    best: dict[tuple, Finding] = {}
    passthrough: list[Finding] = []

    for finding in findings:
        if finding.attack_class is None:
            passthrough.append(finding)
            continue
        key = (finding.sample_id, finding.attack_class, finding.channel)
        current = best.get(key)
        if current is None or finding.confidence > current.confidence:
            best[key] = finding

    return list(best.values()) + passthrough


def scan(root: Path | str, *, artifact_id: str = "") -> tuple[Artifact, Behaviour, list[Finding]]:
    """Analyse one artifact with every single-artifact analyzer.

    **This is the only place the analyzers are composed.** The CLI and the benchmark
    adapter both call it, because they must not be able to disagree about what a scan is.

    They did disagree, silently, from P3 until the v1 checkpoint: `divergence scan` ran
    the declared-interface checks and never called the divergence engine at all, so the
    shipped command was missing the project's headline capability while every benchmark
    number said otherwise. Unit tests called the analyzers directly and the benchmark went
    through the adapter, so nothing exercised the path a user actually runs.
    """
    artifact, behaviour = load(root)
    findings = analyze_declared(artifact, behaviour, sample_id=artifact_id)
    findings += analyze_divergence(artifact, behaviour, sample_id=artifact_id)
    return artifact, behaviour, dedupe(findings)
