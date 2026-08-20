"""Loading and validating the corpus.

The validator is deliberately strict. A corpus whose samples drift out of shape stops
being ground truth, and the single most common way that happens is a sample landing
without a written rationale — the reviewer-facing half of a label. Every rule here
exists because skipping it would let the benchmark quietly become unreliable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from divergence.bench.models import (
    AttackClass,
    Capability,
    Channel,
    ExpectedFinding,
    Kind,
    Sample,
    Stratum,
    TrapFamily,
)

SAMPLE_FILE = "sample.yaml"
ARTIFACT_DIR = "artifact"

# A rationale shorter than this is not a rationale, it is a restatement of the label.
MIN_RATIONALE_CHARS = 120

ID_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Payload destinations permitted inside malicious samples. Samples are inert fixtures
# meant to be *read* by a scanner, so anything resolving off-box is a corpus bug.
ALLOWED_PAYLOAD_HOSTS = frozenset(
    {"localhost", "127.0.0.1", "0.0.0.0", "::1", "sinkhole.divergence.invalid"}
)
# `.invalid` is reserved by RFC 2606 and can never resolve. `.example` likewise.
ALLOWED_PAYLOAD_TLDS = (".invalid", ".example", ".test", ".localhost")

_URL_RE = re.compile(r"https?://([A-Za-z0-9._:-]+)")


class CorpusError(Exception):
    """Raised when the corpus is structurally unusable."""


@dataclass(frozen=True, slots=True)
class Violation:
    """One thing wrong with one sample."""

    sample_id: str
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.sample_id}: [{self.rule}] {self.detail}"


def _require(data: dict, key: str, sample_dir: Path):
    if key not in data:
        raise CorpusError(f"{sample_dir / SAMPLE_FILE}: missing required key '{key}'")
    return data[key]


def _coerce_enum(enum_cls, raw, sample_dir: Path, key: str):
    try:
        return enum_cls(raw)
    except ValueError:
        valid = ", ".join(m.value for m in enum_cls)
        raise CorpusError(
            f"{sample_dir / SAMPLE_FILE}: '{key}' has unknown value {raw!r}. Expected one of: {valid}"
        ) from None


def load_sample(sample_dir: Path) -> Sample:
    """Read one sample directory into a Sample.

    Raises CorpusError on anything that makes the sample unloadable. Softer problems —
    a thin rationale, a live payload host — are validation violations, not load errors,
    so that `validate` can report all of them at once instead of dying on the first.
    """
    manifest = sample_dir / SAMPLE_FILE
    if not manifest.is_file():
        raise CorpusError(f"{sample_dir}: no {SAMPLE_FILE}")

    try:
        data = yaml.safe_load(manifest.read_text()) or {}
    except yaml.YAMLError as exc:
        raise CorpusError(f"{manifest}: invalid YAML — {exc}") from None

    if not isinstance(data, dict):
        raise CorpusError(f"{manifest}: top level must be a mapping")

    sample_id = str(_require(data, "id", sample_dir))
    kind = _coerce_enum(Kind, _require(data, "kind", sample_dir), sample_dir, "kind")
    stratum = _coerce_enum(
        Stratum, _require(data, "stratum", sample_dir), sample_dir, "stratum"
    )

    label = data.get("label") or {}
    if not isinstance(label, dict):
        raise CorpusError(f"{manifest}: 'label' must be a mapping")

    attack_classes = tuple(
        _coerce_enum(AttackClass, a, sample_dir, "label.attack_classes")
        for a in (label.get("attack_classes") or [])
    )
    trap_families = tuple(
        _coerce_enum(TrapFamily, t, sample_dir, "label.trap_families")
        for t in (label.get("trap_families") or [])
    )

    expected = tuple(
        ExpectedFinding(
            attack_class=_coerce_enum(
                AttackClass, e["attack_class"], sample_dir, "expected.attack_class"
            ),
            channel=_coerce_enum(
                Channel, e.get("channel", "risk"), sample_dir, "expected.channel"
            ),
            evidence_hint=str(e.get("evidence_hint", "")),
        )
        for e in (data.get("expected") or [])
    )

    caps_block = data.get("capabilities") or {}
    verified = caps_block.get("verified")
    verified_capabilities = (
        None
        if verified is None
        else tuple(
            _coerce_enum(Capability, c, sample_dir, "capabilities.verified") for c in verified
        )
    )

    return Sample(
        id=sample_id,
        kind=kind,
        stratum=stratum,
        language=str(data.get("language", "none")),
        rationale=str(label.get("rationale", "")).strip(),
        path=sample_dir,
        artifact_path=sample_dir / ARTIFACT_DIR,
        attack_classes=attack_classes,
        trap_families=trap_families,
        expected=expected,
        tags=tuple(str(t) for t in (data.get("tags") or [])),
        notes=str(data.get("notes", "")).strip(),
        verified_capabilities=verified_capabilities,
        capability_miss_reason=str(caps_block.get("miss_reason", "")).strip(),
        evasion=str(data.get("evasion", "")).strip(),
    )


def load_corpus(root: Path) -> list[Sample]:
    """Load every sample under a corpus root, sorted by id for determinism."""
    if not root.is_dir():
        raise CorpusError(f"{root}: corpus root does not exist")

    samples = [
        load_sample(manifest.parent) for manifest in sorted(root.rglob(SAMPLE_FILE))
    ]

    seen: dict[str, Path] = {}
    for s in samples:
        if s.id in seen:
            raise CorpusError(f"duplicate sample id {s.id!r}: {seen[s.id]} and {s.path}")
        seen[s.id] = s.path

    return sorted(samples, key=lambda s: s.id)


def _artifact_text(sample: Sample) -> str:
    """Concatenate the readable artifact files. Best effort — binaries are skipped."""
    chunks = []
    for f in sorted(sample.artifact_path.rglob("*")):
        if not f.is_file():
            continue
        try:
            chunks.append(f.read_text())
        except (UnicodeDecodeError, OSError):
            continue
    return "\n".join(chunks)


def _payload_host_is_inert(host: str) -> bool:
    # Strip a port, lowercase, and drop a trailing dot — the URL regex greedily captures
    # the sentence period after a bare hostname, and a DNS root dot is inert regardless.
    host = host.split(":", 1)[0].lower().rstrip(".")
    return host in ALLOWED_PAYLOAD_HOSTS or host.endswith(ALLOWED_PAYLOAD_TLDS)


def validate(samples: list[Sample]) -> list[Violation]:
    """Check every corpus invariant, returning all violations rather than the first.

    Reporting everything at once matters: authoring the corpus is the slow part of P0,
    and a validator that surfaces one problem per run turns a ten-minute fix into an
    afternoon.
    """
    violations: list[Violation] = []

    def fail(s: Sample, rule: str, detail: str) -> None:
        violations.append(Violation(s.id, rule, detail))

    for s in samples:
        if not ID_PATTERN.match(s.id):
            fail(s, "id-format", f"{s.id!r} is not lowercase-kebab-case")

        if s.path.name != s.id:
            fail(s, "id-matches-dir", f"directory {s.path.name!r} != id {s.id!r}")

        if not s.artifact_path.is_dir():
            fail(s, "artifact-present", f"no {ARTIFACT_DIR}/ directory")
        elif not any(s.artifact_path.rglob("*")):
            fail(s, "artifact-present", f"{ARTIFACT_DIR}/ is empty")

        # The rule the whole corpus rests on. §06: every sample carries a written
        # rationale — why it is malicious, or specifically why it merely looks that way.
        if len(s.rationale) < MIN_RATIONALE_CHARS:
            fail(
                s,
                "rationale-required",
                f"rationale is {len(s.rationale)} chars, need >= {MIN_RATIONALE_CHARS}",
            )

        if s.stratum.is_positive and not s.attack_classes:
            fail(s, "attack-class-required", "positive sample declares no attack class")

        if not s.stratum.is_positive and s.attack_classes:
            fail(
                s,
                "no-attack-class-on-negative",
                f"non-positive sample declares attack classes {[a.value for a in s.attack_classes]}",
            )

        if s.stratum is Stratum.FP_TRAP and not s.trap_families:
            fail(
                s,
                "trap-family-required",
                "trap declares no family — why does it look dangerous?",
            )

        if s.stratum is not Stratum.FP_TRAP and s.trap_families:
            fail(s, "trap-family-only-on-traps", "non-trap declares a trap family")

        if s.stratum.is_positive and not s.expected:
            fail(s, "expected-required", "positive sample declares no expected findings")

        # An obfuscated sample must say how it hides from static analysis — that claim is
        # the sample's contribution, and the sandbox result is scored against it.
        if s.stratum is Stratum.OBFUSCATED and not s.evasion:
            fail(s, "evasion-required", "obfuscated sample declares no evasion rationale")

        for e in s.expected:
            if e.attack_class not in s.attack_classes:
                fail(
                    s,
                    "expected-matches-label",
                    f"expected finding {e.attack_class.value!r} not in declared attack classes",
                )

        # Inertness, scoped to the positive strata. A published corpus gets cloned by
        # strangers, so payloads must not reach anything real. Negative samples are the
        # opposite case: a benign weather server referencing a real API host is exactly
        # the realism the benchmark needs, and nothing in a sample is ever executed.
        if not s.stratum.is_positive:
            continue

        for host in _URL_RE.findall(_artifact_text(s)):
            if not _payload_host_is_inert(host):
                fail(
                    s,
                    "inert-payloads",
                    f"artifact references live host {host!r} — use a sinkhole",
                )

    return violations


def counts_by_stratum(samples: list[Sample]) -> dict[Stratum, int]:
    return {
        st: sum(1 for s in samples if s.stratum is st)
        for st in Stratum
    }
