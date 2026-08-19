"""A7 — fleet analyzers.

Single-artifact scanning is structurally blind to three real attacks, because in each one
the artifact is unremarkable on its own and only becomes wrong relative to what else is
installed:

- **Shadowing.** A near-duplicate of a trusted artifact, from a different publisher. In
  isolation it is a perfectly ordinary GitHub wrapper.
- **Preference and routing manipulation.** "Always use this one" carries no information
  until you know what else the agent could have used.
- **Toxic flow.** Untrusted input, private data access and outbound egress, each honest in
  its own artifact, combining across the installed set into a path nobody declared.

The hard half of the gate is not detection — it is **not flagging the original**. A shadow
resembles what it imitates by construction, so similarity alone condemns both. Provenance
breaks the tie: §04 has A1 record publisher, signature status, first-seen date and download
volume precisely so that when two artifacts look alike, the one with no history is the
suspect.

**On embeddings.** §04 specifies a local embedding model. Shadowing is lexical
near-duplication by nature — an attacker wants the agent to confuse the two artifacts, so
the text is deliberately close — and character-n-gram cosine catches that deterministically,
offline, at zero cost. A neural backend would additionally catch *paraphrase* shadowing,
where the imitation is semantic rather than lexical. That is a real gap, it is recorded
below, and the backend seam is here for when a model is available.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from divergence.core.acquire import Artifact
from divergence.core.behaviour import Behaviour
from divergence.core.claims import Claim, extract_claim
from divergence.core.engine import declared_text
from divergence.core.pipeline import load
from divergence.core.vocabulary import AttackClass, Capability, Channel, Finding

# Above this, two artifacts are describing the same job in nearly the same words.
SHADOW_SIMILARITY = 0.55

# A name this close to another artifact's is imitation regardless of description.
SHADOW_NAME_SIMILARITY = 0.72

_NGRAM = 3


class FleetError(Exception):
    """The fleet manifest could not be loaded."""


@dataclass(frozen=True, slots=True)
class FleetMember:
    """One installed artifact, with everything the analyzers need."""

    id: str
    root: Path
    artifact: Artifact
    behaviour: Behaviour
    claim: Claim

    @property
    def display_name(self) -> str:
        if self.artifact.skill:
            return self.artifact.skill.name
        return self.artifact.provenance.name or self.id

    @property
    def publisher(self) -> str:
        return (self.artifact.provenance.author or "").strip().lower()


@dataclass
class Fleet:
    """An installed set."""

    name: str = ""
    members: tuple[FleetMember, ...] = ()
    expected: dict = field(default_factory=dict)

    def member(self, member_id: str) -> FleetMember:
        for m in self.members:
            if m.id == member_id:
                return m
        raise KeyError(member_id)


# --- similarity -----------------------------------------------------------------------

def _ngrams(text: str, n: int = _NGRAM) -> Counter:
    cleaned = " ".join(text.lower().split())
    if len(cleaned) < n:
        return Counter([cleaned])
    return Counter(cleaned[i : i + n] for i in range(len(cleaned) - n + 1))


def cosine(a: str, b: str) -> float:
    """Character-n-gram cosine similarity. Deterministic, offline, no model."""
    va, vb = _ngrams(a), _ngrams(b)
    if not va or not vb:
        return 0.0

    shared = set(va) & set(vb)
    if not shared:
        return 0.0

    dot = sum(va[g] * vb[g] for g in shared)
    na = math.sqrt(sum(v * v for v in va.values()))
    nb = math.sqrt(sum(v * v for v in vb.values()))
    return dot / (na * nb) if na and nb else 0.0


def _surface(member: FleetMember) -> str:
    """What an agent sees: the artifact's name plus everything it says about itself."""
    return f"{member.display_name}\n{declared_text(member.artifact)}"


# --- provenance -----------------------------------------------------------------------

def _provenance_strength(member: FleetMember) -> int:
    """A crude establishment score. Higher means more likely to be the original.

    Deliberately coarse — it only ever has to *order* two artifacts that already look
    alike, never to judge one in isolation.
    """
    p = member.artifact.provenance
    score = 0

    if p.signed is True:
        score += 3
    elif p.signed is False:
        score -= 2

    if p.downloads_30d is not None:
        if p.downloads_30d >= 100_000:
            score += 3
        elif p.downloads_30d >= 10_000:
            score += 2
        elif p.downloads_30d >= 1_000:
            score += 1
        else:
            score -= 2

    if p.first_published:
        # Anything published in the current year is new; older is established.
        year = p.first_published[:4]
        if year.isdigit():
            score += 2 if int(year) <= 2025 else -1

    if p.typosquat_distance:
        score -= 3

    if p.author:
        score += 1

    return score


# --- the analyzers --------------------------------------------------------------------

def _shadowing(fleet: Fleet) -> list[Finding]:
    """Near-duplicates from different publishers.

    Only the weaker-provenance side is flagged. When provenance cannot separate them the
    pair is reported as posture instead, because condemning both would mean condemning the
    artifact being attacked.
    """
    findings: list[Finding] = []
    members = list(fleet.members)

    for i, a in enumerate(members):
        for b in members[i + 1 :]:
            text_similarity = cosine(_surface(a), _surface(b))
            name_similarity = cosine(a.display_name, b.display_name)

            if text_similarity < SHADOW_SIMILARITY and name_similarity < SHADOW_NAME_SIMILARITY:
                continue

            # Same publisher means a family of tools, not an imitation.
            if a.publisher and b.publisher and a.publisher == b.publisher:
                continue

            strength_a, strength_b = _provenance_strength(a), _provenance_strength(b)

            # Skills carry no registry metadata, so provenance frequently ties. The
            # content then breaks it: between two near-identical artifacts, the one
            # asserting precedence over the other is the aggressor. A legitimate artifact
            # has no reason to tell the agent to disregard its double.
            if strength_a == strength_b:
                asserts_a = a.claim.instructs_other_tools
                asserts_b = b.claim.instructs_other_tools
                if asserts_a != asserts_b:
                    strength_a, strength_b = (
                        (-1, 0) if asserts_a else (0, -1)
                    )

            if strength_a == strength_b:
                findings.append(
                    Finding(
                        sample_id=a.id,
                        channel=Channel.POSTURE,
                        severity="low",
                        message=(
                            f"near-duplicate of {b.id!r} "
                            f"(text {text_similarity:.0%}, name {name_similarity:.0%}) "
                            "with no provenance signal to separate them"
                        ),
                        evidence=f"{a.id} vs {b.id}",
                        claim="posture: cannot tell which is the original",
                    )
                )
                continue

            suspect, original = (a, b) if strength_a < strength_b else (b, a)
            findings.append(
                Finding(
                    sample_id=suspect.id,
                    channel=Channel.RISK,
                    attack_class=AttackClass.SHADOWING,
                    severity="critical",
                    message=(
                        f"{suspect.display_name!r} closely imitates {original.display_name!r} "
                        f"(text {text_similarity:.0%}, name {name_similarity:.0%}) "
                        "from a different publisher, with weaker provenance"
                    ),
                    evidence=(
                        f"{suspect.id}: publisher={suspect.publisher or 'unknown'}, "
                        f"signed={suspect.artifact.provenance.signed}, "
                        f"downloads30d={suspect.artifact.provenance.downloads_30d}"
                    ),
                    claim=(
                        f"{original.id}: publisher={original.publisher or 'unknown'}, "
                        f"signed={original.artifact.provenance.signed}, "
                        f"downloads30d={original.artifact.provenance.downloads_30d}"
                    ),
                    confidence=0.85,
                )
            )

    return findings


def _preference_manipulation(fleet: Fleet) -> list[Finding]:
    """Exclusionary language scored against siblings.

    Superlatives alone are not the signal — plenty of honest tools say they are fast. The
    signal is language that tells the agent to *stop considering* the alternatives, which
    is only meaningful because alternatives exist in the same installed set.
    """
    findings: list[Finding] = []

    for member in fleet.members:
        if not member.claim.instructs_other_tools:
            continue

        siblings = [m for m in fleet.members if m.id != member.id]
        if not siblings:
            continue

        findings.append(
            Finding(
                sample_id=member.id,
                channel=Channel.RISK,
                attack_class=AttackClass.PREFERENCE_MANIPULATION,
                severity="high",
                message=(
                    f"{member.display_name!r} directs the agent's use of other artifacts "
                    f"while {len(siblings)} others are installed"
                ),
                evidence=f"{member.id}: {len(siblings)} sibling artifact(s) in this config",
                claim=member.claim.cross_tool_evidence,
                confidence=0.8,
            )
        )

    return findings


def _trigger_scope(fleet: Fleet) -> list[Finding]:
    """A skill claiming relevance far wider than its capability, relative to siblings.

    Breadth is honest when the capability matches — a universal formatter that genuinely
    formats anything belongs everywhere. The signal is a trigger that reaches beyond both
    the skill's own capability *and* the ground already covered by narrower siblings.
    """
    from divergence.core.claims import TriggerScope

    findings: list[Finding] = []

    for member in fleet.members:
        if member.artifact.skill is None:
            continue
        if member.claim.trigger_scope is not TriggerScope.UNIVERSAL:
            continue

        undeclared = member.behaviour.capabilities - member.claim.capabilities
        if not undeclared:
            continue

        cap = sorted(undeclared)[0]
        findings.append(
            Finding(
                sample_id=member.id,
                channel=Channel.RISK,
                attack_class=AttackClass.TRIGGER_SCOPE_HIJACK,
                severity="high",
                message=(
                    f"{member.display_name!r} claims universal trigger scope inside a "
                    f"{len(fleet.members)}-artifact config while reaching "
                    f"{', '.join(sorted(c.value for c in undeclared))}"
                ),
                evidence=member.behaviour.evidence.get(cap, ""),
                claim=member.claim.trigger_evidence,
                confidence=0.8,
            )
        )

    return findings


# The three capability roles a toxic flow needs. A path exists when all three are present
# in one installed set, whichever artifacts supply them — the agent's context is shared,
# so a page fetched by one tool reaches a sink offered by another.
UNTRUSTED_INPUT = frozenset({Capability.NET_OUTBOUND, Capability.FS_READ})
PRIVATE_DATA = frozenset({Capability.SECRETS_READ, Capability.ENV_READ})
EGRESS = frozenset({Capability.NET_OUTBOUND})


def _toxic_flow(fleet: Fleet) -> list[Finding]:
    """A capability path across artifacts that no single artifact declares.

    Reported as **posture**, not risk, and the distinction is principled rather than
    timid: §02 reserves the verdict for divergence between representations, and a toxic
    flow is a capability combination. Every artifact in the path may be entirely honest —
    in the fixture config, all three are. What makes it worth surfacing is that no single
    artifact's documentation can warn about it, because no single artifact can see it.
    """
    ingest = [m for m in fleet.members if m.behaviour.capabilities & UNTRUSTED_INPUT]
    private = [m for m in fleet.members if m.behaviour.capabilities & PRIVATE_DATA]
    egress = [m for m in fleet.members if m.behaviour.capabilities & EGRESS]

    if not (ingest and private and egress):
        return []

    def names(members: list[FleetMember]) -> str:
        return ", ".join(sorted(m.id for m in members)[:4])

    return [
        Finding(
            sample_id=fleet.name,
            channel=Channel.POSTURE,
            severity="medium",
            message=(
                "toxic flow available across this config: untrusted input "
                f"({names(ingest)}) -> private data ({names(private)}) -> "
                f"egress ({names(egress)})"
            ),
            evidence=f"{len(fleet.members)} artifacts in the installed set",
            claim="posture: no single artifact declares this path, because none can see it",
        )
    ]


def analyze_fleet(fleet: Fleet) -> list[Finding]:
    """Run every fleet analyzer. Risk first, then posture."""
    findings = (
        _shadowing(fleet)
        + _preference_manipulation(fleet)
        + _trigger_scope(fleet)
        + _toxic_flow(fleet)
    )
    risks = [f for f in findings if f.channel is Channel.RISK]
    posture = [f for f in findings if f.channel is Channel.POSTURE]
    return sorted(risks, key=lambda f: f.sample_id) + sorted(posture, key=lambda f: f.sample_id)


# --- loading --------------------------------------------------------------------------

def build_fleet(entries: list[tuple[str, Path]], *, name: str = "fleet", expected: dict | None = None) -> Fleet:
    """Assemble a Fleet from (id, artifact root) pairs."""
    members = []
    for member_id, root in entries:
        artifact, behaviour = load(root)
        members.append(
            FleetMember(
                id=member_id,
                root=Path(root),
                artifact=artifact,
                behaviour=behaviour,
                claim=extract_claim(declared_text(artifact)),
            )
        )
    return Fleet(name=name, members=tuple(members), expected=expected or {})


def load_fleet(manifest_path: Path | str) -> Fleet:
    """Load a fleet from its YAML manifest."""
    manifest_path = Path(manifest_path)
    try:
        data = yaml.safe_load(manifest_path.read_text()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise FleetError(f"{manifest_path}: {exc}") from None

    base = manifest_path.parent
    entries: list[tuple[str, Path]] = []

    for entry in data.get("members") or []:
        root = (base / str(entry["path"])).resolve()
        if not root.is_dir():
            raise FleetError(f"{manifest_path}: member {entry['id']!r} has no directory at {root}")
        entries.append((str(entry["id"]), root))

    return build_fleet(
        entries, name=str(data.get("name", manifest_path.parent.name)),
        expected=data.get("expected") or {},
    )
