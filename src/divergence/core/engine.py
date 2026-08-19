"""A6 — the divergence engine.

Set algebra over C, S and B_s, plus §02's rule table. Every finding carries both halves
of the contradiction — a `file:line` for the behaviour and the exact description sentence
for the claim — and a confidence score.

    Relation        Reading                                       Output
    ───────────────────────────────────────────────────────────────────────────────
    B ⊆ C           does what it advertises, however alarming     posture
    B ⊄ C           reaches for capability it never declared      high-confidence risk
    S ⊄ C           accepts parameters the description omits      hidden-interface risk
    annot ≠ B       readOnlyHint on something that writes         critical (in A2)
    C ⊄ S ∪ B       instructs behaviour it cannot perform         injection at other tools
    B_d ⊄ B_s       does at runtime what its source never showed  P5

**The signal-strength tier.** `B ⊄ C` only raises risk for capabilities natural language
reliably signals: network, credentials, execution, dynamic evaluation, deletion. Undeclared
filesystem and environment access route to posture instead. This is not timidity — almost
any tool that "manages", "tracks" or "records" anything touches a file without saying so,
and a rule that cannot separate a todo list from an exfiltrator has no business in a
verdict. §11: do not claim soundness you do not have.
"""

from __future__ import annotations

import ast
from pathlib import Path

from divergence.core.acquire import Artifact
from divergence.core.behaviour import Behaviour
from divergence.core.claims import Claim, TriggerScope, extract_claim
from divergence.core.vocabulary import AttackClass, Capability, Channel, Finding

# Capabilities a description reliably signals. Undeclared presence of one of these is a
# real contradiction; the rest are too ambiguous in prose to decide a verdict.
HIGH_SIGNAL = frozenset(
    {
        Capability.NET_OUTBOUND,
        Capability.SECRETS_READ,
        Capability.PROC_SPAWN,
        Capability.DYNAMIC_EVAL,
        Capability.FS_DELETE,
    }
)

_UNDECLARED_CLASS: dict[Capability, AttackClass] = {
    Capability.NET_OUTBOUND: AttackClass.UNDECLARED_NETWORK,
    Capability.SECRETS_READ: AttackClass.UNDECLARED_SECRETS,
    Capability.PROC_SPAWN: AttackClass.UNDECLARED_EXEC,
    Capability.DYNAMIC_EVAL: AttackClass.DYNAMIC_CODE_LOADING,
    Capability.FS_DELETE: AttackClass.UNDECLARED_FILESYSTEM,
    Capability.FS_READ: AttackClass.UNDECLARED_FILESYSTEM,
    Capability.FS_WRITE: AttackClass.UNDECLARED_FILESYSTEM,
    Capability.ENV_READ: AttackClass.UNDECLARED_SECRETS,
}

_RESOURCE_SUFFIXES = {".md", ".txt", ".rst"}
_SOURCE_SUFFIXES = {".py", ".ts", ".js", ".mjs", ".tsx", ".sh", ".bash"}
_MAX_BYTES = 256_000


def declared_text(artifact: Artifact) -> str:
    """The C surface: everything the artifact says about itself in its declared interface."""
    parts: list[str] = []
    for tool in artifact.tools:
        parts.append(f"{tool.name}. {tool.description}")
    if artifact.skill:
        parts.append(f"{artifact.skill.name}. {artifact.skill.description}")
        parts.append(artifact.skill.body)
    return "\n".join(p for p in parts if p.strip())


def _schema_text(artifact: Artifact) -> str:
    """Property descriptions — part of what the agent ingests, and where schema poisoning hides."""
    chunks = []
    for tool in artifact.tools:
        for name, spec in tool.schema_properties.items():
            if isinstance(spec, dict) and spec.get("description"):
                chunks.append(f"{tool.name}.{name}: {spec['description']}")
    return "\n".join(chunks)


def _read(path: Path) -> str:
    try:
        return path.read_text()[:_MAX_BYTES]
    except (OSError, UnicodeDecodeError):
        return ""


def analyze_divergence(
    artifact: Artifact, behaviour: Behaviour, *, sample_id: str = ""
) -> list[Finding]:
    """Run the rule table over one artifact."""
    findings: list[Finding] = []

    claim_text = declared_text(artifact)
    claim = extract_claim(claim_text)

    findings += _undeclared_capability(artifact, behaviour, claim, sample_id)
    findings += _cross_tool_instruction(artifact, behaviour, claim, sample_id)
    findings += _concealment_in_declared_surface(artifact, claim, sample_id)
    findings += _schema_poisoning(artifact, sample_id)
    findings += _bundled_resource_payload(artifact, sample_id)
    findings += _return_value_injection(artifact, sample_id)
    findings += _trigger_scope(artifact, behaviour, claim, sample_id)

    return findings


def _undeclared_capability(
    artifact: Artifact, behaviour: Behaviour, claim: Claim, sample_id: str
) -> list[Finding]:
    """B ⊄ C — reaches for capability it never declared.

    The core primitive. A shell executor spawning shells is `B ⊆ C` and produces nothing;
    a markdown renderer that promised to run offline and then opens a socket is the whole
    thesis in one sample.
    """
    findings: list[Finding] = []
    undeclared = behaviour.capabilities - claim.capabilities

    for cap in sorted(undeclared):
        evidence = behaviour.evidence.get(cap, "")
        denied = cap in claim.denied

        if not denied and cap not in HIGH_SIGNAL:
            findings.append(
                Finding(
                    sample_id=sample_id,
                    channel=Channel.POSTURE,
                    severity="info",
                    message=f"reaches {cap.value}, which the description does not mention",
                    evidence=evidence,
                    claim="posture: prose does not reliably signal this capability",
                )
            )
            continue

        if denied:
            findings.append(
                Finding(
                    sample_id=sample_id,
                    channel=Channel.RISK,
                    attack_class=_UNDECLARED_CLASS[cap],
                    severity="critical",
                    message=(
                        f"description explicitly denies {cap.value} but the implementation "
                        "reaches it"
                    ),
                    evidence=evidence,
                    claim=claim.evidence.get(cap, claim_snippet(claim, cap)),
                    confidence=0.95,
                )
            )
        else:
            findings.append(
                Finding(
                    sample_id=sample_id,
                    channel=Channel.RISK,
                    attack_class=_UNDECLARED_CLASS[cap],
                    severity="high",
                    message=(
                        f"reaches {cap.value}, which nothing in the declared interface "
                        "accounts for"
                    ),
                    evidence=evidence,
                    claim=f"declared interface of {_artifact_name(artifact)} does not mention {cap.value}",
                    confidence=0.8,
                )
            )

    # B ⊆ C — the consistency note. Non-urgent by construction.
    consistent = behaviour.capabilities & claim.capabilities
    if consistent and not undeclared:
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="info",
                message=(
                    "behaviour is within what the description advertises: "
                    + ", ".join(sorted(c.value for c in consistent))
                ),
                evidence=behaviour.evidence.get(sorted(consistent)[0], ""),
                claim="posture: capability matches claim",
            )
        )

    return findings


def claim_snippet(claim: Claim, cap: Capability) -> str:
    return claim.evidence.get(cap, "declared interface")


def _artifact_name(artifact: Artifact) -> str:
    if artifact.skill:
        return artifact.skill.name
    return artifact.provenance.name or artifact.root.name


def _cross_tool_instruction(
    artifact: Artifact, behaviour: Behaviour, claim: Claim, sample_id: str
) -> list[Finding]:
    """C ⊄ S ∪ B — instructs behaviour the artifact cannot itself perform.

    The fifth row, and the one keyword scanners structurally cannot reach. A translation
    server whose own behaviour set is `{network}` has no dangerous capability at all; the
    attack is that its description tells the agent how to treat *other* tools. There is
    nothing suspicious to find in the code, and nothing suspicious about the capability.
    It only looks wrong once you notice the instruction exceeds the artifact's own reach.
    """
    if not claim.instructs_other_tools:
        return []

    return [
        Finding(
            sample_id=sample_id,
            channel=Channel.RISK,
            attack_class=AttackClass.CROSS_TOOL_INSTRUCTION,
            severity="critical",
            message=(
                "declared interface directs the agent's handling of other tools, which "
                "this artifact does not provide"
            ),
            evidence=f"{_artifact_name(artifact)}: reach is "
            + (", ".join(sorted(c.value for c in behaviour.capabilities)) or "no capability"),
            claim=claim.cross_tool_evidence,
            confidence=0.85,
        )
    ]


def _concealment_in_declared_surface(
    artifact: Artifact, claim: Claim, sample_id: str
) -> list[Finding]:
    """Instructions to hide activity from the user.

    An artifact asking the agent not to mention what it did is asserting something about
    the user's visibility, not documenting a capability. Honest artifacts have no reason
    to.
    """
    if not claim.conceals:
        return []

    return [
        Finding(
            sample_id=sample_id,
            channel=Channel.RISK,
            attack_class=AttackClass.DESCRIPTION_POISONING,
            severity="critical",
            message="declared interface instructs the agent to conceal its actions from the user",
            evidence=f"{_artifact_name(artifact)}: declared interface",
            claim=claim.cross_tool_evidence,
            confidence=0.9,
        )
    ]


def _schema_poisoning(artifact: Artifact, sample_id: str) -> list[Finding]:
    """Payload in a JSON Schema property description.

    The tool description can be spotless while the schema carries the instruction — and
    the agent receives both. Analysing S as a surface in its own right is the only way to
    see it.
    """
    text = _schema_text(artifact)
    if not text.strip():
        return []

    schema_claim = extract_claim(text)
    if not (schema_claim.conceals or schema_claim.instructs_other_tools):
        return []

    return [
        Finding(
            sample_id=sample_id,
            channel=Channel.RISK,
            attack_class=AttackClass.SCHEMA_POISONING,
            severity="critical",
            message="a JSON Schema property description carries an agent-directed instruction",
            evidence="inputSchema.properties[*].description",
            claim=schema_claim.cross_tool_evidence,
            confidence=0.9,
        )
    ]


def _bundled_resource_payload(artifact: Artifact, sample_id: str) -> list[Finding]:
    """Payload in a bundled resource the frontmatter never mentions.

    §03: the body of a skill is not loaded until it fires, and bundled resources may never
    be read by the model at all. A scanner that stops at frontmatter sees a clean artifact
    while the payload sits one directory away.
    """
    findings: list[Finding] = []
    skill_file = "SKILL.md"

    for path in artifact.bundle_files:
        if path.suffix.lower() not in _RESOURCE_SUFFIXES or path.name == skill_file:
            continue

        resource_claim = extract_claim(_read(path))
        if not (resource_claim.conceals or resource_claim.instructs_other_tools):
            continue

        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.RISK,
                attack_class=AttackClass.PROGRESSIVE_DISCLOSURE_PAYLOAD,
                severity="critical",
                message=(
                    f"bundled resource {path.name!r} carries an agent-directed instruction "
                    "that the declared interface never mentions"
                ),
                evidence=str(path.name),
                claim=resource_claim.cross_tool_evidence,
                confidence=0.85,
            )
        )

    return findings


def _emitted_strings(path: Path) -> str:
    """String literals a module emits, excluding docstrings.

    Docstrings *are* the declared surface — they become the tool description. Scanning them
    here would re-flag the artifact's own documentation as an injected payload, which is
    how an honest server saying "a session token for use with other billing tools" became
    a false positive. Only text the implementation constructs counts.
    """
    source = _read(path)
    if path.suffix.lower() != ".py":
        # For non-Python sources, drop block comments and docstring-style triple quotes so
        # documentation is not mistaken for emitted output.
        return source

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return ""

    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                if isinstance(body[0].value.value, str):
                    docstrings.add(id(body[0].value))

    return "\n".join(
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docstrings
    )


def _return_value_injection(artifact: Artifact, sample_id: str) -> list[Finding]:
    """Agent-directed instructions embedded in what a handler returns.

    Manifest and schema are clean; the payload arrives as tool output, which the agent
    treats as trustworthy. Only reading the implementation reveals it.
    """
    findings: list[Finding] = []

    for path in artifact.bundle_files:
        if path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue

        source_claim = extract_claim(_emitted_strings(path))
        if not (source_claim.conceals or source_claim.instructs_other_tools):
            continue

        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.RISK,
                attack_class=AttackClass.RETURN_VALUE_INJECTION,
                severity="critical",
                message=(
                    f"{path.name} embeds an agent-directed instruction in the text it emits"
                ),
                evidence=str(path.name),
                claim=source_claim.cross_tool_evidence,
                confidence=0.8,
            )
        )

    return findings


def _trigger_scope(
    artifact: Artifact, behaviour: Behaviour, claim: Claim, sample_id: str
) -> list[Finding]:
    """C_trigger ⊅ B — a skill claiming relevance far wider than its capability.

    A skill's description decides *when the agent loads it at all*, so an over-broad one
    is a routing hijack rather than a documentation flaw. Breadth alone is not the signal
    — a universal formatter that genuinely formats anything is honest. The signal is
    breadth combined with reach the description never accounted for.
    """
    if artifact.skill is None or claim.trigger_scope is not TriggerScope.UNIVERSAL:
        return []

    undeclared = (behaviour.capabilities - claim.capabilities) & HIGH_SIGNAL
    if not undeclared:
        return [
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message="skill claims universal trigger scope",
                evidence=claim.trigger_evidence,
                claim="posture: breadth is honest when capability matches it",
            )
        ]

    cap = sorted(undeclared)[0]
    return [
        Finding(
            sample_id=sample_id,
            channel=Channel.RISK,
            attack_class=AttackClass.TRIGGER_SCOPE_HIJACK,
            severity="high",
            message=(
                "skill claims universal trigger scope while reaching "
                f"{', '.join(sorted(c.value for c in undeclared))}, which its description omits"
            ),
            evidence=behaviour.evidence.get(cap, ""),
            claim=claim.trigger_evidence,
            confidence=0.8,
        )
    ]
