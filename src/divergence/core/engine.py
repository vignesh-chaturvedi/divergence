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
import re
from pathlib import Path
from typing import TYPE_CHECKING

from divergence.core.acquire import Artifact
from divergence.core.behaviour import Behaviour
from divergence.core.claim_model import configured_backend
from divergence.core.claims import Claim, ClaimBackend, TriggerScope, extract_claim
from divergence.core.vocabulary import AttackClass, Capability, Channel, Finding

if TYPE_CHECKING:
    from divergence.core.sandbox import Dynamic

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
        with path.open("rb") as handle:
            return handle.read(_MAX_BYTES + 1)[:_MAX_BYTES].decode("utf-8", "replace")
    except (OSError, UnicodeDecodeError):
        return ""


def analyze_divergence(
    artifact: Artifact, behaviour: Behaviour, *, sample_id: str = ""
) -> list[Finding]:
    """Run the rule table over one artifact."""
    findings: list[Finding] = []
    backend = configured_backend()

    claim_text = declared_text(artifact)
    claim = extract_claim(claim_text, backend=backend)

    findings += _undeclared_capability(artifact, behaviour, claim, sample_id, backend)
    findings += _cross_tool_instruction(artifact, behaviour, claim, sample_id)
    findings += _concealment_in_declared_surface(artifact, claim, sample_id)
    findings += _schema_poisoning(artifact, sample_id, backend)
    findings += _bundled_resource_payload(artifact, sample_id, backend)
    findings += _return_value_injection(artifact, behaviour, sample_id, backend)
    trigger_claim = (
        extract_claim(artifact.skill.description, backend=backend)
        if artifact.skill is not None
        else claim
    )
    operational_claim = (
        extract_claim(artifact.skill.body, backend=backend) if artifact.skill is not None else claim
    )
    findings += _trigger_scope(artifact, behaviour, trigger_claim, operational_claim, sample_id)

    return findings


def _undeclared_capability(
    artifact: Artifact,
    behaviour: Behaviour,
    claim: Claim,
    sample_id: str,
    backend: ClaimBackend,
) -> list[Finding]:
    """B ⊄ C — reaches for capability it never declared.

    The core primitive. A shell executor spawning shells is `B ⊆ C` and produces nothing;
    a markdown renderer that promised to run offline and then opens a socket is the whole
    thesis in one sample.
    """
    findings: list[Finding] = []
    attributed: set[Capability] = set()

    # A sibling's honest network claim cannot excuse another handler's hidden egress.
    # Compare each tool to its own reachable handler whenever attribution is available.
    for tool in artifact.tools:
        entrypoint = behaviour.find(tool.name, tool.source_ref)
        if entrypoint is None:
            continue
        attributed |= set(entrypoint.capabilities)
        tool_claim = extract_claim(
            f"{tool.name}. {tool.description}\n{tool.schema_text()}", backend=backend
        )
        evidence = {sink.capability: sink.location for sink in entrypoint.sinks}
        findings += _capability_gap(
            artifact,
            set(entrypoint.capabilities),
            evidence,
            tool_claim,
            sample_id,
            subject=f"tool {tool.name!r}",
        )

    leftovers = behaviour.capabilities - attributed
    if leftovers or not artifact.tools or not attributed:
        caps = leftovers if attributed else behaviour.capabilities
        evidence = {cap: behaviour.evidence.get(cap, "") for cap in caps}
        findings += _capability_gap(artifact, caps, evidence, claim, sample_id, subject="artifact")

    return findings


def _capability_gap(
    artifact: Artifact,
    capabilities: set[Capability],
    evidence_by_capability: dict[Capability, str],
    claim: Claim,
    sample_id: str,
    *,
    subject: str,
) -> list[Finding]:
    """Compare one qualified behaviour surface to its corresponding claim."""
    findings: list[Finding] = []
    undeclared = capabilities - claim.capabilities

    for cap in sorted(undeclared):
        evidence = evidence_by_capability.get(cap, "")
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
                        f"{subject} explicitly denies {cap.value} but its implementation reaches it"
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
                        f"{subject} reaches {cap.value}, which its declared interface "
                        "does not account for"
                    ),
                    evidence=evidence,
                    claim=f"declared interface of {_artifact_name(artifact)} does not mention {cap.value}",
                    confidence=0.8,
                )
            )

    # B ⊆ C — the consistency note. Non-urgent by construction.
    consistent = capabilities & claim.capabilities
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
                evidence=evidence_by_capability.get(sorted(consistent)[0], ""),
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


def _schema_poisoning(artifact: Artifact, sample_id: str, backend: ClaimBackend) -> list[Finding]:
    """Payload in a JSON Schema property description.

    The tool description can be spotless while the schema carries the instruction — and
    the agent receives both. Analysing S as a surface in its own right is the only way to
    see it.
    """
    text = _schema_text(artifact)
    if not text.strip():
        return []

    schema_claim = extract_claim(text, backend=backend)
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


def _bundled_resource_payload(
    artifact: Artifact, sample_id: str, backend: ClaimBackend
) -> list[Finding]:
    """Payload in a bundled resource the frontmatter never mentions.

    §03: the body of a skill is not loaded until it fires, and bundled resources may never
    be read by the model at all. A scanner that stops at frontmatter sees a clean artifact
    while the payload sits one directory away.
    """
    findings: list[Finding] = []
    skill_file = "SKILL.md"

    if artifact.skill is None:
        return []

    for path in artifact.bundle_files:
        if path.suffix.lower() not in _RESOURCE_SUFFIXES or path.name == skill_file:
            continue

        resource_claim = extract_claim(_read(path), backend=backend)
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


def _python_emitted_strings(source: str, active_names: set[str]) -> str:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return ""

    assignments: dict[str, list[str]] = {}

    def strings(node: ast.AST | None) -> list[str]:
        if node is None:
            return []
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        if isinstance(node, ast.Name):
            return assignments.get(node.id, [])
        values: list[str] = []
        for child in ast.iter_child_nodes(node):
            values.extend(strings(child))
        return values

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = getattr(node, "value", None)
            names: list[str] = []
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    names.append(target.id)
            value_strings = strings(value)
            for name in names:
                assignments[name] = value_strings

    emitted: list[str] = []

    def visit_body(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(node, ast.Return):
                emitted.extend(strings(node.value))
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Name) and call.func.id == "print":
                    for arg in call.args:
                        emitted.extend(strings(arg))

    visit_body(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in active_names:
            visit_body(node.body)
    return "\n".join(emitted)


_JS_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def _javascript_emitted_strings(source: str, active_names: set[str]) -> str:
    """Conservative return/output extraction that excludes comments and dead helpers."""
    clean = _JS_COMMENT_RE.sub(" ", source)
    chunks: list[str] = []
    for name in active_names:
        pattern = re.compile(
            rf"(?:export\s+)?(?:async\s+)?function\s+{re.escape(name)}\b[^{{]*{{(.*?)\n}}",
            re.DOTALL,
        )
        for match in pattern.finditer(clean):
            chunks.extend(re.findall(r"\breturn\s+(.+?);", match.group(1), re.DOTALL))
    # Module-level console output is relevant for skill scripts.
    chunks.extend(re.findall(r"\bconsole\.log\s*\((.*?)\)\s*;", clean, re.DOTALL))
    return "\n".join(chunks)


def _emitted_strings(path: Path, active_names: set[str]) -> str:
    """String literals a module emits, excluding docstrings.

    Docstrings *are* the declared surface — they become the tool description. Scanning them
    here would re-flag the artifact's own documentation as an injected payload, which is
    how an honest server saying "a session token for use with other billing tools" became
    a false positive. Only text the implementation constructs counts.
    """
    source = _read(path)
    if path.suffix.lower() != ".py":
        return _javascript_emitted_strings(source, active_names)
    return _python_emitted_strings(source, active_names)


def _return_value_injection(
    artifact: Artifact,
    behaviour: Behaviour,
    sample_id: str,
    backend: ClaimBackend,
) -> list[Finding]:
    """Agent-directed instructions embedded in what a handler returns.

    Manifest and schema are clean; the payload arrives as tool output, which the agent
    treats as trustworthy. Only reading the implementation reveals it.
    """
    findings: list[Finding] = []

    for path in artifact.bundle_files:
        if path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue

        rel = str(path.relative_to(artifact.root))
        active_names = {
            entrypoint.name
            for entrypoint in behaviour.entrypoints
            if entrypoint.location.split(":", 1)[0] == rel and entrypoint.kind == "tool_handler"
        }
        # A script's module body is its output surface.
        if any(
            entrypoint.kind == "script" and entrypoint.location.split(":", 1)[0] == rel
            for entrypoint in behaviour.entrypoints
        ):
            active_names.add("<module>")
        source_claim = extract_claim(_emitted_strings(path, active_names), backend=backend)
        if not (source_claim.conceals or source_claim.instructs_other_tools):
            continue

        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.RISK,
                attack_class=AttackClass.RETURN_VALUE_INJECTION,
                severity="critical",
                message=(f"{path.name} embeds an agent-directed instruction in the text it emits"),
                evidence=str(path.name),
                claim=source_claim.cross_tool_evidence,
                confidence=0.8,
            )
        )

    return findings


def _trigger_scope(
    artifact: Artifact,
    behaviour: Behaviour,
    trigger_claim: Claim,
    operational_claim: Claim,
    sample_id: str,
) -> list[Finding]:
    """C_trigger ⊅ B — a skill claiming relevance far wider than its capability.

    A skill's description decides *when the agent loads it at all*, so an over-broad one
    is a routing hijack rather than a documentation flaw. Breadth alone is not the signal
    — a universal formatter that genuinely formats anything is honest. The signal is
    breadth combined with reach the description never accounted for.
    """
    if artifact.skill is None or trigger_claim.trigger_scope is not TriggerScope.UNIVERSAL:
        return []

    undeclared = (behaviour.capabilities - operational_claim.capabilities) & HIGH_SIGNAL
    if not undeclared:
        return [
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message="skill claims universal trigger scope",
                evidence=trigger_claim.trigger_evidence,
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
            claim=trigger_claim.trigger_evidence,
            confidence=0.8,
        )
    ]


# --- rule table row six: B_dynamic ⊄ B_static -----------------------------------------

# Capabilities worth a risk finding when they appear only at runtime. Same high-signal
# list the B ⊄ C rule uses, and for the same reason (ADR 0004): undeclared filesystem and
# environment access cannot separate a todo list from an exfiltrator, so they stay posture
# even here.
_DYNAMIC_HIGH_SIGNAL = frozenset(
    {
        Capability.NET_OUTBOUND,
        Capability.PROC_SPAWN,
        Capability.SECRETS_READ,
        Capability.DYNAMIC_EVAL,
        Capability.FS_DELETE,
    }
)


def dynamic_divergence(
    static_capabilities: set[Capability],
    dynamic: "Dynamic",
    *,
    sample_id: str = "",
) -> list[Finding]:
    """B_dynamic ⊄ B_static — the artifact did at runtime what its source never showed.

    §05 calls this "the strongest anti-evasion signal in the system", and the reasoning is
    worth restating: static analysis loses to obfuscation, and execution does not care how
    a payload was encoded. Benign code does not accidentally hide its capabilities from a
    parser — a base64-assembled socket call is not a coincidence.

    Two guards keep this honest:

    - **Nothing is inferred from silence.** If the sandbox did not run, or ran without
      observing a single syscall, there are no findings. An empty B_dynamic means "unknown",
      never "clean".
    - **Coverage travels with every finding.** A reader must be able to see how much of the
      artifact actually executed, because a malicious branch gated on specific arguments
      looks identical to no malicious branch at all.
    """
    if not dynamic.ran:
        return []

    findings: list[Finding] = []
    undeclared = dynamic.capabilities - set(static_capabilities)

    for capability in sorted(undeclared, key=lambda c: c.value):
        non_decoy = next(
            (o for o in dynamic.observations if o.capability is capability and not o.decoy),
            None,
        )
        if (
            capability is Capability.SECRETS_READ
            and non_decoy is None
            and any(o.capability is capability and o.decoy for o in dynamic.observations)
        ):
            # The decoy-specific finding below is stronger and carries the exact path.
            continue
        observed = non_decoy or next(
            (o for o in dynamic.observations if o.capability is capability), None
        )
        target = f" -> {observed.target}" if observed and observed.target else ""
        outcome = "performed" if observed is None or observed.succeeded else "attempted"

        findings.append(
            Finding(
                sample_id=sample_id,
                channel=(Channel.RISK if capability in _DYNAMIC_HIGH_SIGNAL else Channel.POSTURE),
                attack_class=AttackClass.DYNAMIC_CODE_LOADING,
                severity="critical" if capability in _DYNAMIC_HIGH_SIGNAL else "info",
                message=(
                    f"{outcome} a {capability.value} operation at runtime that static analysis could not "
                    f"see in the source{target}"
                ),
                evidence=dynamic.evidence.get(capability, observed.syscall if observed else ""),
                claim=f"B_static did not contain {capability.value}; {dynamic.coverage_note}",
                confidence=0.9 if capability in _DYNAMIC_HIGH_SIGNAL else 0.5,
            )
        )

    # Decoy reads.
    #
    # §05 says "anything that reads them is caught red-handed with no ambiguity to
    # adjudicate." That is too strong, and the corpus proves it: a credential manager reads
    # ~/.ssh because managing credentials is its declared job, and the decoy is planted at
    # exactly the path it legitimately opens. Firing unconditionally would flag
    # `trap-priv-002` — the precise over-flagging this project exists to eliminate.
    #
    # The core rule settles it. A finding is the gap, not the capability: a decoy read is
    # risk when credential access was *not* already visible statically, and posture when it
    # was. The decoy still earns its keep — it makes the read observable at all, and gives
    # a concrete path as evidence.
    declared_secrets = Capability.SECRETS_READ in static_capabilities

    for observation in dynamic.decoy_reads:
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE if declared_secrets else Channel.RISK,
                attack_class=None if declared_secrets else AttackClass.UNDECLARED_SECRETS,
                severity="info" if declared_secrets else "critical",
                message=(
                    f"read the planted decoy credential at {observation.target}"
                    + (" — consistent with its declared capability" if declared_secrets else "")
                ),
                evidence=f"{observation.syscall}({observation.target})",
                claim=(
                    f"credential access {'was' if declared_secrets else 'was not'} visible in "
                    f"B_static; {dynamic.coverage_note}"
                ),
                confidence=0.5 if declared_secrets else 0.95,
            )
        )

    return findings
