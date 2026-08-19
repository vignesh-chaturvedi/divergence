"""A2 — the declared-interface analyzer.

Every check is deterministic: a parse, or set algebra over capability sets. No model
runs here and none ever will.

The scope is narrower than it might be, deliberately. A2 flags contradictions it can
*prove* — an annotation the implementation disproves, a permission grant the bundle
exceeds, a name that shadows a popular one. It does not attempt to judge whether a
description reads as adversarial; that is C-versus-B reasoning and it belongs to P3's
claim extractor. Guessing here would trade the precision this project is built on for
recall that arrives properly one phase later.

Two rules govern everything below:

1. Capability that matches the claim is **posture**, however alarming it looks. A shell
   executor executing shells is not a finding.
2. A wildcard is **always** posture. §03: thousands of benign published artifacts declare
   one, and routing it to the verdict has already forced a competing benchmark to
   withdraw headline scores.
"""

from __future__ import annotations

from divergence.core.acquire import Artifact
from divergence.core.behaviour import Behaviour
from divergence.core.vocabulary import (
    MUTATING,
    AttackClass,
    Capability,
    Channel,
    Finding,
    capabilities_for_allowed_tools,
    declaration_is_wildcard,
)

# Capabilities that an `allowed-tools` declaration actually governs. Reading the
# environment is available to any script that runs at all, so counting it as an excess
# would flag every honest skill that reads a config variable.
TOOL_GATED = frozenset(
    {
        Capability.FS_READ,
        Capability.FS_WRITE,
        Capability.FS_DELETE,
        Capability.NET_OUTBOUND,
        Capability.NET_LISTEN,
        Capability.PROC_SPAWN,
        Capability.DYNAMIC_EVAL,
    }
)

# Reading a credential file is a filesystem read. A `Read` grant covers it, and treating
# it as a separate permission would flag every honest credential manager.
_COARSEN = {Capability.SECRETS_READ: Capability.FS_READ}


def _coarsen(caps: set[Capability]) -> set[Capability]:
    return {_COARSEN.get(c, c) for c in caps} & TOOL_GATED


def _capabilities_for_tool(behaviour: Behaviour, tool_name: str) -> tuple[set[Capability], dict]:
    """Capabilities reachable from one tool's handler, with evidence.

    P1 could not do this. It scanned for sinks flatly and attributed everything to the
    whole artifact, so a server exposing an honest reader beside an honest writer had the
    reader blamed for the writer's `write_text`. A2 had to compensate with a guard that
    suppressed the check whenever any sibling might explain the mutation, which cost real
    detections.

    A4's call graph removes the guess. When a handler for this tool is found, its
    reachable set is the answer. When it is not — a TypeScript server whose handler name
    does not match the declared tool, say — `None` is returned and the caller falls back
    to the conservative artifact-wide reading rather than inventing an attribution.
    """
    match = behaviour.find(tool_name)
    if match is not None and match.kind in ("tool_handler", "function"):
        return set(match.capabilities), {s.capability: s.location for s in match.sinks}
    return None, {}


def _sibling_could_explain(artifact: Artifact) -> bool:
    """Fallback guard, used only when per-tool attribution is unavailable.

    Retained because attribution can still fail — an unparsed grammar, a handler
    registered dynamically. Where it fails, the conservative reading is the right one.
    """
    return any(
        tool.annotations.get("readOnlyHint") is False
        or tool.annotations.get("destructiveHint") is True
        or not tool.annotations
        for tool in artifact.tools
    )


def _annotation_findings(
    artifact: Artifact, behaviour: Behaviour, sample_id: str
) -> list[Finding]:
    """MCP annotation contradictions.

    The cheapest high-severity finding in the design. An annotation is a machine-readable
    promise, so disproving it needs no interpretation — only a capability set, now scoped
    to the handler that actually made the promise.
    """
    findings: list[Finding] = []
    fallback_caps = behaviour.capabilities
    fallback_evidence = behaviour.evidence
    fallback_blocked = _sibling_could_explain(artifact)

    for tool in artifact.tools:
        annotations = tool.annotations
        if not annotations:
            continue

        scoped, scoped_evidence = _capabilities_for_tool(behaviour, tool.name)
        if scoped is not None:
            caps, evidence, attributed = scoped, scoped_evidence, True
        else:
            caps, evidence, attributed = fallback_caps, fallback_evidence, False

        if annotations.get("readOnlyHint") is True and (attributed or not fallback_blocked):
            violations = caps & MUTATING
            if violations:
                cap = sorted(violations)[0]
                findings.append(
                    Finding(
                        sample_id=sample_id,
                        channel=Channel.RISK,
                        attack_class=AttackClass.ANNOTATION_LIE,
                        severity="critical",
                        message=(
                            f"tool {tool.name!r} declares readOnlyHint: true but its handler "
                            f"reaches {cap.value}"
                        ),
                        evidence=evidence.get(cap, ""),
                        claim=f"{tool.source_ref}: {tool.name}.annotations.readOnlyHint = true",
                    )
                )

        if annotations.get("openWorldHint") is False and Capability.NET_OUTBOUND in caps:
            findings.append(
                Finding(
                    sample_id=sample_id,
                    channel=Channel.RISK,
                    attack_class=AttackClass.UNDECLARED_NETWORK,
                    severity="high",
                    message=(
                        f"tool {tool.name!r} declares openWorldHint: false but its handler "
                        "opens an outbound connection"
                    ),
                    evidence=evidence.get(Capability.NET_OUTBOUND, ""),
                    claim=f"{tool.source_ref}: {tool.name}.annotations.openWorldHint = false",
                )
            )

        if (
            annotations.get("destructiveHint") is False
            and Capability.FS_DELETE in caps
            and (attributed or not fallback_blocked)
        ):
            findings.append(
                Finding(
                    sample_id=sample_id,
                    channel=Channel.RISK,
                    attack_class=AttackClass.ANNOTATION_LIE,
                    severity="high",
                    message=(
                        f"tool {tool.name!r} declares destructiveHint: false but its handler "
                        "deletes from the filesystem"
                    ),
                    evidence=evidence.get(Capability.FS_DELETE, ""),
                    claim=f"{tool.source_ref}: {tool.name}.annotations.destructiveHint = false",
                )
            )

    return findings


def _allowed_tools_findings(
    artifact: Artifact, behaviour: Behaviour, sample_id: str
) -> list[Finding]:
    """The skill analogue of the annotation lie.

    `allowed-tools` is a least-privilege promise. When the bundle reaches for something
    the grant does not cover, the artifact contradicts itself inside one file.
    """
    skill = artifact.skill
    if skill is None:
        return []

    declaration = skill.allowed_tools

    # A wildcard, or no declaration at all, restricts nothing — so nothing can exceed it.
    if declaration_is_wildcard(declaration):
        return [
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message=(
                    "skill declares unrestricted tool access"
                    if declaration
                    else "skill declares no allowed-tools, so tool access is unrestricted"
                ),
                evidence=f"{skill.source_ref}: allowed-tools = {declaration or '<absent>'}",
                claim="least-privilege posture only — never a verdict signal",
            )
        ]

    granted = _coarsen(capabilities_for_allowed_tools(declaration))
    used = _coarsen(behaviour.capabilities)
    excess = used - granted
    if not excess:
        return []

    cap = sorted(excess)[0]
    return [
        Finding(
            sample_id=sample_id,
            channel=Channel.RISK,
            attack_class=AttackClass.SCRIPT_EXCEEDS_ALLOWED_TOOLS,
            severity="high",
            message=(
                f"bundle reaches {', '.join(sorted(c.value for c in excess))} but "
                f"allowed-tools grants only {', '.join(sorted(c.value for c in granted)) or 'nothing'}"
            ),
            evidence=behaviour.evidence.get(cap, ""),
            claim=f"{skill.source_ref}: allowed-tools = {declaration}",
        )
    ]


def _provenance_findings(artifact: Artifact, sample_id: str) -> list[Finding]:
    """Typosquat proximity. A provenance signal, invisible in the source."""
    prov = artifact.provenance
    distance = prov.typosquat_distance

    if distance is None or distance == 0 or not prov.nearest_popular_name:
        return []

    corroboration = []
    if prov.signed is False:
        corroboration.append("unsigned")
    if prov.downloads_30d is not None and prov.downloads_30d < 1000:
        corroboration.append(f"{prov.downloads_30d} downloads/30d")

    return [
        Finding(
            sample_id=sample_id,
            channel=Channel.RISK,
            attack_class=AttackClass.TYPOSQUAT,
            severity="high",
            message=(
                f"package {prov.name!r} is edit distance {distance} from "
                f"{prov.nearest_popular_name!r}"
                + (f" ({', '.join(corroboration)})" if corroboration else "")
            ),
            evidence=f"package.json: name = {prov.name}",
            claim=f"registry: nearest popular name {prov.nearest_popular_name}",
        )
    ]


def _posture_findings(
    artifact: Artifact, behaviour: Behaviour, sample_id: str
) -> list[Finding]:
    """What the artifact can do. Recorded, displayed, and never counted toward a verdict."""
    findings: list[Finding] = []

    if Capability.SECRETS_READ in behaviour.capabilities:
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message="reaches credential-bearing paths",
                evidence=behaviour.evidence.get(Capability.SECRETS_READ, ""),
                claim="posture: high-value target, not evidence of exfiltration",
            )
        )

    if {Capability.PROC_SPAWN, Capability.NET_OUTBOUND} <= behaviour.capabilities:
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message="combines subprocess execution with outbound network access",
                evidence=behaviour.evidence.get(Capability.PROC_SPAWN, ""),
                claim="posture: broad blast radius",
            )
        )

    # §04's taint pass, surfaced. A parameter reaching a sink is what an injection path
    # looks like — but on a shell executor it is the advertised function, so it belongs
    # in posture. P3 promotes it to risk precisely when the claim does not cover it.
    flows: list[tuple[str, str, str, str]] = []
    for entrypoint in behaviour.entrypoints:
        for sink in entrypoint.tainted_sinks:
            flows.append(
                (entrypoint.name, ", ".join(sink.tainted_by), sink.capability.value, sink.location)
            )

    for name, params, capability, location in flows[:5]:
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message=f"parameter {params} of {name!r} flows into a {capability} sink",
                evidence=location,
                claim="posture: caller-controlled input reaches a capability",
            )
        )

    if behaviour.unreachable_capabilities:
        cap = sorted(behaviour.unreachable_capabilities)[0]
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="info",
                message=(
                    "ships code no entrypoint can reach, carrying "
                    f"{', '.join(sorted(c.value for c in behaviour.unreachable_capabilities))}"
                ),
                evidence=behaviour.unreachable_evidence.get(cap, ""),
                claim="posture: unreferenced today, callable tomorrow",
            )
        )

    untagged = [t.name for t in artifact.tools if not t.annotations]
    if untagged and artifact.kind == "mcp_server":
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="info",
                message=f"{len(untagged)} tool(s) declare no MCP annotations",
                evidence=f"tools: {', '.join(untagged[:5])}",
                claim="posture: an unannotated tool cannot be checked against its hints",
            )
        )

    return findings


def analyze_declared(
    artifact: Artifact, behaviour: Behaviour, *, sample_id: str = ""
) -> list[Finding]:
    """Run every A2 check over one artifact.

    Returns risk findings first so a caller truncating the list keeps what matters.
    """
    checked = (
        _annotation_findings(artifact, behaviour, sample_id)
        + _allowed_tools_findings(artifact, behaviour, sample_id)
        + _provenance_findings(artifact, sample_id)
    )
    risks = [f for f in checked if f.channel is Channel.RISK]
    posture = [f for f in checked if f.channel is Channel.POSTURE]

    return risks + posture + _posture_findings(artifact, behaviour, sample_id)
