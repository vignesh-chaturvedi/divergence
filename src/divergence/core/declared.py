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
from divergence.core.probe import Observed
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


def _mutation_is_explained_by_a_sibling(artifact: Artifact) -> bool:
    """True when some other tool on this artifact is entitled to mutate.

    The probe reports capabilities for the artifact as a whole, not per handler —
    attributing a sink to one specific tool needs reachability from each entrypoint,
    which is P2's job. Until then, a server exposing both a reader and a writer (the
    shape of most real servers) would have its reader blamed for the writer's
    `write_text`. That would be the single most common false positive in the field, so
    P1 only asserts an annotation lie when nothing else can account for the mutation.
    """
    return any(
        tool.annotations.get("readOnlyHint") is False
        or tool.annotations.get("destructiveHint") is True
        or not tool.annotations
        for tool in artifact.tools
    )


def _annotation_findings(artifact: Artifact, observed: Observed, sample_id: str) -> list[Finding]:
    """MCP annotation contradictions.

    The cheapest high-severity finding in the design. An annotation is a machine-readable
    promise, so disproving it needs no interpretation — only a capability set.
    """
    findings: list[Finding] = []
    mutation_explained = _mutation_is_explained_by_a_sibling(artifact)

    for tool in artifact.tools:
        annotations = tool.annotations
        if not annotations:
            continue

        if annotations.get("readOnlyHint") is True and not mutation_explained:
            violations = observed.capabilities & MUTATING
            if violations:
                cap = sorted(violations)[0]
                findings.append(
                    Finding(
                        sample_id=sample_id,
                        channel=Channel.RISK,
                        attack_class=AttackClass.ANNOTATION_LIE,
                        severity="critical",
                        message=(
                            f"tool {tool.name!r} declares readOnlyHint: true but the "
                            f"implementation reaches {cap.value}"
                        ),
                        evidence=observed.evidence.get(cap, ""),
                        claim=f"{tool.source_ref}: {tool.name}.annotations.readOnlyHint = true",
                    )
                )

        if annotations.get("openWorldHint") is False and Capability.NET_OUTBOUND in observed:
            findings.append(
                Finding(
                    sample_id=sample_id,
                    channel=Channel.RISK,
                    attack_class=AttackClass.UNDECLARED_NETWORK,
                    severity="high",
                    message=(
                        f"tool {tool.name!r} declares openWorldHint: false but the "
                        "implementation opens an outbound connection"
                    ),
                    evidence=observed.evidence.get(Capability.NET_OUTBOUND, ""),
                    claim=f"{tool.source_ref}: {tool.name}.annotations.openWorldHint = false",
                )
            )

        if (
            annotations.get("destructiveHint") is False
            and Capability.FS_DELETE in observed
            and not mutation_explained
        ):
            findings.append(
                Finding(
                    sample_id=sample_id,
                    channel=Channel.RISK,
                    attack_class=AttackClass.ANNOTATION_LIE,
                    severity="high",
                    message=(
                        f"tool {tool.name!r} declares destructiveHint: false but the "
                        "implementation deletes from the filesystem"
                    ),
                    evidence=observed.evidence.get(Capability.FS_DELETE, ""),
                    claim=f"{tool.source_ref}: {tool.name}.annotations.destructiveHint = false",
                )
            )

    return findings


def _allowed_tools_findings(artifact: Artifact, observed: Observed, sample_id: str) -> list[Finding]:
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
    used = _coarsen(observed.capabilities)
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
            evidence=observed.evidence.get(cap, ""),
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


def _posture_findings(artifact: Artifact, observed: Observed, sample_id: str) -> list[Finding]:
    """What the artifact can do. Recorded, displayed, and never counted toward a verdict."""
    findings: list[Finding] = []

    if Capability.SECRETS_READ in observed:
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message="reaches credential-bearing paths",
                evidence=observed.evidence.get(Capability.SECRETS_READ, ""),
                claim="posture: high-value target, not evidence of exfiltration",
            )
        )

    if {Capability.PROC_SPAWN, Capability.NET_OUTBOUND} <= observed.capabilities:
        findings.append(
            Finding(
                sample_id=sample_id,
                channel=Channel.POSTURE,
                severity="low",
                message="combines subprocess execution with outbound network access",
                evidence=observed.evidence.get(Capability.PROC_SPAWN, ""),
                claim="posture: broad blast radius",
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
    artifact: Artifact, observed: Observed, *, sample_id: str = ""
) -> list[Finding]:
    """Run every A2 check over one artifact.

    Returns risk findings first so a caller truncating the list keeps what matters.
    """
    checked = (
        _annotation_findings(artifact, observed, sample_id)
        + _allowed_tools_findings(artifact, observed, sample_id)
        + _provenance_findings(artifact, sample_id)
    )
    risks = [f for f in checked if f.channel is Channel.RISK]
    posture = [f for f in checked if f.channel is Channel.POSTURE]

    return risks + posture + _posture_findings(artifact, observed, sample_id)
