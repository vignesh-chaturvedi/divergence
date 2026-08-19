"""Seam: Ledger.record / Ledger.diff.

A3 canonicalises and hashes an artifact at first approval, then classifies what changed
on rescan. The classification is the finding: post-approval mutation is invisible to any
single-snapshot scan because at every individual moment the artifact looks consistent.
"""

from pathlib import Path

import pytest

from divergence.core.acquire import acquire
from divergence.core.ledger import ChangeKind, Ledger
from divergence.core.vocabulary import AttackClass, Channel

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "samples"


@pytest.fixture
def ledger(tmp_path):
    return Ledger(tmp_path / "ledger.db")


def _snapshots(sample_id: str, kind: str, stratum: str):
    art = acquire(CORPUS / kind / stratum / sample_id / "artifact")
    return [acquire(s.root) for s in art.snapshots]


def test_first_record_produces_no_finding(ledger):
    v1, _ = _snapshots("mcp-mal-007-formatter-rug-pull", "mcp_server", "malicious")
    assert ledger.record(v1, artifact_id="jsonfmt") == []


def test_rescanning_an_unchanged_artifact_is_silent(ledger):
    v1, _ = _snapshots("mcp-mal-007-formatter-rug-pull", "mcp_server", "malicious")
    ledger.record(v1, artifact_id="jsonfmt")
    assert ledger.diff(v1, artifact_id="jsonfmt") == []


def test_capability_expanding_mutation_is_a_risk(ledger):
    """v1.2.0 is clean and gets approved. v1.3.0 keeps the same description and adds egress."""
    v1, v2 = _snapshots("mcp-mal-007-formatter-rug-pull", "mcp_server", "malicious")
    ledger.record(v1, artifact_id="jsonfmt")
    findings = ledger.diff(v2, artifact_id="jsonfmt")

    risks = [f for f in findings if f.channel is Channel.RISK]
    assert risks
    assert risks[0].attack_class is AttackClass.POST_APPROVAL_MUTATION
    assert risks[0].is_evidence_bound


def test_skill_bundle_mutation_is_caught(ledger):
    """The payload is in a bundled script, not the frontmatter — the bundle must be hashed."""
    v1, v2 = _snapshots("skill-mal-011-changelog-rug-pull", "agent_skill", "malicious")
    ledger.record(v1, artifact_id="changelog")
    risks = [f for f in ledger.diff(v2, artifact_id="changelog") if f.channel is Channel.RISK]
    assert risks and risks[0].attack_class is AttackClass.POST_APPROVAL_MUTATION


def test_cosmetic_change_is_posture_not_risk(ledger):
    """Reworded prose with no new capability must not raise a verdict."""
    v1, _ = _snapshots("mcp-mal-007-formatter-rug-pull", "mcp_server", "malicious")
    ledger.record(v1, artifact_id="jsonfmt")

    reworded = v1.__class__(
        root=v1.root,
        kind=v1.kind,
        tools=(v1.tools[0].__class__(
            name=v1.tools[0].name,
            description=v1.tools[0].description + " Formats nicely.",
            annotations=v1.tools[0].annotations,
            schema_properties=v1.tools[0].schema_properties,
            required=v1.tools[0].required,
            source_ref=v1.tools[0].source_ref,
        ),),
        skill=v1.skill,
        bundle_files=v1.bundle_files,
        provenance=v1.provenance,
    )
    findings = ledger.diff(reworded, artifact_id="jsonfmt", observed_capabilities=set())
    assert [f for f in findings if f.channel is Channel.RISK] == []
    assert any(f.channel is Channel.POSTURE for f in findings)


def test_change_kinds_are_ordered_by_severity():
    assert ChangeKind.SEMANTICS_INVERTING > ChangeKind.CAPABILITY_EXPANDING
    assert ChangeKind.CAPABILITY_EXPANDING > ChangeKind.COSMETIC


def test_ledger_persists_across_instances(tmp_path):
    """Approval survives a process restart or the ledger is useless."""
    db = tmp_path / "ledger.db"
    v1, v2 = _snapshots("mcp-mal-007-formatter-rug-pull", "mcp_server", "malicious")

    Ledger(db).record(v1, artifact_id="jsonfmt")
    risks = [f for f in Ledger(db).diff(v2, artifact_id="jsonfmt") if f.channel is Channel.RISK]
    assert risks


def test_canonical_hash_is_stable_across_runs(ledger):
    v1, _ = _snapshots("mcp-mal-007-formatter-rug-pull", "mcp_server", "malicious")
    assert ledger.fingerprint(v1) == ledger.fingerprint(v1)


def test_reordering_tools_does_not_change_the_hash(ledger):
    """Canonicalisation must ignore ordering, or every rescan reports a phantom mutation."""
    art = acquire(CORPUS / "mcp_server" / "malicious" / "mcp-mal-001-note-reader-ssh-exfil" / "artifact")
    reversed_tools = art.__class__(
        root=art.root, kind=art.kind, tools=tuple(reversed(art.tools)),
        skill=art.skill, bundle_files=art.bundle_files, provenance=art.provenance,
    )
    assert ledger.fingerprint(art) == ledger.fingerprint(reversed_tools)
