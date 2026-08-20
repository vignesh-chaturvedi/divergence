"""Seam: acquire(path) -> Artifact.

A1's contract is that it resolves a target's *declared surface* without executing it.
Tested against real corpus samples rather than hand-built fixtures, so the parser is
exercised on the same shapes the benchmark scores.
"""

from pathlib import Path

from divergence.core.acquire import Artifact, acquire

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "samples"


def _artifact(sample_id: str, kind: str, stratum: str) -> Artifact:
    return acquire(CORPUS / kind / stratum / sample_id / "artifact")


def test_acquires_mcp_server_tools_from_manifest():
    art = _artifact("mcp-mal-001-note-reader-ssh-exfil", "mcp_server", "malicious")
    assert art.kind == "mcp_server"
    names = {t.name for t in art.tools}
    assert names == {"read_note", "search_notes"}


def test_tool_carries_description_schema_and_annotations():
    art = _artifact("mcp-mal-008-readonly-annotation-lie", "mcp_server", "malicious")
    tool = art.tool("get_config")
    assert "Does not modify anything" in tool.description
    assert tool.annotations.get("readOnlyHint") is True
    assert "key" in tool.schema_properties


def test_acquires_skill_frontmatter():
    art = _artifact("skill-mal-003-linter-exceeds-allowed-tools", "agent_skill", "malicious")
    assert art.kind == "agent_skill"
    assert art.skill is not None
    assert art.skill.name == "python-linter"
    assert art.skill.allowed_tools == "Read"
    assert "Lint Python files" in art.skill.description


def test_skill_with_no_allowed_tools_reports_none_not_empty_string():
    """Absence must be distinguishable from an empty declaration downstream."""
    art = _artifact("skill-mal-002-onboarding-remote-fetch", "agent_skill", "malicious")
    assert art.skill.allowed_tools is None


def test_bundle_walk_finds_scripts_the_frontmatter_never_mentions():
    """§04: for skills, walk the full bundle — scripts, resources, anything unmentioned."""
    art = _artifact("skill-mal-001-formatter-trigger-hijack", "agent_skill", "malicious")
    bundled = {f.name for f in art.bundle_files}
    assert "collect.py" in bundled


def test_provenance_read_from_package_metadata():
    art = _artifact("mcp-mal-011-filesystem-typosquat", "mcp_server", "malicious")
    assert art.provenance.name == "filesystem-mcp-server"
    assert art.provenance.author == "npm-user-4417"
    # Signature/download claims in an artifact-controlled registry.json are untrusted.
    assert art.provenance.signed is None


def test_typosquat_distance_against_popular_names():
    art = _artifact("mcp-mal-011-filesystem-typosquat", "mcp_server", "malicious")
    assert art.provenance.typosquat_distance == 1
    assert art.provenance.nearest_popular_name


def test_benign_package_has_no_typosquat_signal():
    art = _artifact("benign-007-markdown-local", "mcp_server", "benign_plain")
    assert art.provenance.typosquat_distance is None


def test_snapshots_are_detected_and_ordered():
    """Rug-pull samples ship two versions; the ledger needs them oldest-first."""
    art = _artifact("mcp-mal-007-formatter-rug-pull", "mcp_server", "malicious")
    assert [s.label for s in art.snapshots] == ["v1.2.0", "v1.3.0"]


def test_tools_parsed_from_source_when_no_manifest():
    """Static parse of tool-registration calls is primary, not a fallback."""
    art = acquire(
        CORPUS / "mcp_server" / "malicious" / "mcp-mal-001-note-reader-ssh-exfil" / "artifact"
    )
    from_source = acquire(art.root, use_manifest=False)
    assert {t.name for t in from_source.tools} == {"read_note", "search_notes"}


def test_acquire_is_idempotent():
    a = _artifact("benign-001-calculator", "mcp_server", "benign_plain")
    b = _artifact("benign-001-calculator", "mcp_server", "benign_plain")
    assert [t.name for t in a.tools] == [t.name for t in b.tools]
