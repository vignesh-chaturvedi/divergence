"""Seam: probe(root) -> Observed.

The minimal deterministic sink scan. This is *not* P2's static behaviour extractor —
there is no reachability and no taint, so it over-reports (a sink in dead code still
counts). That trade is deliberate: A2 needs to know whether a handler writes at all, and
a conservative over-report costs a posture note while an under-report costs a missed
annotation lie.

Every capability must carry a file:line, because a risk finding without evidence is not
reviewable.
"""

from pathlib import Path

from divergence.core.probe import probe
from divergence.core.vocabulary import Capability

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "samples"


def _probe(sample_id: str, kind: str, stratum: str):
    return probe(CORPUS / kind / stratum / sample_id / "artifact")


def test_detects_filesystem_write():
    obs = _probe("mcp-mal-008-readonly-annotation-lie", "mcp_server", "malicious")
    assert Capability.FS_WRITE in obs.capabilities


def test_detects_outbound_network_in_python():
    obs = _probe("mcp-mal-010-env-sweep-uptime", "mcp_server", "malicious")
    assert Capability.NET_OUTBOUND in obs.capabilities


def test_detects_outbound_network_in_typescript():
    obs = _probe("mcp-mal-009-markdown-undeclared-egress", "mcp_server", "malicious")
    assert Capability.NET_OUTBOUND in obs.capabilities


def test_detects_subprocess_spawn():
    obs = _probe("trap-priv-001-shell-executor", "mcp_server", "fp_trap")
    assert Capability.PROC_SPAWN in obs.capabilities


def test_detects_credential_paths_as_secrets_read():
    obs = _probe("skill-mal-006-git-helper-credential-read", "agent_skill", "malicious")
    assert Capability.SECRETS_READ in obs.capabilities


def test_detects_dynamic_evaluation():
    obs = _probe("mcp-mal-012-plugin-dynamic-eval", "mcp_server", "malicious")
    assert Capability.DYNAMIC_EVAL in obs.capabilities


def test_detects_environment_read():
    obs = _probe("mcp-mal-010-env-sweep-uptime", "mcp_server", "malicious")
    assert Capability.ENV_READ in obs.capabilities


def test_detects_shell_download_in_markdown_body():
    """A skill's payload can be a curl in prose, never in a script file."""
    obs = _probe("skill-mal-002-onboarding-remote-fetch", "agent_skill", "malicious")
    assert Capability.NET_OUTBOUND in obs.capabilities


def test_pure_computation_has_no_capabilities():
    """The floor case. A calculator must probe clean or every metric downstream is noise."""
    obs = _probe("benign-001-calculator", "mcp_server", "benign_plain")
    assert obs.capabilities == set()


def test_pure_transform_skill_script_has_no_capabilities():
    obs = _probe("benign-020-slugify-skill", "agent_skill", "benign_plain")
    assert obs.capabilities == set()


def test_every_capability_carries_evidence():
    obs = _probe("mcp-mal-010-env-sweep-uptime", "mcp_server", "malicious")
    for cap in obs.capabilities:
        assert obs.evidence[cap], f"{cap} has no file:line evidence"
        assert ":" in obs.evidence[cap]


def test_probe_never_imports_the_target():
    """Parsing only. Importing an MCP server runs its module body."""
    import sys

    before = set(sys.modules)
    _probe("mcp-mal-012-plugin-dynamic-eval", "mcp_server", "malicious")
    assert not {m for m in set(sys.modules) - before if "plugin" in m}
