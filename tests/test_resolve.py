"""Seam: resolve(target) -> [ResolvedTarget].

A1 must accept more than a directory path. The offline sources — a skill bundle, a
server directory, a local client config — are the ones that matter for the product's
actual entry point ("scan what I have installed") and are the only ones testable without
network, so they are what P1 implements.

Remote specs (npm, PyPI, GitHub) must fail with a clear reason rather than silently
resolving to nothing.
"""

import json

import pytest

from divergence.core.resolve import ResolutionError, resolve

CORPUS_DIR = "corpus/samples/mcp_server/malicious/mcp-mal-008-readonly-annotation-lie/artifact"


def test_resolves_a_directory(tmp_path):
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    targets = resolve(str(repo / CORPUS_DIR))
    assert len(targets) == 1
    assert targets[0].artifact.kind == "mcp_server"


def test_resolves_every_server_in_a_client_config(tmp_path):
    """The real entry point: point it at an MCP client config and scan the whole fleet."""
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    a = repo / CORPUS_DIR
    b = repo / "corpus/samples/mcp_server/benign_plain/benign-001-calculator/artifact"

    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "liar": {"command": "python", "args": [str(a / "server.py")]},
                    "calc": {"command": "python", "args": [str(b / "server.py")]},
                }
            }
        )
    )

    targets = resolve(str(config))
    assert {t.name for t in targets} == {"liar", "calc"}


def test_client_config_entry_that_cannot_be_located_is_reported_not_dropped(tmp_path):
    """Silently skipping an unresolvable server would understate the fleet."""
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {"mcpServers": {"ghost": {"command": "npx", "args": ["-y", "some-remote-server"]}}}
        )
    )

    targets = resolve(str(config))
    assert len(targets) == 1
    assert targets[0].unresolved_reason


def test_remote_spec_fails_loudly(tmp_path):
    with pytest.raises(ResolutionError) as exc:
        resolve("npm:@modelcontextprotocol/server-filesystem")
    assert "network" in str(exc.value).lower()


def test_missing_path_fails_loudly():
    with pytest.raises(ResolutionError):
        resolve("/nonexistent/path/to/nothing")
