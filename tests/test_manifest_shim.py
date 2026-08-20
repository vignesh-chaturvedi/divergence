"""The benchmark's live-MCP bridge must expose declarations without running artifacts."""

from __future__ import annotations

import io
import json

import divergence.bench.manifest_shim as shim


def test_load_tools_normalises_schema_and_preserves_annotations(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "read_note",
                        "description": "Read one note",
                        "annotations": {"readOnlyHint": True},
                    },
                    {
                        "name": "search",
                        "description": "Search notes",
                        "inputSchema": {"type": "object", "required": ["query"]},
                    },
                ]
            }
        )
    )

    tools = shim._load_tools(manifest)

    assert tools[0]["inputSchema"] == {"type": "object", "properties": {}}
    assert tools[0]["annotations"] == {"readOnlyHint": True}
    assert tools[1]["inputSchema"]["required"] == ["query"]


def test_load_tools_treats_missing_or_invalid_manifest_as_empty(tmp_path):
    missing = tmp_path / "missing.json"
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not-json")

    assert shim._load_tools(missing) == []
    assert shim._load_tools(invalid) == []


def test_stdio_server_implements_safe_read_only_protocol(monkeypatch, capsys, tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"tools": [{"name": "safe", "description": "A declared tool"}]}))
    requests = [
        "",
        "not-json",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "prompts/list"}),
        json.dumps({"jsonrpc": "2.0", "id": 4, "method": "resources/list"}),
        json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}),
        json.dumps({"jsonrpc": "2.0", "id": 6, "method": "tools/call"}),
    ]
    monkeypatch.setattr(shim.sys, "stdin", io.StringIO("\n".join(requests)))

    assert shim.serve(manifest) == 0

    responses = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [response["id"] for response in responses] == [1, 2, 3, 4, 5, 6]
    assert responses[0]["result"]["protocolVersion"] == shim.PROTOCOL_VERSION
    assert responses[0]["result"]["serverInfo"]["name"] == tmp_path.name
    assert responses[1]["result"]["tools"][0]["name"] == "safe"
    assert responses[2]["result"] == {"prompts": []}
    assert responses[3]["result"] == {"resources": []}
    assert responses[4]["result"] == {}
    assert responses[5]["error"]["code"] == -32601


def test_main_requires_manifest_and_delegates(monkeypatch, capsys, tmp_path):
    assert shim.main([]) == 2
    assert "usage: manifest_shim" in capsys.readouterr().err

    manifest = tmp_path / "manifest.json"
    seen = []
    monkeypatch.setattr(shim, "serve", lambda path: seen.append(path) or 7)
    assert shim.main([str(manifest)]) == 7
    assert seen == [manifest]
