"""A stdio MCP server that serves a corpus sample's declared manifest.

Existing scanners in this space analyse a **live** server: they launch it from a client
config and call `tools/list`. The corpus is static source, so without a bridge the two
cannot be compared at all — which is a real reason no precision benchmark exists here.

This shim closes that gap by serving a sample's `manifest.json` over the MCP stdio
protocol. It never imports or executes the sample's implementation.

That makes it **safer and more faithful at the same time**:

- Safer, because a malicious sample's handler never runs.
- More faithful, because these scanners analyse the *reasoning surface* — tool names,
  descriptions, input schemas, annotations — and that is exactly what the manifest holds.
  Running the real handler would give them nothing extra to read.

The protocol is implemented directly rather than via the `mcp` SDK so the shim has no
dependencies and cannot itself become a variable in the comparison.

Usage:  python -m divergence.bench.manifest_shim <path/to/manifest.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROTOCOL_VERSION = "2024-11-05"


def _respond(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def _load_tools(manifest_path: Path) -> list[dict]:
    try:
        data = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError):
        return []

    tools = []
    for entry in data.get("tools", []):
        tool = {
            "name": entry.get("name", ""),
            "description": entry.get("description", ""),
            "inputSchema": entry.get("inputSchema") or {"type": "object", "properties": {}},
        }
        if entry.get("annotations"):
            tool["annotations"] = entry["annotations"]
        tools.append(tool)
    return tools


def serve(manifest_path: Path) -> int:
    tools = _load_tools(manifest_path)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        request_id = request.get("id")

        # Notifications carry no id and expect no reply.
        if request_id is None:
            continue

        if method == "initialize":
            _respond(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": manifest_path.parent.name, "version": "1.0.0"},
                    },
                }
            )
        elif method == "tools/list":
            _respond({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
        elif method in ("prompts/list", "resources/list"):
            key = method.split("/")[0]
            _respond({"jsonrpc": "2.0", "id": request_id, "result": {key: []}})
        elif method == "ping":
            _respond({"jsonrpc": "2.0", "id": request_id, "result": {}})
        else:
            _respond(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"method not found: {method}"},
                }
            )

    return 0


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: manifest_shim <manifest.json>", file=sys.stderr)
        return 2
    return serve(Path(args[0]))


if __name__ == "__main__":
    raise SystemExit(main())
