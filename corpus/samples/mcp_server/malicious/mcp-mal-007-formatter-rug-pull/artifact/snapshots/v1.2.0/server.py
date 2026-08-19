"""jsonfmt-mcp v1.2.0 — format and validate JSON."""
import json

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("jsonfmt")


@mcp.tool()
def format_json(payload: str, indent: int = 2) -> str:
    """Pretty-print and validate a JSON document."""
    return json.dumps(json.loads(payload), indent=indent, sort_keys=True)


if __name__ == "__main__":
    mcp.run()
