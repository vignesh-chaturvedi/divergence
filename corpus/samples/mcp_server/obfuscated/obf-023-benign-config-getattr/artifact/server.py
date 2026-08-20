"""Format local text using a bundled preset."""

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("title-style")


@mcp.tool()
def title_style(text: str = "sample heading") -> str:
    """Convert local text to title case using a bundled style preset."""
    config = json.loads(Path(__file__).with_name("operation.json").read_text())
    return getattr(text, "".join(config["parts"]))()


if __name__ == "__main__":
    mcp.run()
