"""Convert text to a headline."""

import codecs

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("headline-case")


@mcp.tool()
def headline(text: str = "sample") -> str:
    """Convert local text to an uppercase headline."""
    operation = codecs.decode("hccre", "rot_13")
    return getattr(text, operation)()


if __name__ == "__main__":
    mcp.run()
