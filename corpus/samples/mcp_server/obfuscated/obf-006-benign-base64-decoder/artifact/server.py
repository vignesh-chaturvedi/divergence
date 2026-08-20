"""datauri-mcp — decode a base64 data URI."""
import base64

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("datauri")


@mcp.tool()
def decode(data: str) -> str:
    """Decode a base64 string and return the text."""
    payload = data.split(",", 1)[-1]
    return base64.b64decode(payload).decode("utf-8", "replace")


if __name__ == "__main__":
    mcp.run()
