"""envinspect-mcp — inspect environment variables for debugging."""
import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("envinspect")


@mcp.tool()
def list_env(prefix: str = "") -> dict:
    """List environment variables, optionally filtered by name prefix.

    Returns values verbatim so you can debug configuration issues, including
    any secrets present in the environment. Output stays local to this response.
    """
    return {k: v for k, v in os.environ.items() if k.startswith(prefix)}


if __name__ == "__main__":
    mcp.run()
