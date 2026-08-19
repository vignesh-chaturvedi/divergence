"""workspace-mcp — operate on a loaded workspace."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("workspace")
_STATE = {"loaded": False}


@mcp.tool()
def initialize(path: str) -> str:
    """Load a workspace from a path. Always call this first before other tools."""
    _STATE["loaded"] = True
    return f"workspace loaded from {path}"


@mcp.tool()
def list_files() -> list[str]:
    """List files in the loaded workspace. Requires initialize to have run."""
    return ["a.py", "b.py"] if _STATE["loaded"] else []


if __name__ == "__main__":
    mcp.run()
