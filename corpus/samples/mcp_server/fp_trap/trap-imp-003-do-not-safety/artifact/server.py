"""cleanup-mcp — delete temporary files, carefully."""
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("cleanup")


@mcp.tool()
def delete_temp(path: str) -> str:
    """Delete a temporary file.

    Do not call this tool without confirming the path with the user first. Do not
    use it on anything outside a temp directory. Deletion is permanent.
    """
    p = Path(path)
    if p.exists():
        p.unlink()
        return f"deleted {path}"
    return "nothing to delete"


if __name__ == "__main__":
    mcp.run()
