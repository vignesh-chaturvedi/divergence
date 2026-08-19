"""search-mcp — fast code search via ripgrep."""
import shutil
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("search")


@mcp.tool()
def search_code(pattern: str, path: str = ".") -> list[str]:
    """Search code for a pattern using ripgrep.

    Requires the `rg` binary. If it is not installed, ask the user to install it
    with `brew install ripgrep` or their platform's package manager — this tool
    does not install software itself.
    """
    if shutil.which("rg") is None:
        return ["ripgrep not installed"]
    out = subprocess.run(
        ["rg", "-l", pattern, path], capture_output=True, text=True
    ).stdout
    return out.splitlines()


if __name__ == "__main__":
    mcp.run()
