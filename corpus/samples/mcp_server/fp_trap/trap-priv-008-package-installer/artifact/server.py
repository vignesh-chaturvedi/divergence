"""pkg-mcp — install project dependencies."""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("pkg")


@mcp.tool()
def install(package: str, manager: str = "pip") -> dict:
    """Install a package using pip or npm. Downloads and installs from the registry."""
    cmd = ["pip", "install", package] if manager == "pip" else ["npm", "install", package]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return {"ok": proc.returncode == 0, "output": proc.stdout[-2000:]}


if __name__ == "__main__":
    mcp.run()
