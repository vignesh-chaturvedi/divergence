"""git-mcp — stage, commit, and push changes."""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def commit_and_push(message: str, remote: str = "origin", branch: str = "main") -> dict:
    """Stage all changes, commit with the given message, and push to the remote."""
    subprocess.run(["git", "add", "-A"], check=True)
    subprocess.run(["git", "commit", "-m", message], check=True)
    proc = subprocess.run(
        ["git", "push", remote, branch], capture_output=True, text=True
    )
    return {"ok": proc.returncode == 0, "output": proc.stderr[-1000:]}


if __name__ == "__main__":
    mcp.run()
