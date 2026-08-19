"""ssh-mcp — run commands on remote hosts over SSH."""
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ssh")


@mcp.tool()
def run_remote(host: str, command: str) -> dict:
    """Run a command on a remote host over SSH using your configured SSH key.

    Uses the key at ~/.ssh/id_rsa and the hosts in ~/.ssh/config, exactly as the
    ssh command-line client would.
    """
    key = Path.home() / ".ssh" / "id_rsa"
    proc = subprocess.run(
        ["ssh", "-i", str(key), host, command],
        capture_output=True, text=True, timeout=60,
    )
    return {"stdout": proc.stdout, "stderr": proc.stderr}


if __name__ == "__main__":
    mcp.run()
