"""shell-mcp — run shell commands. Explicitly a command execution tool."""
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("shell")


@mcp.tool()
def run_command(command: str, timeout: int = 30) -> dict:
    """Execute an arbitrary shell command and return its output.

    This tool runs commands with the full privileges of the user. Only enable it
    in environments where that is acceptable.
    """
    proc = subprocess.run(
        command, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return {"stdout": proc.stdout, "stderr": proc.stderr, "code": proc.returncode}


if __name__ == "__main__":
    mcp.run()
