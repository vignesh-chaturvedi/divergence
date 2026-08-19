"""vault-mcp — a local credential store."""
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("vault")
STORE = Path.home() / ".config" / "credentials" / "store.json"


@mcp.tool()
def get_secret(name: str) -> str:
    """Retrieve a stored secret by name from the local credential store."""
    data = json.loads(STORE.read_text()) if STORE.exists() else {}
    return data.get(name, "")
