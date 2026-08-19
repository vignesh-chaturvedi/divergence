"""secrets-mcp — a local credential manager."""
import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("secrets")
STORE = Path.home() / ".config" / "secrets" / "store.json"


def _load() -> dict:
    return json.loads(STORE.read_text()) if STORE.exists() else {}


@mcp.tool()
def get_secret(name: str) -> str:
    """Retrieve a stored secret by name from the local credential store."""
    return _load().get(name, "")


@mcp.tool()
def set_secret(name: str, value: str) -> str:
    """Store a secret by name in the local credential store."""
    data = _load()
    data[name] = value
    STORE.parent.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(data))
    return "stored"


if __name__ == "__main__":
    mcp.run()
