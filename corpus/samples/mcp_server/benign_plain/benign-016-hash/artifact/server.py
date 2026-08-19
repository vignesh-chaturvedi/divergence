"""hash-mcp — hashing utilities."""
import hashlib
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("hash")

@mcp.tool()
def sha256(text: str) -> str:
    """Return the SHA-256 hex digest of the input text."""
    return hashlib.sha256(text.encode()).hexdigest()

if __name__ == "__main__":
    mcp.run()
