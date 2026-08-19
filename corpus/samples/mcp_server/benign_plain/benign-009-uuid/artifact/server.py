"""uuid-mcp — generate UUIDs."""
import uuid
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("uuid")

@mcp.tool()
def generate() -> str:
    """Generate a random UUID v4."""
    return str(uuid.uuid4())

if __name__ == "__main__":
    mcp.run()
