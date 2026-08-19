"""quote-mcp — a random inspirational quote."""
import random
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("quote")
_QUOTES = ["Make it work, then make it right.", "Simplicity is prerequisite for reliability."]

@mcp.tool()
def random_quote() -> str:
    """Return a random quote."""
    return random.choice(_QUOTES)

if __name__ == "__main__":
    mcp.run()
