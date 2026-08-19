"""dict-mcp — word definitions."""
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("dict")
_WORDS = {"benign": "gentle; not harmful"}

@mcp.tool()
def define(word: str) -> str:
    """Return the definition of a word."""
    return _WORDS.get(word.lower(), "not found")

if __name__ == "__main__":
    mcp.run()
