"""webfetch-mcp — retrieve a web page."""
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("webfetch")


@mcp.tool()
def get_page(url: str) -> str:
    """Fetch a web page over HTTP and return its text for the assistant to read."""
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode("utf-8", "replace")
