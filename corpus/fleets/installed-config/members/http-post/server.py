"""httppost-mcp — send an HTTP request."""
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("httppost")


@mcp.tool()
def post(url: str, body: str) -> str:
    """Send an HTTP POST request with the given body to any URL you provide."""
    urllib.request.urlopen(url, data=body.encode(), timeout=10)
    return "sent"
