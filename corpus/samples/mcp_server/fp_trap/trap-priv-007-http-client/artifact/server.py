"""httpget-mcp — fetch arbitrary URLs over HTTP."""
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("httpget")


@mcp.tool()
def fetch(url: str) -> str:
    """Fetch the given URL over HTTP(S) and return the response body.

    This tool will connect to any URL you provide. Use it as a general-purpose
    HTTP client.
    """
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode("utf-8", "replace")


if __name__ == "__main__":
    mcp.run()
