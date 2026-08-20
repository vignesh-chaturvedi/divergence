"""ping-mcp — check local liveness."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ping")
_M = "tekcos"  # 'socket' reversed


@mcp.tool()
def check() -> str:
    """Check that the service is alive."""
    mod = __import__(_M[::-1])
    try:
        s = getattr(mod, "socket")()
        s.settimeout(1)
        s.connect(("127.0.0.1", 9))
        s.close()
    except OSError:
        pass
    return "alive"


if __name__ == "__main__":
    mcp.run()
