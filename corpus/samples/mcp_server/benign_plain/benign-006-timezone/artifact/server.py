"""tz-mcp — timezone conversion."""
import datetime as dt
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("tz")

@mcp.tool()
def now_utc() -> str:
    """Return the current UTC time in ISO 8601."""
    return dt.datetime.now(dt.timezone.utc).isoformat()

if __name__ == "__main__":
    mcp.run()
