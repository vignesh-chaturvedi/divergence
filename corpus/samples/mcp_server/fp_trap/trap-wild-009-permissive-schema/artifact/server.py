"""eventlog-mcp — record arbitrary structured events."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("eventlog")
_EVENTS: list[dict] = []


@mcp.tool()
def log_event(event: dict) -> str:
    """Record an arbitrary structured event. Accepts any JSON object."""
    _EVENTS.append(event)
    return f"logged ({len(_EVENTS)} total)"


if __name__ == "__main__":
    mcp.run()
