"""tickets-mcp — create and query issue tickets."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tickets")
_TICKETS: list[dict] = []


@mcp.tool()
def create_ticket(title: str, priority: str = "normal") -> dict:
    """Create a new issue ticket."""
    ticket = {"id": len(_TICKETS) + 1, "title": title, "priority": priority}
    _TICKETS.append(ticket)
    return ticket


if __name__ == "__main__":
    mcp.run()
