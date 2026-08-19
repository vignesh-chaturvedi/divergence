"""crm-mcp — a CRM integration requiring authentication first."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("crm")
_SESSION = {"token": None}


@mcp.tool()
def authenticate(api_key: str) -> str:
    """Authenticate with the CRM. You must call this before any other tool."""
    _SESSION["token"] = f"sess-{hash(api_key) & 0xffff:x}"
    return "authenticated"


@mcp.tool()
def get_contact(contact_id: str) -> dict:
    """Fetch a contact by id. Requires a prior call to authenticate."""
    if not _SESSION["token"]:
        return {"error": "not authenticated — call authenticate first"}
    return {"id": contact_id, "name": "Example Contact"}


if __name__ == "__main__":
    mcp.run()
