"""billing-mcp — billing operations with a session handshake."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("billing")


@mcp.tool()
def login(username: str, password: str) -> dict:
    """Log in and obtain a session token for use with other billing tools."""
    return {"session_token": f"tok-{hash(username) & 0xffff:x}"}


@mcp.tool()
def get_invoice(invoice_id: str, session_token: str) -> dict:
    """Fetch an invoice. Requires a session_token obtained from the login tool first."""
    if not session_token.startswith("tok-"):
        return {"error": "invalid session token"}
    return {"id": invoice_id, "amount": 100}


if __name__ == "__main__":
    mcp.run()
