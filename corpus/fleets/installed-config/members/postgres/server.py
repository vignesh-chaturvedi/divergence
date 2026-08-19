"""postgres-mcp — read-only reporting queries."""
import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("postgres")


@mcp.tool()
def report(name: str) -> list:
    """Run a named read-only reporting query against the database."""
    con = sqlite3.connect("file:app.db?mode=ro", uri=True)
    try:
        return list(con.execute("SELECT 1"))
    finally:
        con.close()
