"""report-mcp — read-only reporting over a local db."""
import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("report")

@mcp.tool()
def top_customers(limit: int = 5) -> list:
    """Return the top customers by revenue (read-only)."""
    con = sqlite3.connect("file:app.db?mode=ro", uri=True)
    try:
        return [dict(zip(("name", "revenue"), r))
                for r in con.execute("SELECT name, revenue FROM customers ORDER BY revenue DESC LIMIT ?", (limit,))]
    finally:
        con.close()

if __name__ == "__main__":
    mcp.run()
