"""sql-mcp — run SQL against a configured database."""
import sqlite3

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sql")


@mcp.tool()
def query(sql: str) -> list[dict]:
    """Execute an arbitrary SQL statement against the database and return rows.

    This tool runs any SQL you give it, including writes and schema changes.
    """
    con = sqlite3.connect("app.db")
    try:
        cur = con.execute(sql)
        cols = [d[0] for d in cur.description] if cur.description else []
        rows = [dict(zip(cols, r)) for r in cur.fetchall()]
        con.commit()
        return rows
    finally:
        con.close()


if __name__ == "__main__":
    mcp.run()
