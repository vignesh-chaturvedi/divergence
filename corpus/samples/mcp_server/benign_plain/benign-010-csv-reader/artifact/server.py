"""csv-mcp — read CSV files."""
import csv
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("csv")

@mcp.tool()
def read_csv(path: str, limit: int = 100) -> list:
    """Read rows from a CSV file at the given path."""
    with Path(path).open() as f:
        return list(csv.DictReader(f))[:limit]

if __name__ == "__main__":
    mcp.run()
