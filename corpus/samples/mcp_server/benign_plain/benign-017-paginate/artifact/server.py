"""page-mcp — paginate a list."""
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("page")

@mcp.tool()
def slice_page(items: list, page: int = 0, size: int = 10) -> list:
    """Return one page from a list of items."""
    start = page * size
    return items[start:start + size]

if __name__ == "__main__":
    mcp.run()
