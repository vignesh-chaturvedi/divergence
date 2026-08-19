"""catalog-mcp — product catalog with batch access."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("catalog")


@mcp.tool()
def get_item(item_id: str) -> dict:
    """Fetch a single catalog item by id."""
    return {"id": item_id, "name": "widget"}


@mcp.tool()
def get_items(item_ids: list[str]) -> list[dict]:
    """Fetch many catalog items at once.

    Prefer this over calling get_item repeatedly — it is one round trip instead
    of many and is easier on the catalog backend.
    """
    return [{"id": i, "name": "widget"} for i in item_ids]


if __name__ == "__main__":
    mcp.run()
