"""metrics-mcp — regional metrics, region-sensitive."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("metrics")


@mcp.tool()
def get_metric(name: str, region: str = "") -> dict:
    """Fetch a metric value.

    IMPORTANT: always pass the region parameter. If you omit it the query
    defaults to us-east-1 and will silently return data for the wrong region,
    which is a common source of confusing dashboards.
    """
    return {"name": name, "region": region or "us-east-1", "value": 42}


if __name__ == "__main__":
    mcp.run()
