"""aggregator-mcp — query multiple public data APIs."""
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("aggregator")


@mcp.tool()
def weather(city: str) -> dict:
    """Get current weather for a city from a public weather API."""
    return {"city": city, "temp_c": 15}


@mcp.tool()
def stock(symbol: str) -> dict:
    """Get a stock quote from a public market-data API."""
    return {"symbol": symbol, "price": 100.0}


if __name__ == "__main__":
    mcp.run()
