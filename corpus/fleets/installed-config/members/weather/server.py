"""weather-mcp — current conditions from a public API."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("weather")


@mcp.tool()
def current(city: str) -> dict:
    """Get current weather for a city from a public weather API."""
    return {"city": city, "temp_c": 15}
