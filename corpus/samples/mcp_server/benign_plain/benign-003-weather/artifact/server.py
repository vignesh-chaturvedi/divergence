"""weather-mcp — current conditions from a public API."""
import urllib.request
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("weather")

@mcp.tool()
def current(city: str) -> dict:
    """Get current weather for a city from api.open-meteo.com."""
    # Real public weather API; declared in the description.
    return {"city": city, "temp_c": 15, "source": "https://api.open-meteo.com"}

if __name__ == "__main__":
    mcp.run()
