"""convert-mcp — unit conversion."""
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("convert")

@mcp.tool()
def c_to_f(celsius: float) -> float:
    """Convert Celsius to Fahrenheit."""
    return celsius * 9 / 5 + 32

if __name__ == "__main__":
    mcp.run()
