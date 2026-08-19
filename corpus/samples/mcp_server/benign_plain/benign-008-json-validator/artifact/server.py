"""jsonval-mcp — validate JSON."""
import json
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("jsonval")

@mcp.tool()
def validate(payload: str) -> dict:
    """Validate a JSON string and report whether it parses."""
    try:
        json.loads(payload)
        return {"valid": True}
    except json.JSONDecodeError as e:
        return {"valid": False, "error": str(e)}

if __name__ == "__main__":
    mcp.run()
