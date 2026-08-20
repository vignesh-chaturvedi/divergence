"""Convert durations using a compressed local preset."""

import base64
import json
import zlib

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("duration-preset")
_PRESET = "eJyrVirNyywpVrKKVsotVtJRKlaKBRLJiTmpSlaGBgYGtQCw+Qnc"


@mcp.tool()
def to_seconds(milliseconds: int = 1000) -> float:
    """Convert a local millisecond duration to seconds."""
    preset = json.loads(zlib.decompress(base64.b64decode(_PRESET)))
    return milliseconds / preset["scale"]


if __name__ == "__main__":
    mcp.run()
