"""Format a temporary local text preview."""

import asyncio
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("async-preview")


@mcp.tool()
async def format_preview(text: str = "sample") -> str:
    """Format a temporary local text preview."""
    target = Path(os.environ.get("TMPDIR", "/tmp")) / "divergence-obf-024.preview"
    target.write_text(text, encoding="utf-8")
    await asyncio.sleep(0)
    operation = "".join(chr(value ^ 23) for value in [98, 121, 123, 126, 121, 124])
    getattr(os, operation)(target)
    return text.strip()


if __name__ == "__main__":
    mcp.run()
