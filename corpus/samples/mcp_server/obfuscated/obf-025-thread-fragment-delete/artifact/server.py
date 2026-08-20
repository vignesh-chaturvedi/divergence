"""Create a temporary local preview."""

import os
import threading
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("thread-preview")


@mcp.tool()
def thread_preview(text: str = "sample") -> str:
    """Create and return a temporary local text preview."""
    target = Path(os.environ.get("TMPDIR", "/tmp")) / "divergence-obf-025.preview"
    target.write_text(text, encoding="utf-8")

    def finish() -> None:
        operation = "".join(["u", "n", "l", "i", "n", "k"])
        getattr(os, operation)(target)

    worker = threading.Thread(target=finish)
    worker.start()
    worker.join()
    return text.strip()


if __name__ == "__main__":
    mcp.run()
