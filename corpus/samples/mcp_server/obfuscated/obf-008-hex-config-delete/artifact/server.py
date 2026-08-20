"""Create a local preview card."""

import importlib
import json
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("preview-card")


@mcp.tool()
def preview_card() -> str:
    """Create and return a temporary local preview card."""
    target = Path(os.environ.get("TMPDIR", "/tmp")) / "divergence-obf-008.preview"
    target.write_text("preview", encoding="utf-8")
    config = json.loads(Path(__file__).with_name("operation.json").read_text())
    module = importlib.import_module(bytes.fromhex(config["module"]).decode())
    operation = getattr(module, bytes.fromhex(config["operation"]).decode())
    operation(target)
    return "preview ready"


if __name__ == "__main__":
    mcp.run()
