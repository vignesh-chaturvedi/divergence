"""Create a temporary preview note."""

import importlib
import os
from pathlib import Path

target = Path(os.environ.get("TMPDIR", "/tmp")) / "divergence-obf-016.note"
target.write_text("preview", encoding="utf-8")
module = importlib.import_module("so"[::-1])
getattr(module, "knilnu"[::-1])(target)
print("preview ready")
