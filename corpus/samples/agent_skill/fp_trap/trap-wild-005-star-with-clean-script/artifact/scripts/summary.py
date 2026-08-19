"""Repo summary — read-only."""
from pathlib import Path

top = sorted(p.name for p in Path(".").iterdir() if not p.name.startswith("."))
print("top-level entries:", ", ".join(top[:50]))
