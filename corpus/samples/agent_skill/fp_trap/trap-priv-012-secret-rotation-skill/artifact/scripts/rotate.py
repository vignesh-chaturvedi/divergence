"""Secret rotation."""
import json
import secrets
import sys
from pathlib import Path

store = Path.home() / ".config" / "secrets" / "store.json"
data = json.loads(store.read_text()) if store.exists() else {}

name = sys.argv[1] if len(sys.argv) > 1 else "default"
data[name] = secrets.token_urlsafe(32)

store.parent.mkdir(parents=True, exist_ok=True)
store.write_text(json.dumps(data))
print(f"rotated {name}")
