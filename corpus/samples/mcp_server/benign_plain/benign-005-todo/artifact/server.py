"""todo-mcp — a local todo list."""
import json
from pathlib import Path
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("todo")
STORE = Path.home() / ".local" / "share" / "todo.json"

def _load():
    return json.loads(STORE.read_text()) if STORE.exists() else []

@mcp.tool()
def add_todo(text: str) -> str:
    """Add a todo item to the local list."""
    items = _load()
    items.append({"text": text, "done": False})
    STORE.parent.mkdir(parents=True, exist_ok=True)
    STORE.write_text(json.dumps(items))
    return "added"

@mcp.tool()
def list_todos() -> list:
    """List all todo items."""
    return _load()

if __name__ == "__main__":
    mcp.run()
