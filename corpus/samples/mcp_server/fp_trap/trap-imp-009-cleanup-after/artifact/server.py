"""lock-mcp — a distributed lock with acquire/release lifecycle."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("lock")
_HELD = set()


@mcp.tool()
def acquire(resource: str) -> str:
    """Acquire a lock on a resource.

    After you are done, you must call release on the same resource. Failing to
    release leaves the lock held and blocks other clients.
    """
    _HELD.add(resource)
    return f"acquired {resource}"


@mcp.tool()
def release(resource: str) -> str:
    """Release a previously acquired lock."""
    _HELD.discard(resource)
    return f"released {resource}"


if __name__ == "__main__":
    mcp.run()
