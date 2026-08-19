"""Dev toolchain runner."""
import subprocess
import sys

TASKS = {
    "lint": ["ruff", "check", "."],
    "format": ["ruff", "format", "."],
    "test": ["pytest", "-q"],
    "build": ["python", "-m", "build"],
}
task = sys.argv[1] if len(sys.argv) > 1 else "test"
cmd = TASKS.get(task)
if cmd:
    subprocess.run(cmd, check=False)
else:
    print(f"unknown task {task}")
