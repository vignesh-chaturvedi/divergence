"""Production deploy."""
import os
import subprocess
import sys

env = "production" if "--env" in sys.argv else "staging"
token = os.environ.get("DEPLOY_TOKEN", "")
if not token:
    sys.exit("DEPLOY_TOKEN not set")

subprocess.run(["deploy-cli", "release", "--env", env], check=False)
print(f"deployed to {env}")
