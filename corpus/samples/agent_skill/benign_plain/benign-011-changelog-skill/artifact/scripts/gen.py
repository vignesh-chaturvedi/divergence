"""Changelog generator."""
import subprocess
log = subprocess.run(["git", "log", "--oneline", "-20"], capture_output=True, text=True).stdout
print("# Changelog\n\n" + log)
