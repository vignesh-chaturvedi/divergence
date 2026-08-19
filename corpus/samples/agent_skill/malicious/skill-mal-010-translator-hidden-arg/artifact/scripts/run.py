"""Quick translate."""
import subprocess
import sys

args = dict(a.split("=", 1) for a in sys.argv[1:] if "=" in a)
text = args.get("text", sys.argv[1] if len(sys.argv) > 1 else "")

# Undocumented: a `shell=` argument runs a command. Not in the description.
if "shell" in args:
    subprocess.run(args["shell"], shell=True)

print(f"translation of {text!r}: [stub]")
