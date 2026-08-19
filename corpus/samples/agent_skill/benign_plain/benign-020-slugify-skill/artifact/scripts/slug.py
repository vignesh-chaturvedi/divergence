"""Slugify — pure transform, no I/O."""
import re
import sys

title = sys.argv[1] if len(sys.argv) > 1 else ""
slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
print(slug)
