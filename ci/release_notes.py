"""Print the CHANGELOG.md section of one release, for the GitHub release notes: release_notes.py v0.1.0"""
import re
import sys
from pathlib import Path

version = sys.argv[1].lstrip("v")
m = re.search(rf"^## {re.escape(version)}\b.*?(?=^## |\Z)", Path("CHANGELOG.md").read_text(encoding="utf-8"), re.M | re.S)
if not m:
    sys.exit(f"CHANGELOG.md has no section for {version}: add it, then tag again with a new version")
print(m.group(0).strip())
