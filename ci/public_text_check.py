"""Public text check: everything posted to the public repository is public at once (issues, pull requests, comments,
added lines and commit messages). Hard failures are local paths, private keys and tokens; INSULAR_PRIVATE_PATTERNS (a CI
secret, one regex per line) adds what would publish itself, and is reported by number only.

  public_text_check.py --text FILE        a posted text
  public_text_check.py --range BASE..HEAD added diff lines and commit messages

Exit 0 clean, 3 on a match: a maintainer reads it, and the text is edited or the match explained.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = [("a local path", r"(?i)(c:[\\/]+users[\\/]+|/home/[a-z]+/|/users/[a-z]+/)"),
            ("a private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            ("a token", r"(glpat-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})")]


def hits(text: str) -> list[str]:
    extra = [(f"private pattern {n}", p) for n, p in
             enumerate(filter(None, os.environ.get("INSULAR_PRIVATE_PATTERNS", "").splitlines()), start=1)]
    return [label for label, rx in PATTERNS + extra if re.search(rx, text)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--text")
    ap.add_argument("--range")
    a = ap.parse_args()
    if a.text:
        text = Path(a.text).read_text(encoding="utf-8", errors="replace")
    elif a.range:
        git = lambda *args: subprocess.run(["git", *args], capture_output=True, text=True, errors="replace", check=True).stdout  # noqa: E731
        added = [ln[1:] for ln in git("diff", a.range).splitlines() if ln.startswith("+") and not ln.startswith("+++")]
        text = "\n".join(added) + "\n" + git("log", "--format=%B", a.range)
    else:
        ap.error("give --text FILE or --range BASE..HEAD")
    found = hits(text)
    for label in found:
        print(f"HOLD this text contains {label}: a maintainer reads it, then edits the text or explains the match")
    return 3 if found else 0


if __name__ == "__main__":
    sys.exit(main())
