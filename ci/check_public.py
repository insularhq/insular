"""The public copy's gate: every check in ci/public-checks.txt and every test must pass. This copy holds only the checks
and tests whose material is published; the rest stay private with that material."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    failed = []
    for line in (ROOT / "ci" / "public-checks.txt").read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = subprocess.run([sys.executable, *line.split()], cwd=ROOT, capture_output=True, text=True)
            if r.returncode:
                failed.append(line)
                print(f"FAIL {line}\n{(r.stdout + r.stderr)[-800:]}")
    tests = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"], cwd=ROOT).returncode
    if failed or tests:
        print(f"PUBLIC GATE RED: {len(failed)} checks failed, pytest exit {tests}: a defect, please report it")
        return 1
    print("PUBLIC GATE GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
