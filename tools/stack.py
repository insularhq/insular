"""The stack as one product: lock validation, version bump from the change class, and release readiness."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
BUMP = {"standard": "patch", "normal": "minor", "major": "major"}


def load(rel: str, root: Path = ROOT) -> dict:
    return yaml.safe_load((root / rel).read_text(encoding="utf-8"))


def lock_errors(lock: dict, runtime: set[str], bom_licences: dict[str, str], support_end: date) -> list[str]:
    errs = []
    pinned = lock.get("components", {})
    for c in sorted(runtime - set(pinned)):
        errs.append(f"{c}: not pinned in the stack lock")
    for c, p in pinned.items():
        if c not in runtime:
            errs.append(f"{c}: pinned but not part of any size")
            continue
        if lock.get("status") == "released" and not DIGEST.match(str(p.get("digest", ""))):
            errs.append(f"{c}: a released lock needs a sha256 digest")
        if p.get("licence") != bom_licences.get(c):
            errs.append(f"{c}: licence {p.get('licence')} differs from the bill of materials ({bom_licences.get(c)})")
        if p.get("eol") and date.fromisoformat(str(p["eol"])) < support_end:
            errs.append(f"{c}: end of life {p['eol']} falls inside the support window")
    return errs


def next_version(current: str, change_class: str) -> str:
    major, minor, patch = (int(x) for x in current.split("."))
    kind = BUMP[change_class]
    if kind == "major":
        return f"{major + 1}.0.0"
    if kind == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def release_blockers(cfg: dict, kind: str, results: dict[str, bool]) -> list[str]:
    out = []
    for stage in cfg["required_for"][kind]:
        if stage not in results:
            out.append(f"{stage}: did not run")
        elif not results[stage]:
            out.append(f"{stage}: failed")
    return out
