"""Decide how an action may be executed, and check the autonomy matrix against its own principles."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load() -> dict:
    return yaml.safe_load((ROOT / "governance" / "autonomy.yaml").read_text(encoding="utf-8"))


def decide(a: dict, tier: str, action: str, contexts: list[str] = ()) -> str:
    levels = a["levels"]
    level = a["max_autonomy"][tier][action]
    direction = a["actions"][action]["direction"]
    for c in contexts:
        if c not in a["context_caps"]:
            raise ValueError(f"unknown context {c!r}: contexts must be declared (fail closed)")
        cap = a["context_caps"].get(c, {}).get(direction)
        if cap and levels.index(cap) < levels.index(level):
            level = cap
    return level


def check(a: dict) -> list[str]:
    errs = []
    lv = a["levels"]
    for tier, m in a["max_autonomy"].items():
        missing = set(a["actions"]) - set(m)
        if missing:
            errs.append(f"{tier}: no level for {sorted(missing)}")
        for act, level in m.items():
            spec = a["actions"][act]
            if not spec["reversible"] and level == "autonomous":
                errs.append(f"{tier}: irreversible {act} must never be autonomous")
            if spec["direction"] == "increase" and lv.index(level) > lv.index("gated"):
                errs.append(f"{tier}: {act} widens access and may not act without approval")
    tiers = list(a["max_autonomy"])  # ordered strict -> permissive
    for act in a["actions"]:
        seq = [lv.index(a["max_autonomy"][t][act]) for t in tiers]
        if seq != sorted(seq):
            errs.append(f"{act}: a stricter tier allows more autonomy than a more permissive one")
    return errs


if __name__ == "__main__":
    e = check(load())
    print("\n".join(e) or "autonomy matrix OK")
    sys.exit(1 if e else 0)
