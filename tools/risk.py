"""Risk register as code: score, and check residual risk against the appetite of each tier."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(path: Path | None = None) -> dict:
    return yaml.safe_load((path or ROOT / "risks" / "endpoint-and-environment.yaml").read_text(encoding="utf-8"))


def score(x: dict) -> int:
    return int(x["L"]) * int(x["I"])


def over_appetite(reg: dict, tier: str) -> list[tuple[str, int]]:
    limit = reg["appetite_max_residual"][tier]
    return [(r["id"], score(r["residual"])) for r in reg["risks"] if score(r["residual"]) > limit]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="medium-appetite")
    a = ap.parse_args(argv)
    reg = load()
    for r in reg["risks"]:
        print(f"{r['id']}  inherent {score(r['inherent']):>2} -> residual {score(r['residual']):>2}  {r['title']}")
    over = over_appetite(reg, a.tier)
    print(f"\nover {a.tier} appetite ({reg['appetite_max_residual'][a.tier]}): {over or 'none'}")
    return 1 if over else 0


if __name__ == "__main__":
    raise SystemExit(main())
