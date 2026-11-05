"""Classification checks: required level per infrastructure layer, and whether tenants may share a layer."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "classification.yaml").read_text(encoding="utf-8"))


def required_level(cls: dict, layer: str, hosted: list[str]) -> str | None:
    """Plaintext and authority layers inherit the highest hosted label; ciphertext and metadata layers need none."""
    if cls["layers"][layer]["sees"] in ("plaintext", "authority"):
        return max(hosted, key=cls["labels"].index)
    return None


def cohost(cls: dict, a: str, b: str, layer: str, boundary: str, isolation: dict) -> list[str]:
    """May tenants with labels a and b share this layer, separated by the given isolation level?"""
    if cls["layers"][layer]["sees"] not in ("plaintext", "authority"):
        return []
    rank = cls["labels"].index
    hi = max(a, b, key=rank)
    errs = []
    if a != b and hi == cls["labels"][-1]:
        errs.append(f"{hi} is the top label: it never shares {layer} with a {min(a, b, key=rank)} tenant")
    if abs(rank(a) - rank(b)) > cls["max_cohost_gap"]:
        errs.append(f"label gap {a}/{b} exceeds {cls['max_cohost_gap']} on {layer}")
    order = isolation["isolation_order"]
    floor = isolation["isolation_floor"][hi]
    if order.index(boundary) < order.index(floor):
        errs.append(f"boundary {boundary} on {layer} is below the {hi} floor {floor}")
    return errs
