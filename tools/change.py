"""Change classification against the accredited envelope, release evidence completeness, and backlog priority."""

from __future__ import annotations

import fnmatch
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ORDER = ["standard", "normal", "major"]


def load(rel: str, root: Path = ROOT) -> dict:
    return yaml.safe_load((root / rel).read_text(encoding="utf-8"))


def path_class(path: str, envelope: dict) -> str:
    if any(fnmatch.fnmatch(path, pat) for pat in envelope["major"]):
        return "major"
    if any(fnmatch.fnmatch(path, pat) for pat in envelope["standard"]):
        return "standard"
    return "normal"   # default: an unlisted path is never pre-authorised


def classify(changed: list[str], envelope: dict) -> str:
    """The class of a change is the highest class any changed path falls in."""
    return max((path_class(p, envelope) for p in changed), key=ORDER.index, default="standard")


def missing_evidence(bundle: dict, delivery: dict) -> list[str]:
    return [k for k in delivery["evidence_bundle"]["required"] if not bundle.get(k)]


def priority(item: dict) -> float:
    return round((item["user_value"] + item["risk_reduction"] + 0.5 * item["requesters"]) / item["effort"], 2)


def needs_budget_decision(item: dict, remaining_budget: float) -> bool:
    return item["estimated_cost"] > remaining_budget
