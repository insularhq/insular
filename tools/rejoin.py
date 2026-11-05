"""Reconnect pipeline: when a site returns, re-profile it, measure drift, score the risk, render it for the risk owner
and decide between reconcile, quarantine and destroy-and-rebuild, with the approval level the risk requires.

Builds on tools/reconcile.py (classification from the centre's records), tools/deviation.py (flow drift) and the
autonomy levels. Everything the site cannot prove counts against it.
"""

from __future__ import annotations

from datetime import datetime

from reconcile import plan

LEVELS = ["low", "medium", "high", "critical"]


def reprofile(site: dict, expected: dict) -> dict:
    """What the site is now, compared with what it should be."""
    have = set(site.get("components", {}).items())
    want = set(expected["components"].items())
    return {
        "attested": site.get("attestation_ok") is True,
        "unexpected_components": sorted(dict(have - want)),
        "missing_components": sorted(dict(want - have)),
        "policy_bundle_current": site.get("policy_bundle") == expected["policy_bundle"],
        "cache_over_age": [c for c, age in site.get("cache_age_hours", {}).items() if age > expected["cache_max_hours"].get(c, 0)],
    }


def drift(site: dict, expected: dict) -> list[str]:
    allowed = {tuple(f) for f in expected["flows"]}
    out = [f"flow {f}" for f in map(tuple, site.get("observed_flows", [])) if f not in allowed]
    out += [f"config {k}" for k, v in site.get("config", {}).items() if expected["config"].get(k) != v]
    return out


def score(cls: str, prof: dict, drifts: list[str], break_glass: int) -> str:
    if cls == "stale" or not prof["attested"]:
        return "critical"
    points = len(drifts) + 2 * break_glass + len(prof["unexpected_components"]) * 2 + len(prof["cache_over_age"])
    points += 0 if prof["policy_bundle_current"] else 1
    points += 2 if cls == "long" else 0
    return "low" if points == 0 else "medium" if points <= 3 else "high"


def decide(site: dict, centre: dict, expected: dict, now: datetime, grace_h: float, max_absence_h: float) -> dict:
    p = plan(site, centre, now, grace_h, max_absence_h)
    prof = reprofile(site, expected)
    d = drift(site, expected)
    risk = score(p["class"], prof, d, len(p["break_glass"]))
    action, approval = {
        "low": ("reconcile", "autonomous"),
        "medium": ("quarantine, then reconcile", "gated"),
        "high": ("quarantine; risk owner decides reconcile or rebuild", "human"),
        "critical": ("destroy and rebuild from the signed image; import data only through inspection", "external"),
    }[risk]
    card = [f"Site {site.get('id')} is back after {centre.get('last_seen')}.",
            f"Risk: {risk}. Proposed: {action}.",
            f"Changes found: {len(d)}. Unexpected software: {len(prof['unexpected_components'])}.",
            f"Emergency access used: {len(p['break_glass'])} time(s).",
            "Approve, choose another action, or ask a question."]
    return {"class": p["class"], "profile": prof, "drift": d, "risk": risk, "action": action,
            "approval": approval, "steps": p["steps"], "break_glass": p["break_glass"], "card": card}
