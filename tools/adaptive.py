"""Adaptive policy (platform/adaptive-policy.yaml): signals -> risk band -> decision per path, workload profile for a
remote browser session, and loud, localisable notices with a disclosure level. Unknown is never green.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import yaml

from clock import floor, skew, utc

ROOT = Path(__file__).resolve().parent.parent
ORDER = ["green", "amber", "red", "black"]


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "adaptive-policy.yaml").read_text(encoding="utf-8"))


def _fresh(sig: dict | None, max_age: int, now: datetime) -> bool:
    """Fresh means at most max_age old and not dated beyond now plus the clock skew: a future-dated
    signal never ages, so it is not fresh at all. An unreadable time is not fresh."""
    if not sig or "at" not in sig:
        return False
    try:
        at, n = utc(sig["at"]), utc(now)
    except (TypeError, ValueError):
        return False
    return at - n <= skew() and n - at <= timedelta(minutes=max_age)


def band(cfg: dict, signals: dict, now: datetime, watermark: datetime | None = None) -> dict:
    """signals: name -> {value, at}. Returns {band, score, reasons}. `watermark` is the latest time this evaluator has
    accepted: now never goes below it, so a clock set back does not revive old signals."""
    now = floor(now, watermark)
    reasons, score = [], 0
    vals = {}
    for name, spec in cfg["signals"].items():
        sig = signals.get(name)
        if _fresh(sig, spec["max_age"], now):
            vals[name] = sig["value"]
        elif not spec.get("optional"):
            score += cfg["weights"]["missing_signal"]
            reasons.append("SIGNAL_MISSING")
    worst = "green"
    for rule in cfg["hard_rules"]:
        field, value = [x.strip() for x in rule["when"].split("==")]
        # a sticky deny keeps its band when the signal goes stale: expiry only tightens
        stale_deny = rule.get("sticky") and (signals.get(field) or {}).get("value") == value
        if vals.get(field) == value or stale_deny:
            reasons.append(rule["reason"])
            worst = max(worst, rule["band"], key=ORDER.index)
    for name, table in cfg["weights"].items():
        if isinstance(table, dict) and name in vals:
            score += table.get(vals[name], cfg["weights"]["missing_signal"])
    code = {"network": {"unknown": "NOT_ENTERPRISE_NETWORK"}, "time_of_day": {"outside": "OUTSIDE_HOURS"},
            "device_posture": {"outdated": "DEVICE_OUTDATED"}, "environment": {"amber": "SITE_AT_RISK", "red": "SITE_AT_RISK"},
            "world_state": {"high": "THREAT_LEVEL_HIGH", "severe": "THREAT_LEVEL_HIGH"}, "behaviour": {"anomaly": "BEHAVIOUR_ANOMALY"}}
    for name, m in code.items():
        if vals.get(name) in m:
            reasons.append(m[vals[name]])
    scored = "green" if score <= cfg["bands"]["green"] else "amber" if score <= cfg["bands"]["amber"] else "red"
    worst = max(worst, scored, key=ORDER.index)
    return {"band": worst, "score": score, "reasons": sorted(set(reasons))}


def decide(cfg: dict, path: str, b: dict) -> dict:
    tol = cfg["path_tolerance"][path]
    if ORDER.index(b["band"]) > ORDER.index(tol["max"]):
        return {"allow": False, "step_up": False, "reasons": b["reasons"] or ["SIGNAL_MISSING"]}
    step = b["band"] == "amber" and tol.get("amber_requires") == "step-up"
    return {"allow": True, "step_up": step, "reasons": b["reasons"]}


def workload_profile(cfg: dict, owner_band: str, facts: set[str], world_state: str) -> str:
    """Profile of a remote browser session: 'open' or 'isolated' (no internal, no external)."""
    triggers = set(cfg["workload_profiles"]["isolate_when"])
    hit = owner_band in ("red", "black") or world_state == "severe" or bool(facts & {
        "image not attested", "perimeter drift detected", "egress incident open"} & {t for t in triggers})
    return "isolated" if hit else "open"


def notice(cfg: dict, reasons: list[str], ref: str, at: datetime, case_disclosure: str | None = None) -> dict:
    """A loud, complete message. Discreet reasons show a neutral text; the real codes go to the security officer."""
    fl = cfg["fail_loudly"]
    discreet = case_disclosure == "discreet" or (case_disclosure != "full" and any(r in fl["disclosure"]["default_discreet"] for r in reasons))
    if discreet:
        shown = [{"code": "ACCESS_RESTRICTED", "text": "Access is temporarily restricted.", "todo": "Contact your security officer."}]
    else:
        shown = [{"code": r, **cfg["reasons"][r]} for r in reasons]
    return {"messages": shown, "reference": ref, "time": at.isoformat(), "contact": "your security officer or the service desk",
            "logged_reasons": reasons, "discreet": discreet}


TRUST_ORDER = ["none", "low", "medium", "high"]


def trust(cfg: dict, evidence: dict, now: datetime) -> dict:
    """evidence: signal -> {sensor, at, signed, strong_identity}. Trust is what the evidence is worth, not how good it looks."""
    t = cfg["trust"]
    pts, reasons = [], []
    for name, ev in evidence.items():
        spec = cfg["signals"].get(name, {"max_age": 0})
        sensor = cfg["sensors"].get(ev.get("sensor"), {})
        fresh = _fresh(ev, spec["max_age"], now)
        p = (t["evidence_points"]["attested"] if sensor.get("attested") else 0) + (t["evidence_points"]["signed_sensor"] if ev.get("signed") else 0) \
            + (t["evidence_points"]["fresh"] if fresh else 0) + (t["evidence_points"]["strong_identity"] if ev.get("strong_identity") else 0)
        if not sensor.get("attested"):
            p = min(p, t["thresholds"]["medium"])
        if not fresh:
            p = min(p, t["thresholds"]["low"])
            reasons.append(f"{name}: stale")
        if not ev.get("strong_identity"):
            p = min(p, t["thresholds"]["low"])
        pts.append(p)
    score = sum(pts) / len(pts) if pts else 0
    level = next((lv for lv in ("high", "medium", "low") if score >= t["thresholds"][lv]), "none")
    return {"trust": level, "score": round(score, 2), "reasons": reasons}


def decide_tr(cfg: dict, path: str, tr: dict, b: dict) -> dict:
    """Allow only if trust is high enough AND risk is within the path's tolerance."""
    need = cfg["path_trust"][path]
    if TRUST_ORDER.index(tr["trust"]) < TRUST_ORDER.index(need):
        return {"allow": False, "step_up": False, "reasons": ["SIGNAL_MISSING"] + b["reasons"], "why": f"trust {tr['trust']} below {need}"}
    d = decide(cfg, path, b)
    d["why"] = "ok" if d["allow"] else f"risk {b['band']} above tolerance"
    return d


def on_event(cfg: dict, event: str) -> list[str]:
    """Actions a continuous-access event triggers; unknown events are treated as anomalies."""
    return cfg["continuous"].get(event, ["raise-anomaly", "notify-security-officer"])
