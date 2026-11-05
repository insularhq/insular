"""ZTOP, the Zero Trust Operational Picture: the live state of trust per request path and per layer, the core of both
panes of glass (provider and tenant).

Each request path (platform/zero-trust.yaml) is as trustworthy as its weakest enforcement point. An enforcement point
is GREEN only when it reports enforcing, its policy bundle is current and fresh, and the signals the path needs are
fresh; missing reports are UNKNOWN (silence is never green). Nearest prior art is the Cyber Common
Operational Picture in research literature.
"""

from __future__ import annotations

from datetime import datetime, timedelta

ORDER = {"GREEN": 0, "AMBER": 1, "UNKNOWN": 2, "RED": 3}


def pep_state(report: dict | None, bundle: str, now: datetime, max_age: timedelta) -> str:
    if not report:
        return "UNKNOWN"
    try:
        at = datetime.fromisoformat(report["at"])
    except (KeyError, TypeError, ValueError):
        return "RED"
    if at - now > timedelta(minutes=2) or not report.get("enforcing"):
        return "RED"
    if now - at > max_age:
        return "UNKNOWN"
    return "GREEN" if report.get("bundle") == bundle else "AMBER"


def picture(zt: dict, reports: dict, signals: dict, bundle: str, now: datetime, max_age: timedelta) -> dict:
    """reports: pep -> {at, enforcing, bundle}; signals: name -> {at}. Returns path states and an overall state."""
    paths = {}
    for p in zt["request_paths"]:
        states = [pep_state(reports.get(pep), bundle, now, max_age) for pep in p["peps"]]
        stale = [s for s in p["signals"] if s != "signature" and (s not in signals or now - datetime.fromisoformat(signals[s]["at"]) > max_age)]
        state = max(states, key=ORDER.get)
        if stale and ORDER[state] < ORDER["UNKNOWN"]:
            state = "UNKNOWN"
        if p["pdp"] == "exception" and state == "GREEN":
            state = "AMBER"   # a declared bypass is never shown as plainly green
        paths[p["path"]] = {"state": state, "peps": dict(zip(p["peps"], states)), "stale_signals": stale}
    overall = max((v["state"] for v in paths.values()), key=ORDER.get) if paths else "UNKNOWN"
    return {"paths": paths, "overall": overall}
