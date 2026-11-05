"""Who must be told what, and is the communication plan itself healthy?

impacted(): from an affected capability to the people who depend on it, by criticality.
check_people(): every person meets the channel, independence, offline and delegate rules of their criticality.
plan(): the escalation ladder for one event.
test_state(): continuous communication tests as a control state (GREEN / AMBER / RED).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "communication.yaml").read_text(encoding="utf-8"))


def check_people(comm: dict, people: list[dict]) -> list[str]:
    errs = []
    for p in people:
        rule = comm["criticality"][p["criticality"]]
        chans = [comm["channels"][c] for c in p["channels"]]
        if len(chans) < rule["min_channels"]:
            errs.append(f"{p['id']}: {len(chans)} channels, needs {rule['min_channels']}")
        if sum(c["independent_of_platform"] for c in chans) < rule["min_independent"]:
            errs.append(f"{p['id']}: too few channels independent of the platform")
        if sum(not c["needs_internet"] for c in chans) < rule["min_offline"]:
            errs.append(f"{p['id']}: no channel that works without the network")
        if rule["delegate_required"] and not p.get("delegate"):
            errs.append(f"{p['id']}: no delegate")
    return errs


def impacted(capability: str, people: list[dict]) -> list[dict]:
    order = ["mission-critical", "key-user", "user"]
    hit = [p for p in people if capability in p.get("depends_on", [])]
    return sorted(hit, key=lambda p: order.index(p["criticality"]))


def plan(event: dict, comm: dict, people: list[dict], now: datetime) -> list[dict]:
    """Notifications for an event {trigger, capability, starts_at?}. Maintenance announced too late is flagged."""
    out = []
    for p in impacted(event["capability"], people):
        rule = comm["criticality"][p["criticality"]]
        ladder = [s for s in comm["escalation"] if s["to"] == "person"
                  or (s["to"] == "delegate" and p.get("delegate"))
                  or (s["to"] in ("site-contact", "service-owner") and p["criticality"] == "mission-critical")]
        late = False
        if event["trigger"] == "planned-maintenance":
            late = event["starts_at"] - now < timedelta(hours=rule["maintenance_notice_hours"])
        ranked = sorted(p["channels"], key=lambda c: (not comm["channels"][c]["independent_of_platform"],
                                                     comm["channels"][c]["needs_internet"]))
        out.append({"person": p["id"], "channels": ranked, "ladder": [s["to"] for s in ladder],
                    "ack_minutes": rule["ack_minutes"], "late_notice": late})
    return out


def test_state(comm: dict, last: dict[str, datetime | None], now: datetime) -> str:
    worst = "GREEN"
    for name, max_h in comm["continuous_test"]["max_age_hours"].items():
        t = last.get(name)
        if t is None or now - t > timedelta(hours=2 * max_h):
            return "RED"
        if now - t > timedelta(hours=max_h):
            worst = "AMBER"
    return worst
