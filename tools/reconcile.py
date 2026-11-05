"""Return of an edge site after an absence or a break-glass: classify, plan the steps, and decide what happens to
every action taken locally.

The centre decides on its OWN records: absence is computed from the centre's last-seen time, not
reported by the site; break-glass events are the union of what the site reports and what the centre observed from
the use log of the break-glass credentials; anything the site cannot prove (chain, attestation) counts as failed.

Classes: short (within grace) -> resync; long (beyond grace, or any break-glass) -> quarantine, verify, resync,
gated re-admission; stale (beyond the edge intermediate's lifetime, broken or unproven chain, failed or missing
attestation, suspected compromise) -> rebuild from the signed image, import data only through inspection,
re-admission by the external authority. Every break-glass action becomes a retroactive decision card.
"""

from __future__ import annotations

from datetime import datetime

ORDER = ["revocations", "policy-and-config", "data", "audit-chains", "evidence"]


def absence_hours(centre: dict, now: datetime) -> float:
    """Hours since the centre last saw the site. Anything unprovable counts as infinitely long."""
    try:
        seen = datetime.fromisoformat(centre["last_seen"])
        hours = (now - seen).total_seconds() / 3600
    except (KeyError, TypeError, ValueError):
        return float("inf")
    return float("inf") if hours < 0 else hours


def events(site: dict, centre: dict) -> list[dict]:
    seen = {e["id"]: e for e in site.get("break_glass_events", [])}
    for e in centre.get("break_glass_uses", []):
        seen.setdefault(e["id"], {**e, "unreported": True})
    return list(seen.values())


def classify(site: dict, centre: dict, now: datetime, grace_h: float, max_absence_h: float) -> str:
    if centre.get("compromise_suspected") or site.get("chain_ok") is not True or site.get("attestation_ok") is not True:
        return "stale"
    absent = absence_hours(centre, now)
    if absent > max_absence_h:
        return "stale"
    if absent > grace_h or events(site, centre):
        return "long"
    return "short"


def plan(site: dict, centre: dict, now: datetime, grace_h: float, max_absence_h: float) -> dict:
    cls = classify(site, centre, now, grace_h, max_absence_h)
    evs = events(site, centre)
    authority = {"short": "autonomous", "long": "gated", "stale": "external"}[cls]
    if cls == "short":
        steps = [f"resync {s}" for s in ORDER]
    elif cls == "long":
        steps = ["quarantine: evidence upload only", "verify audit chain and attestation"] + \
                [f"resync {s}" for s in ORDER] + ["rotate break-glass credentials" if evs else "rotate site credentials"]
    else:
        steps = ["isolate", "preserve forensic copy", "wipe and reinstall from the signed image",
                 "re-attest hardware", "issue new keys and edge intermediate", "import data only through inspection",
                 "resync revocations", "resync policy-and-config", "anchor recovered audit chain as evidence"]
    if any(e.get("unreported") for e in evs):
        steps.append("incident: break-glass use not reported by the site")
    return {"class": cls, "steps": steps, "readmission_authority": authority, "break_glass": [ratify(e) for e in evs]}


def ratify(event: dict) -> dict:
    """Each break-glass action is presented to its risk owner after the fact."""
    decided = event.get("ratified")
    if decided is True:
        outcome = "ratified: recorded as an accepted risk with its justification; effects kept until their expiry"
    elif decided is False:
        outcome = "not ratified: effects reverted to declared state; incident opened"
    else:
        outcome = "pending: decision card sent to the risk owner; effects reverted at the deadline if undecided"
    return {"id": event["id"], "action": event.get("action", "unknown"), "outcome": outcome}
