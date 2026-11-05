"""Data logistics planner (ADR-0106): where data must be, by when, over which path, and what happens when a PoP
comes or goes.

- place(): may this product be placed at this site for this reader (demand, lease, ring)?
- transport(): network or carrier, from size, deadline and the link, with the carriers needed and the deltas after.
- spin_up(): the ordered pull plan for a new PoP.
- spin_down(): what drains, what returns on a carrier, what is crypto-shredded, and the power-off gate.
- backup(): copies, recovery point and time, and drills per product.

Usage: python tools/data_logistics.py   (checks the policy and prints the example spin-up plan)
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
CRIT = ["mission-critical", "important", "normal"]


def policy() -> dict:
    return yaml.safe_load((ROOT / "policies" / "data-logistics.yaml").read_text(encoding="utf-8"))


def member_of(pl: dict, site: str, today: str = "2026-10-10") -> str:
    """The site ring a site belongs to: its own, or its parent's while an evidenced membership lease runs."""
    m = (pl.get("memberships") or {}).get(site)
    if not m:
        return site
    if set(pl["placement"]["membership_conditions"]) - {k for k, v in (m.get("conditions") or {}).items() if v}:
        return site
    if str(m.get("member_until", "")) < today:
        return site
    return m["ring_site"]


def site_relation(pl: dict, home: str, target: str, today: str) -> str:
    """The narrowest ring that contains both sites: same site, same tenant, or beyond. `today` is required: an expired
    membership ends the site ring on the caller's date, not on a frozen default."""
    ring_site = lambda x: member_of(pl, x, today)   # a PoP joins its parent's site ring only as a current, evidenced member
    if ring_site(home) == ring_site(target):
        return "site"
    return "tenant" if target in pl["sites"] and home in pl["sites"] else "federation"


def place(d: dict, pl: dict, product: str, home: str, target: str, reader: str, purpose: str, today: str = "2026-10-10") -> dict:
    from data_provenance import current_lease
    order = d["pv"]["rings"]["order"]
    p = d["dp"]["products"][product]
    need = site_relation(pl, home, target, today)
    if order.index(need) > order.index(p["releasable_to"]):
        return {"allowed": False, "reason": f"{product} may not leave the {p['releasable_to']} ring; {target} is outside it"}
    lease = current_lease(d, product, reader, purpose, today)
    if not lease:
        return {"allowed": False, "reason": f"no current lease for {reader} on {product} for {purpose}: request one first"}
    return {"allowed": True, "lease": lease}


def transport(pl: dict, product: str, site: str, needed_in_hours: float) -> dict:
    t, prod, link = pl["transport"], pl["products"][product], pl["links"][site]
    gbps = link["mbps"] / 1000 * link["availability"] * t["network_efficiency"]
    hours = prod["size_gb"] * 8 / gbps / 3600 if gbps else math.inf
    daily = prod["change_gb_per_day"] * 8 / gbps / 3600 if gbps else math.inf
    sustain = {"daily_change_hours": round(daily, 1), "keeps_up": daily <= 24 * link["availability"],
               "advice": None if daily <= 24 * link["availability"] * 0.5 else
               "the link spends most of its uptime on this product's changes: thin it at the edge (aggregate, filter) or add bandwidth"}
    if hours <= min(needed_in_hours, t["max_network_hours"]):
        return {"mode": "network", "network_hours": round(hours, 1), "sustain": sustain}
    transit_days = max(1, math.ceil(needed_in_hours / 24))
    delta = prod["change_gb_per_day"] * (transit_days + 1)
    delta_hours = delta * 8 / gbps / 3600 if gbps else math.inf
    return {"mode": "carrier", "network_hours": round(hours, 1), "carriers": math.ceil(prod["size_gb"] / t["carrier"]["capacity_gb"]),
            "delta_gb": round(delta, 2), "delta_hours": round(delta_hours, 1),
            "sustain": sustain,
            "why": f"{prod['size_gb']} GB over the link takes {round(hours, 1)} h; the deadline is {needed_in_hours} h and the network limit {t['max_network_hours']} h"}


def spin_up(d: dict, pl: dict, site: str, demands: list[dict], needed_in_hours: float, today: str = "2026-10-10") -> list[dict]:
    """Ordered plan: mission-critical first; each demand placed, then moved by network or carrier."""
    plan = []
    for dm in sorted(demands, key=lambda x: CRIT.index(pl["products"][x["product"]]["criticality"])):
        pc = place(d, pl, dm["product"], dm["home"], site, dm["reader"], dm["purpose"], today)
        step = {"product": dm["product"], "criticality": pl["products"][dm["product"]]["criticality"], **pc}
        if pc["allowed"]:
            step["move"] = transport(pl, dm["product"], site, needed_in_hours)
            step["verify"] = "proof bundle and snapshot ids before first use"
        plan.append(step)
    return plan


def spin_down(d: dict, pl: dict, site: str, held: list[dict], acks: set[str] | None = None, today: str = "2026-10-10") -> dict:
    """held: [{unit, product, origin: originated|cached|audit|key, home}]. Returns steps and whether power-off may go."""
    order = d["pv"]["rings"]["order"]
    acks, steps = acks or set(), []
    for h in held:
        if h["origin"] == "originated":
            ring = d["dp"]["products"][h["product"]]["releasable_to"]
            need = site_relation(pl, site, h["home"], today)
            if order.index(need) <= order.index(ring):
                steps.append({"unit": h["unit"], "action": "drain", "to": h["home"], "needs_ack": True})
            else:
                steps.append({"unit": h["unit"], "action": "carrier-return or shred at retention", "to": site, "needs_ack": True,
                              "why": f"{ring}-bound data may not be drained to {h['home']}"})
        elif h["origin"] == "audit":
            steps.append({"unit": h["unit"], "action": "drain append-only, then shred locally", "to": pl["sites"][site].get("parent"), "needs_ack": True})
        elif h["origin"] == "cached":
            steps.append({"unit": h["unit"], "action": "crypto-shred and wipe", "needs_ack": False})
        elif h["origin"] == "key":
            steps.append({"unit": h["unit"], "action": "destroy and record in the shred ledger", "needs_ack": False})
    pending = [s["unit"] for s in steps if s["needs_ack"] and s["unit"] not in acks]
    return {"steps": steps, "pending": pending, "power_off_allowed": not pending}


def backup(d: dict, pl: dict, product: str) -> dict:
    c = pl["products"][product]["criticality"]
    b = dict(pl["backup"]["by_criticality"][c])
    ring = d["dp"]["products"][product]["releasable_to"]
    if "offline-carrier" in b["copies"] and ring == "site":
        b["offline_location"] = "the product's own site (site-bound data)"
    b |= {"contents": "ciphertext only", "keys": "backed up apart", "restore": "replays the shred ledger first"}
    return b


def check(d: dict | None = None) -> list[str]:
    from data_provenance import load
    d, pl, errs = d or load(), policy(), []
    for name, p in pl["products"].items():
        if name not in d["dp"]["products"]:
            errs.append(f"logistics product {name} is not a registered data product")
        if p["criticality"] not in CRIT or p["mode"] not in pl["replication"]["modes"]:
            errs.append(f"{name}: criticality and mode must be registered")
    if set(pl["backup"]["by_criticality"]) != set(CRIT):
        errs.append("backup: one class per criticality")
    for site, m in (pl.get("memberships") or {}).items():
        missing = set(pl["placement"]["membership_conditions"]) - {k for k, v in (m.get("conditions") or {}).items() if v}
        if missing:
            errs.append(f"membership {site}: conditions without evidence: {sorted(missing)} (the PoP stays its own site)")
        if m.get("ring_site") != pl["sites"].get(site, {}).get("parent"):
            errs.append(f"membership {site}: a PoP joins only its own parent's site ring")
    rpo = [pl["backup"]["by_criticality"][c]["rpo_minutes"] for c in CRIT]
    if rpo != sorted(rpo):
        errs.append("backup: more critical products have shorter recovery points")
    if any("ciphertext" not in pl["backup"]["rule"] for _ in [0]) or "ciphertext" not in pl["transport"]["carrier"]["contents"]:
        errs.append("backups and carriers move ciphertext only")
    return errs


if __name__ == "__main__":
    from data_provenance import load
    problems = check()
    print(f"logistics: {len(policy()['products'])} products, {len(policy()['sites'])} sites")
    for x in problems:
        print("ERROR", x)
    sys.exit(1 if problems else 0)
