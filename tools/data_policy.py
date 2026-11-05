"""Data-centric limits as policy (ADR-0100).

Where data may go, how small an aggregate may be and how long a subscription may run are rules in policy packs. They
are not constants in code:
- `policies/packs/data-centric.yaml` is the baseline, each rule naming the standards it implements;
- a sector or tenant pack tightens them with a more specific scope;
- a pack loosens them only with raises_risk, a minimum trust and a risk acceptance.

limits() resolves them for a context (tenant, trust, band, day) through the same engine the OPA bundle mirrors.
check() verifies the direction of every deviation, and that every standard named exists in the framework register.

Usage: python tools/data_policy.py
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
LABELS = ["Internal", "Sensitive", "Restricted"]
RINGS = ["host", "site", "tenant", "federation", "public"]
TOPICS = ("data-max-ring", "data-max-ring-unidentified", "data-max-ring-transcribed", "data-min-group-size",
          "data-lease-subscription-days", "data-ring-ceiling")
TODAY = date(2026, 10, 10)


def limits(ctx: dict | None = None, day: date | None = None) -> dict:
    """The effective data limits for a context; every value comes from a rule, with the rule id alongside."""
    from policy_engine import band_floor, effective, load
    model, rules = load()
    floors, day, ctx = band_floor(model), day or TODAY, dict(ctx or {})
    eff = lambda extra: effective(rules, {**ctx, **extra}, day, floors)
    base, by_label = eff({}), {lab: eff({"label": lab}) for lab in LABELS}
    out = {"label_max_ring": {lab: by_label[lab]["data-max-ring"]["parameter"] for lab in LABELS},
           "max_ring_by_assurance": {"unidentified": base["data-max-ring-unidentified"]["parameter"],
                                     "transcribed": base["data-max-ring-transcribed"]["parameter"]},
           "min_group_size": int(base["data-min-group-size"]["parameter"]),
           "subscription_max_days": {lab: int(by_label[lab]["data-lease-subscription-days"]["parameter"]) for lab in LABELS},
           "ring_ceiling": {lab: by_label[lab]["data-ring-ceiling"]["parameter"] for lab in LABELS},
           "rules": sorted({base[t]["rule"] for t in TOPICS if base.get(t, {}).get("rule")}
                           | {by_label[lab][t]["rule"] for lab in LABELS for t in TOPICS if by_label[lab].get(t, {}).get("rule")})}
    return out


def _looser(topic: str, base, other) -> bool:
    if topic.startswith("data-max-ring") or topic == "data-ring-ceiling":
        return RINGS.index(str(other)) > RINGS.index(str(base))
    if topic == "data-min-group-size":
        return int(other) < int(base)
    return int(other) > int(base)


def check() -> list[str]:
    from policy_engine import load
    model, rules = load()
    reg = yaml.safe_load((ROOT / "frameworks" / "register.yaml").read_text(encoding="utf-8"))["frameworks"]
    errs = []
    for r in rules:
        for s in r.get("standards", []):
            if str(s).split(":")[0] not in reg:
                errs.append(f"{r['id']}: standard {s} is not in frameworks/register.yaml")
        if r["topic"] in TOPICS and not r.get("standards"):
            errs.append(f"{r['id']}: a data-centric rule names the standards it implements")
    try:
        base = limits()
    except (KeyError, TypeError) as e:
        return errs + [f"baseline pack incomplete: no rule for {e}"]
    days = [base["subscription_max_days"][x] for x in LABELS]
    rings = [RINGS.index(base["label_max_ring"][x]) for x in LABELS]
    if days != sorted(days, reverse=True) or rings != sorted(rings, reverse=True):
        errs.append("baseline: subscription limits and widest rings must shrink from Internal to Restricted")
    ceil = [RINGS.index(base["ring_ceiling"][x]) for x in LABELS]
    if ceil != sorted(ceil, reverse=True) or any(c < r for c, r in zip(ceil, rings)):
        errs.append("baseline: ceilings shrink toward Restricted and are never narrower than the widest ring")
    for r in rules:
        if r["topic"] not in TOPICS or not (r.get("scope") or {}).get("tenant"):
            continue
        labs = (r["scope"] or {}).get("label") or [None]
        for lab in labs:
            if r["topic"] == "data-max-ring":
                b = base["label_max_ring"][lab]
            elif r["topic"] == "data-ring-ceiling":
                b = base["ring_ceiling"][lab]
            elif r["topic"] == "data-lease-subscription-days":
                b = base["subscription_max_days"][lab]
            elif r["topic"] == "data-min-group-size":
                b = base["min_group_size"]
            else:
                b = base["max_ring_by_assurance"][r["topic"].rsplit("-", 1)[1]]
            if _looser(r["topic"], b, r["parameter"]) and not (r.get("raises_risk") and r.get("min_trust") and r.get("acceptance")):
                errs.append(f"{r['id']}: loosens {r['topic']} ({b} -> {r['parameter']}) without raises_risk, min_trust and an acceptance")
    return errs


if __name__ == "__main__":
    problems = check()
    lim = limits()
    print(f"data limits from {len(lim['rules'])} rules: rings {lim['label_max_ring']}, min group {lim['min_group_size']}")
    for p in problems:
        print("ERROR", p)
    sys.exit(1 if problems else 0)
