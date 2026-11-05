"""Detection and response cards per capability (ADR-0085): drift method and interval, detector, trust and risk impact,
coordinates in time and cyberspace, and the response ladder with act or inform per rung (autonomy from tools/autonomy.py).

Usage: python tools/detection_response.py [CAPABILITY]   (prints the card; checks all cards)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from autonomy import decide, load as aload  # noqa: E402


def _y(rel: str):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def load() -> dict:
    return {"dr": _y("platform/detection-response.yaml"), "contracts": _y("catalog/contracts.yaml")["contracts"],
            "facets": _y("platform/facets.yaml"), "obs": _y("platform/observability.yaml"), "mp": _y("policies/master-protection.yaml"),
            "bind": _y("policies/infra-bindings.yaml")["bindings"], "autonomy": aload()}


def card(d: dict, cap: str, appetite: str = "medium-appetite", contexts: tuple[str, ...] = ()) -> dict:
    f, mp, dr = d["facets"], d["mp"], d["dr"]
    master = f["masters_by_capability"].get(cap)
    prot = f["protection"].get(cap, "")
    lever = prot[7:] if prot.startswith("lever: ") else None
    target = master or lever
    tier = "tier0" if (target and target in mp["tiers"]["tier0"]) or cap in mp["tiers"].get("tier0_dependencies", []) else "tier1"
    profiles = d["obs"]["capabilities"].get(cap, [])
    method = "adapter-verify" if target and target != "out-of-band management" else (
        "redfish" if target == "out-of-band management" else dr["method_by_profile"].get(profiles[0]) if profiles else None)
    m = dr["drift_methods"].get(method, {})
    facts = mp["masters"].get(master, {}).get("facts", []) if master else []
    risks = sorted({r for fa in facts for r in d["bind"].get(fa, {}).get("risks", [])} | set(f["risk_links"].get(cap, [])))
    ctx = list(contexts) + (["tier0-target"] if tier == "tier0" else [])
    rungs = []
    for r in dr["ladder"]:
        action = dr["target_actions"].get(r["rung"], {}).get(cap, r["action"])
        level = decide(d["autonomy"], appetite, action, ctx)
        inform = [f["owners"].get(cap)]
        if tier == "tier0" or r["rung"] in ("revocation", "quarantine"):
            inform.append("security_officer")
        if tier == "tier0":
            inform.append("auditor")
        mode = "act" if level in ("autonomous", "notify") else "ask" if level in ("gated", "human") else "forbidden"
        rungs.append({"rung": r["rung"], "action": action, "autonomy": level, "mode": mode, "inform": sorted({i for i in inform if i}), "when": r["when"]})
    return {"capability": cap, "tier": tier, "target": target or "component",
            "drift": {"method": method, "how": m.get("how"), "detector": m.get("detector"), "interval_min": m.get("interval_min", {}).get(tier)},
            "trust_impact": dr["trust_impact"][tier], "risk_impact": {"risks": risks, "rule": dr["risk_impact"]},
            "coordinates": {"layer": d["contracts"][cap].get("stack_layer"), "site": "per site (estate register)",
                            "infra": "host, node or BMC (DCIM, Kubernetes)", "logical": f"entities of {target or cap} in the estate graph"},
            "ladder": rungs}


def check(d: dict) -> list[str]:
    errs = []
    for cap in d["contracts"]:
        c = card(d, cap)
        if not c["drift"]["method"] or not c["drift"]["how"] or not c["drift"]["interval_min"]:
            errs.append(f"{cap}: no drift method or interval")
        if c["tier"] == "tier0" and c["drift"]["interval_min"] > 60:
            errs.append(f"{cap}: a Tier 0 component is checked at least hourly")
        if not c["risk_impact"]["risks"]:
            errs.append(f"{cap}: drift has no risk to raise")
        for r in c["ladder"]:
            if r["mode"] == "forbidden" or not r["inform"]:
                errs.append(f"{cap}: rung {r['rung']} cannot act or inform anyone")
            if d["autonomy"]["actions"][r["action"]]["direction"] == "increase" and r["autonomy"] == "autonomous":
                errs.append(f"{cap}: an increase action is never autonomous")
        if c["tier"] == "tier0" and any(r["rung"] == "quarantine" and r["autonomy"] == "autonomous" for r in c["ladder"]):
            errs.append(f"{cap}: quarantining a Tier 0 component is never autonomous")
    errs += [f"method_by_profile names unknown method {m}" for m in d["dr"]["method_by_profile"].values() if m not in d["dr"]["drift_methods"]]
    errs += [f"ladder action {r['action']} is not an autonomy action" for r in d["dr"]["ladder"] if r["action"] not in d["autonomy"]["actions"]]
    for rung, m in d["dr"]["target_actions"].items():
        errs += [f"target action {a} is not an autonomy action" for a in m.values() if a not in d["autonomy"]["actions"]]
    return errs


if __name__ == "__main__":
    data = load()
    if len(sys.argv) > 1:
        print(json.dumps(card(data, sys.argv[1]), indent=1))
    problems = check(data)
    for p in problems:
        print("ERROR", p)
    sys.exit(1 if problems else 0)
