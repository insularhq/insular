"""Capability contracts (catalog/contracts.yaml): coverage, feature matrices, readiness, computed lock-in, and the
attack-surface priority of each component (exposure from platform/seams.yaml times advisory posture from
catalog/security-posture.yaml). Run: python tools/contracts.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RANK = {"none": 0, "partial": 1, "candidate": 2, "ready": 3}


def load(root: Path = ROOT) -> dict:
    rd = lambda p: yaml.safe_load((root / p).read_text(encoding="utf-8"))
    contracts = rd("catalog/contracts.yaml")
    norm = {True: "yes", False: "no"}   # YAML 1.1 reads bare yes and no as booleans
    for k in contracts["contracts"].values():
        for impl in k["implementations"].values():
            impl["features"] = {f: norm.get(v, v) for f, v in impl["features"].items()}
    return {"contracts": contracts, "interfaces": rd("catalog/interfaces.yaml")["capabilities"],
            "posture": rd("catalog/security-posture.yaml"), "seams": rd("platform/seams.yaml")["seams"],
            "compensations": rd("catalog/compensations.yaml")["components"]}


def readiness(features: dict, required: list[str], evidence: str | None = None) -> str:
    vals = [features.get(f, "no") for f in required]
    if all(v == "yes" for v in vals):
        return "ready" if evidence else "candidate"
    return "partial" if any(v in ("yes", "partial") for v in vals) else "none"


def combined(contract: dict, role: str) -> dict[str, str]:
    """Readiness per set: implementations of one role that share a 'set' (primaries always form one set) fulfil the
    contract together; per feature the best value counts."""
    sets: dict[str, dict] = {}
    for name, i in contract["implementations"].items():
        if i["role"] != role:
            continue
        key = "primary" if role == "primary" else i.get("set", name)
        cur = sets.setdefault(key, {"features": {}, "evidence": True})
        for f, v in i["features"].items():
            best = {"yes": 2, "partial": 1, "no": 0}
            if best[v] >= best.get(cur["features"].get(f, "no"), 0):
                cur["features"][f] = v
        cur["evidence"] = cur["evidence"] and bool(i.get("evidence"))
    return {k: readiness(v["features"], contract["required"], "lab" if v["evidence"] else None) for k, v in sets.items()}


def lock_in(contract: dict) -> str:
    best = max((RANK[r] for r in combined(contract, "alternate").values()), default=0)
    return {3: "none", 2: "low", 1: "medium", 0: "high"}[best]


def check(d: dict) -> list[str]:
    errs = []
    c, iface = d["contracts"], d["interfaces"]
    caps, backlog = set(c["contracts"]), set(c.get("backlog", []))
    if caps & backlog:
        errs.append(f"in both contracts and backlog: {sorted(caps & backlog)}")
    if (caps | backlog) != set(iface):
        errs.append(f"capabilities without contract or backlog entry: {sorted(set(iface) - caps - backlog)}; unknown: {sorted((caps | backlog) - set(iface))}")
    order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    for cap, k in c["contracts"].items():
        req = k["required"]
        prim = [n for n, i in k["implementations"].items() if i["role"] == "primary"]
        if not prim or not set(prim) & set(iface.get(cap, {}).get("implementations", [])):
            errs.append(f"{cap}: no primary that implements the capability")
        for name, impl in k["implementations"].items():
            missing = [f for f in req if f not in impl["features"]]
            if missing:
                errs.append(f"{cap}/{name}: features not scored: {missing}")
            bad = [f for f, v in impl["features"].items() if v not in ("yes", "partial", "no")]
            if bad:
                errs.append(f"{cap}/{name}: invalid feature values {bad}")
            computed = readiness(impl["features"], req, impl.get("evidence"))
            if RANK[impl["readiness"]] > RANK[computed]:
                errs.append(f"{cap}/{name}: claims {impl['readiness']} but its features support {computed}")
        claimed = iface.get(cap, {}).get("lock_in")
        if claimed in order and order[claimed] < order[lock_in(k)]:
            errs.append(f"{cap}: interfaces claim lock-in {claimed}, the contract shows {lock_in(k)}")
    return errs


def exposure(component: str, seams: list[dict]) -> int:
    level = 1
    for s in seams:
        if component in (s["to"], s.get("pep")) or component in str(s.get("pep")):
            zones = s.get("zones") or []
            if zones and zones[0] in ("internet", "vpn-overlay", "endpoint"):
                level = max(level, 3)
            elif "gateway-cell" in zones:
                level = max(level, 2)
    return level


def priorities(d: dict) -> list[dict]:
    w = d["posture"]["weights"]
    out = []
    for name, p in d["posture"]["components"].items():
        score = sum(w[k] * p[k] for k in w)
        e = exposure(name, d["seams"])
        out.append({"component": name, "score": score, "exposure": e, "priority": score * e, "coverage": p["coverage"]})
    return sorted(out, key=lambda x: -x["priority"])


def alternates_worse(d: dict) -> list[str]:
    w, comps = d["posture"]["weights"], d["posture"]["components"]
    sc = lambda n: sum(w[k] * comps[n][k] for k in w) if n in comps else None
    out = []
    for cap, k in d["contracts"]["contracts"].items():
        prims = [n for n, i in k["implementations"].items() if i["role"] == "primary" and sc(n) is not None]
        for n, i in k["implementations"].items():
            if i["role"] == "alternate" and sc(n) is not None and prims and sc(n) > 2 * max(sc(p) for p in prims) and sc(n) >= 20:
                out.append(f"{cap}: alternate {n} ({sc(n)}) has a much worse advisory record than {', '.join(prims)} ({max(sc(p) for p in prims)})")
    return out


def seam_contracts(d: dict) -> dict:
    """Bind every seam to the contract of the component it reaches (or its enforcement point)."""
    owner = {}
    for cap, spec in d["interfaces"].items():
        for impl in spec["implementations"]:
            owner.setdefault(impl, cap)
    bound, backlog, unknown = {}, {}, []
    contracts, bl = d["contracts"]["contracts"], set(d["contracts"].get("backlog", []))
    for s in d["seams"]:
        cap = owner.get(s["to"]) or owner.get(str(s.get("pep")))
        if cap in contracts:
            bound[s["id"]] = cap
        elif cap in bl:
            backlog[s["id"]] = cap
        else:
            unknown.append(s["id"])
    return {"bound": bound, "backlog": backlog, "external": unknown}


def needs_compensation(d: dict) -> list[str]:
    thr = d["posture"]["compensations_required_when"]["priority_at_least"]
    return sorted(p["component"] for p in priorities(d) if p["priority"] >= thr and p["exposure"] >= 2)


def main() -> int:
    d = load()
    errs = check(d)
    print("contracts:", len(d["contracts"]["contracts"]), "backlog:", len(d["contracts"].get("backlog", [])))
    print("lock-in:", {cap: lock_in(k) for cap, k in d["contracts"]["contracts"].items()})
    print("primaries together:", {cap: combined(k, "primary")["primary"] for cap, k in d["contracts"]["contracts"].items()})
    print("top attack-surface priorities:")
    for p in priorities(d)[:12]:
        print(f"  {p['component']:24} priority {p['priority']:4} (score {p['score']}, exposure {p['exposure']}, {p['coverage']})")
    sc = seam_contracts(d)
    print(f"seams bound to a contract: {len(sc['bound'])}, to a backlog capability: {len(sc['backlog'])}, external parties: {len(sc['external'])}")
    comp = d["compensations"]
    missing = [c for c in needs_compensation(d) if c not in comp]
    for c in missing:
        errs.append(f"{c}: exposed with a heavy advisory record and no recorded compensations")
    for a in alternates_worse(d):
        print("  WARN", a)
    for e in errs:
        print("ERROR", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
