"""Layers and seam classes (ADR-0076): one stack, standard seam classes, contracts and seams bound to them.

check() returns every violation; report() prints the stack with its contracts and the seam classes in use.
Usage: python tools/layers.py [--report]
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
NON_SWAPPABLE = {"own-api", "proprietary"}


def _y(rel: str, root: Path) -> dict:
    return yaml.safe_load((root / rel).read_text(encoding="utf-8"))


def load(root: Path = ROOT) -> dict:
    return {"layers": _y("platform/layers.yaml", root), "seams": _y("platform/seams.yaml", root)["seams"],
            "contracts": _y("catalog/contracts.yaml", root)["contracts"], "backlog": _y("catalog/contracts.yaml", root).get("backlog"), "spog": _y("platform/spog.yaml", root),
            "interrogation": _y("platform/interrogation.yaml", root)}


def sublayers(lay: dict) -> set[str]:
    return {f"{l['id']}/{s}" for l in lay["layers"] for s in l["sub"]}


def check(d: dict) -> list[str]:
    lay, errs = d["layers"], []
    ids = [l["id"] for l in lay["layers"]]
    classes = lay["seam_classes"]
    if ids != d["spog"]["layers"]:
        errs.append(f"stack layers {ids} differ from the SPOG layers {d['spog']['layers']}")
    groups = list(d["interrogation"]["groups"])
    if set(lay["interrogation_groups"]) != set(groups):
        errs.append(f"interrogation groups not mapped: {sorted(set(groups) ^ set(lay['interrogation_groups']))}")
    for g, ls in lay["interrogation_groups"].items():
        errs += [f"interrogation group {g}: unknown layer {x}" for x in ls if x not in ids]
    for c, v in classes.items():
        if v.get("kind") not in {"open-standard", "de-facto", "own", "proprietary"} or not v.get("specs") or not v.get("conformance"):
            errs.append(f"seam class {c}: needs kind, specs and conformance")
    # federation: every class says how it does HA, parent-child, peer and WAN-down; nothing is central-only
    modes = lay.get("federation", {}).get("modes", [])
    topo = lay.get("topology", {})
    if set(modes) != {"ha", "parent_child", "peer", "wan_down"}:
        errs.append("federation modes must be ha, parent_child, peer, wan_down")
    for c in classes:
        t = topo.get(c)
        if not t:
            errs.append(f"seam class {c}: no topology (HA, parent-child, peer, WAN-down)")
            continue
        errs += [f"seam class {c}: topology misses {m}" for m in modes if not t.get(m)]
        if "central" in str(t.get("wan_down", "")).lower() and "never central" not in str(t.get("wan_down", "")).lower():
            errs.append(f"seam class {c}: WAN-down behaviour depends on the centre")
    # seams
    locked = set()
    for s in d["seams"]:
        c = s.get("class")
        if c not in classes:
            errs.append(f"{s['id']}: seam class {c!r} unknown")
        elif c in NON_SWAPPABLE:
            locked.add(s["id"])
    exits = set(lay.get("proprietary_exits", {}))
    errs += [f"{x}: own-api or proprietary seam without an exit in layers.yaml" for x in sorted(locked - exits)]
    errs += [f"{x}: exit listed but the seam is not own-api or proprietary" for x in sorted(exits - locked)]
    # contracts
    subs = sublayers(lay)
    backlog = d.get("backlog") or {}
    errs += [f"backlog {n}: unknown sub-layer {v}" for n, v in backlog.items() if v not in subs]
    covered = {k.get("stack_layer") for k in d["contracts"].values()} | set(backlog.values()) | set(lay.get("no_contract", {}))
    errs += [f"sub-layer {x} has no contract, no backlog entry and no no_contract reason" for x in sorted(subs - covered)]
    alias = lay.get("seam_aliases", {})
    ends = defaultdict(set)   # seam end name -> classes it provides
    for s in d["seams"]:
        ends[s["to"]].add(s.get("class"))
    for name, k in d["contracts"].items():
        if k.get("stack_layer") not in subs:
            errs.append(f"contract {name}: stack_layer {k.get('stack_layer')!r} is not a known sub-layer")
        prov, cons = k.get("provides"), k.get("consumes")
        if prov is None or cons is None:
            errs.append(f"contract {name}: needs provides and consumes")
            continue
        for c in prov + cons:
            if c not in classes:
                errs.append(f"contract {name}: unknown seam class {c}")
            elif c in NON_SWAPPABLE:
                errs.append(f"contract {name}: a contract never standardises on {c}")
        if bool(k.get("actor")) != (not prov):
            errs.append(f"contract {name}: actor must be true exactly when it provides nothing")
        prim = [i for i, v in k["implementations"].items() if v.get("role") == "primary"]
        for i in prim:   # every swappable seam ending at the primary must be a class the contract provides
            for c in set().union(*[ends.get(e, set()) for e in alias.get(i, [i])]):
                if c in NON_SWAPPABLE or classes.get(c, {}).get("path") or c in prov:
                    continue
                errs.append(f"contract {name}: {i} receives a {c} seam that the contract does not provide")
    return errs


def report(d: dict) -> None:
    by_sub = defaultdict(list)
    for name, k in d["contracts"].items():
        by_sub[k["stack_layer"]].append(name)
    use = defaultdict(int)
    for s in d["seams"]:
        use[s["class"]] += 1
    for l in d["layers"]["layers"]:
        print(l["id"])
        for sub in l["sub"]:
            print(f"  {sub:28} {', '.join(by_sub.get(l['id'] + '/' + sub, [])) or '-'}")
    print("seam classes in use:", ", ".join(f"{c} {n}" for c, n in sorted(use.items(), key=lambda x: -x[1])))


if __name__ == "__main__":
    data = load()
    problems = check(data)
    if "--report" in sys.argv:
        report(data)
    for p in problems:
        print("ERROR", p)
    sys.exit(1 if problems else 0)
