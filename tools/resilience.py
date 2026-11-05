"""Resilience and seams: HA pattern, failure mode, restore path and network needs per component and size, and every
seam with its standard, enforcement point and outside watcher. Models: platform/resilience.yaml, platform/seams.yaml.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WATCHERS = {"hubble", "evaluator", "off-instance-evaluator", "ztop", "audit", "pgaudit"}


def load(root: Path = ROOT) -> tuple[dict, dict, dict]:
    rd = lambda p: yaml.safe_load((root / p).read_text(encoding="utf-8"))
    return rd("platform/resilience.yaml"), rd("platform/seams.yaml"), rd("platform/sizes.yaml")


def size_components(sizes: dict, size: str) -> set[str]:
    order = ["S", "M", "L"]
    names = {c["component"] for c in sizes["core"]}
    for m in sizes["modules"].values():
        if m["size"] in order and order.index(m["size"]) <= order.index(size):
            names |= {c["component"] for c in m.get("components", [])}
    return names


def check(res: dict, seams: dict, sizes: dict) -> list[str]:
    errs = []
    comps, pats = res["components"], res["ha_patterns"]
    bom_known = set(comps) | {"PostgreSQL"}
    for size in ("S", "M", "L"):
        for name in sorted(size_components(sizes, size)):
            p = comps.get(name)
            if p is None:
                errs.append(f"{size}: {name} has no resilience profile")
            elif size not in p["ha"]:
                errs.append(f"{size}: {name} has no HA pattern for this size")
    for name, p in comps.items():
        for size, pat in p["ha"].items():
            if pat not in pats:
                errs.append(f"{name}: unknown HA pattern {pat}")
        if p["mode"] not in res["failure_modes"]:
            errs.append(f"{name}: unknown failure mode {p['mode']}")
        if p["restore"] not in res["restore_kinds"]:
            errs.append(f"{name}: unknown restore kind {p['restore']}")
        if p["state"] in ("data", "quorum-data") and p["restore"] != "reprovision+data" and name != "K3s":
            errs.append(f"{name}: holds data but is not restored with its data")
        if p["state"] in ("data", "quorum-data") and not p.get("data"):
            errs.append(f"{name}: holds data but names no backup")
        if p["state"] == "quorum-data" and p.get("snapshot", "forbidden") != "forbidden":
            errs.append(f"{name}: a consensus member must never be restored from a VM or volume snapshot")
        if "stretch" in str(p.get("net", "")).lower() and "never stretched" not in str(p.get("net", "")).lower():
            errs.append(f"{name}: layer-2 stretching is not allowed")
        for b in p.get("backing", []):
            if b not in bom_known and b not in res.get("undeclared_backing", {}):
                errs.append(f"{name}: backing service {b} is neither a component nor a listed undeclared backing")
    ids = set()
    for s in seams["seams"]:
        if s["id"] in ids:
            errs.append(f"{s['id']}: duplicate seam id")
        ids.add(s["id"])
        if not s.get("watch") or not set(s["watch"]) <= WATCHERS:
            errs.append(f"{s['id']}: watchers must be from {sorted(WATCHERS)}")
        if s["from"] in s["watch"] or s["to"] in s["watch"]:
            errs.append(f"{s['id']}: a seam is never watched only by one of its own parties")
        if s["on_failure"] not in res["failure_modes"]:
            errs.append(f"{s['id']}: unknown failure mode")
        if not s.get("pep"):
            errs.append(f"{s['id']}: no enforcement point")
    return errs


def blast(name: str, res: dict, seams: dict, size: str) -> dict:
    """What fails when a component fails, in a size: its own failure plus every seam it is a party or enforcer of."""
    order = ["S", "M", "L"]
    p = res["components"][name]
    hit = [s for s in seams["seams"] if order.index(s["size"]) <= order.index(size)
           and name in (s["from"], s["to"], s["pep"])]
    dependents = sorted(n for n, q in res["components"].items() if name in q.get("backing", []))
    return {"component": name, "pattern": p["ha"].get(size), "mode": p["mode"], "fails": p["fails"],
            "seams": [f"{s['id']} {s['from']} -> {s['to']} ({s['on_failure']})" for s in hit], "backing_for": dependents}


def spofs(res: dict, sizes: dict, size: str) -> list[str]:
    """Components that are a single instance in this size and hold data: restored, not failed over."""
    return sorted(n for n in size_components(sizes, size) if n in res["components"]
                  and res["components"][n]["ha"].get(size) == "single" and res["components"][n]["state"] != "none")


def main() -> int:
    res, seams, sizes = load()
    errs = check(res, seams, sizes)
    for size in ("S", "M", "L"):
        print(size, "single instances with state:", ", ".join(spofs(res, sizes, size)))
    for e in errs:
        print("ERROR", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
