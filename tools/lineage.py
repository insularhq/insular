"""Lineage of the trust, risk and policy model (ADR-0150): every part names its public sources, what it takes from
each, why, what is our own, and when to look again.

check() returns every violation. Usage: python tools/lineage.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
FIELDS = ("id", "element", "where", "adr", "takes", "why", "ours", "amend_when")
# the trust model's decisions that must each be explained by at least one element
COVERED_ADRS = ("ADR-0064", "ADR-0078", "ADR-0089", "ADR-0093", "ADR-0145", "ADR-0146", "ADR-0147", "ADR-0148", "ADR-0149")
# parts of policies/federation.yaml partner_trust that must each be explained (fictional partners and risk ids excluded)
PARTNER_PARTS = ("contract", "classes", "acceptance", "ladder", "status_carrier", "directions", "common_mode")


def _y(rel: str, root: Path):
    return yaml.safe_load((root / rel).read_text(encoding="utf-8"))


def load(root: Path = ROOT) -> dict:
    return {"lineage": _y("frameworks/lineage.yaml", root), "register": _y("frameworks/register.yaml", root)["frameworks"],
            "federation": _y("policies/federation.yaml", root), "root": root}


def check(d: dict) -> list[str]:
    errs = []
    reg, root = d["register"], d["root"]
    seen = set()
    for e in d["lineage"]["elements"]:
        eid = e.get("id", "?")
        missing = [f for f in FIELDS if f not in e or e[f] in (None, "")]
        if missing:
            errs.append(f"lineage {eid}: missing {', '.join(missing)}")
            continue
        if eid in seen:
            errs.append(f"lineage {eid}: duplicate id")
        seen.add(eid)
        path = str(e["where"]).split("#")[0]
        if not (root / path).exists():
            errs.append(f"lineage {eid}: where {path} does not exist")
        if not list((root / "intent" / "decisions").glob(f"{e['adr']}-*.md")):
            errs.append(f"lineage {eid}: decision record {e['adr']} not found")
        if not e["takes"] and "own" not in str(e["ours"]):
            errs.append(f"lineage {eid}: no public source; say in ours that it is our own")
        for t in e["takes"]:
            src = reg.get(t.get("from"))
            if src is None:
                errs.append(f"lineage {eid}: source {t.get('from')} is not in frameworks/register.yaml")
            elif not str(src.get("url", "")).startswith("https://"):
                errs.append(f"lineage {eid}: source {t['from']} has no public https URL in the register")
            if not t.get("what"):
                errs.append(f"lineage {eid}: says nothing about what it takes from {t.get('from')}")
    adrs = {e.get("adr") for e in d["lineage"]["elements"]}
    errs += [f"lineage: no element explains {a}" for a in COVERED_ADRS if a not in adrs]
    wheres = " ".join(str(e.get("where")) for e in d["lineage"]["elements"])
    errs += [f"lineage: partner_trust.{p} is not explained" for p in PARTNER_PARTS
             if f"partner_trust.{p}" not in wheres or p not in d["federation"]["partner_trust"]]
    return errs


if __name__ == "__main__":
    problems = check(load())
    for p in problems:
        print("ERROR", p)
    sys.exit(1 if problems else 0)
