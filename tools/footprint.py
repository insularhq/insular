"""KeyClerk's footprint budget.

The budget states, per full node, the memory request and limit of each KeyClerk container, KeyClerk's share, the
neighbours on the same node (Keycloak, its database, the OS) and the disk per volume. check() keeps the budget
consistent: requests within limits, the share equal to the sum of KeyClerk's rows, every limit on a node within the
node minus its headroom, every volume within the node's disk. verify() judges a ring measurement against it, so the
claim "four small containers" becomes a test that fails when it stops being true.

A measurement file (YAML or JSON), written during the ring acceptance run:
  containers: {engine: 301, verifier: 40, ...}   peak memory in MiB (cgroup memory.peak); a counted row (opa) is per copy
  disk: {keyclerk-database: 0.4, journal: 0.01, ...}   GB used per volume

Usage:
  python tools/footprint.py                    check the budget in platform/access-lifecycle.yaml
  python tools/footprint.py --measured FILE    judge a ring measurement against it
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REGISTER = ROOT / "platform" / "access-lifecycle.yaml"


def budget(doc: dict | None = None) -> dict:
    doc = doc or yaml.safe_load(REGISTER.read_text(encoding="utf-8"))
    return doc["keyclerk_lean"]["budget"]


def _sum(rows: list[dict], key: str) -> int:
    return sum(r[key] * r.get("count", 1) for r in rows)


def check(b: dict) -> list[str]:
    errs = []
    for r in b["keyclerk"] + b["neighbours"]:
        if r["request"] > r["limit"]:
            errs.append(f"{r['name']}: request {r['request']} above limit {r['limit']}")
    for k in ("request", "limit"):
        if _sum(b["keyclerk"], k) != b["share"][k]:
            errs.append(f"share {k} {b['share'][k]} is not the sum of KeyClerk's rows ({_sum(b['keyclerk'], k)})")
    room = b["node"]["ram"] - b["node"]["headroom_ram"]
    limits = _sum(b["keyclerk"], "limit") + _sum(b["neighbours"], "limit")
    if limits > room:
        errs.append(f"node: limits add up to {limits} MiB, above {room} (node RAM minus headroom)")
    disk = sum(d["gb"] for d in b["disk"])
    if disk > b["node"]["disk"]:
        errs.append(f"node: volumes add up to {disk} GB, above the node's {b['node']['disk']}")
    names = [r["name"] for r in b["keyclerk"] + b["neighbours"]] + [d["name"] for d in b["disk"]]
    if len(names) != len(set(names)):
        errs.append("a row name appears twice")
    return errs


def verify(b: dict, measured: dict) -> list[str]:
    """A container over its limit, KeyClerk's share over its share, a volume over its row, or a KeyClerk container
    that was not measured: each fails. Neighbours are reported only when measured."""
    errs = []
    got = measured.get("containers", {})
    share = 0
    for r in b["keyclerk"]:
        if r["name"] not in got:
            errs.append(f"{r['name']}: not measured")
            continue
        share += got[r["name"]] * r.get("count", 1)
    for r in b["keyclerk"] + b["neighbours"]:
        if r["name"] in got and got[r["name"]] > r["limit"]:
            errs.append(f"{r['name']}: peak {got[r['name']]} MiB above its limit {r['limit']}")
    if share > b["share"]["limit"]:
        errs.append(f"KeyClerk's share: {share} MiB above {b['share']['limit']}")
    rows = {d["name"]: d["gb"] for d in b["disk"]}
    for name, gb in measured.get("disk", {}).items():
        if name not in rows:
            errs.append(f"{name}: a volume the budget does not name")
        elif gb > rows[name]:
            errs.append(f"{name}: {gb} GB above its row {rows[name]}")
    return errs


def yearly_gb(b: dict, events_per_day: int, days: int = 365) -> float:
    """Disk a stream of events takes, kept `days` days, with the budget's event size and index factor."""
    g = b["growth"]
    return events_per_day * days * g["event_bytes"] * g["index_factor"] / 1e9


def main(argv: list[str]) -> int:
    b = budget()
    errs = check(b)
    if argv[:1] == ["--measured"]:
        errs += verify(b, yaml.safe_load(Path(argv[1]).read_text(encoding="utf-8")))
    for e in errs:
        print(f"footprint: {e}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
