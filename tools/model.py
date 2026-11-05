"""Shared helpers: load the CALM architecture and the pack, and check the pack's tiers against its floors."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load_calm(path: Path | None = None) -> dict:
    return json.loads((path or ROOT / "calm" / "vdhome-platform.architecture.json").read_text(encoding="utf-8"))


def load_pack(name: str = "vdhome-platform") -> dict:
    return yaml.safe_load((ROOT / "packs" / name / "pack.yaml").read_text(encoding="utf-8"))


def nodes(calm: dict) -> dict[str, dict]:
    return {n["unique-id"]: n for n in calm["nodes"]}


def interface(node: dict, iface_id: str) -> dict:
    for i in node.get("interfaces", []):
        if i["unique-id"] == iface_id:
            return i
    raise KeyError(f"{node['unique-id']} has no interface {iface_id}")


def meta(node: dict, key: str, default=None):
    for m in node.get("metadata", []) or []:
        if key in m:
            return m[key]
    return default


def placement(calm: dict) -> dict[str, str]:
    """node -> the container it is deployed in (one level)."""
    out = {}
    for r in calm["relationships"]:
        d = r["relationship-type"].get("deployed-in")
        if d:
            for n in d["nodes"]:
                out[n] = d["container"]
    return out


def site_of(calm: dict, node_id: str) -> str | None:
    """Walk deployed-in upwards until an 'ecosystem' node (a site) is reached."""
    ns, place = nodes(calm), placement(calm)
    cur = node_id
    while cur in place:
        cur = place[cur]
        if ns[cur]["node-type"] == "ecosystem":
            return cur
    return None


def host_of(calm: dict, node_id: str) -> str | None:
    """The system node a service runs on (its direct container), or the node itself if it is a system."""
    ns = nodes(calm)
    if ns[node_id]["node-type"] in ("system",):
        return node_id
    return placement(calm).get(node_id)


@dataclass(frozen=True)
class Flow:
    rel_id: str
    src: str
    dst: str
    port: int
    proto: str


def flows(calm: dict) -> list[Flow]:
    """Every allowed flow as (source node, destination node, port, transport protocol)."""
    ns = nodes(calm)
    out = []
    for r in calm["relationships"]:
        c = r["relationship-type"].get("connects")
        if not c:
            continue
        dst = ns[c["destination"]["node"]]
        for iid in c["destination"].get("interfaces", []):
            i = interface(dst, iid)
            out.append(Flow(r["unique-id"], c["source"]["node"], dst["unique-id"], int(i["port"]), i.get("protocol", "TCP").lower()))
    return out


def check_floors(pack: dict) -> list[str]:
    """A tier weaker than a floor is an error: risk appetite tunes controls, it never removes the baseline."""
    errors = []
    floors, strength = pack["floors"], pack.get("strength", {})
    for tier, params in pack["tiers"].items():
        for k, floor in floors.items():
            v = params.get(k)
            if v is None:
                errors.append(f"{tier}: missing {k}")
                continue
            if k in strength:
                order = strength[k]
                if order.index(v) > order.index(floor):
                    errors.append(f"{tier}: {k}={v} is weaker than floor {floor}")
            elif k in ("release_approvers",):
                if v < floor:
                    errors.append(f"{tier}: {k}={v} below floor {floor}")
            elif v > floor:  # durations: shorter is stricter
                errors.append(f"{tier}: {k}={v} exceeds floor {floor}")
    return errors


def check_offline_grace(pack: dict) -> list[str]:
    """No tier may let an island keep deciding longer than the floor for a label."""
    errs = []
    floor = pack.get("offline_grace_hours_floor", {})
    for tier, labels in pack.get("offline_grace_hours", {}).items():
        for label, hours in labels.items():
            if hours > floor.get(label, 0):
                errs.append(f"{tier}: offline grace {label}={hours}h exceeds floor {floor.get(label, 0)}h")
    return errs
