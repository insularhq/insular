"""Deviations from the golden path as code: justified, scoped, time-boxed, approved by the right authority and
locked to their content by a hash. Valid deviations extend a resolved intent; everything else observed is drift.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import yaml

from model import Flow
from signing import verify

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ("id", "app", "type", "requested_by", "justification", "risk", "compensating_controls", "scope", "expires")


def content_hash(dev: dict) -> str:
    body = {k: v for k, v in dev.items() if k != "approvals"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def load_approvers(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "governance" / "approvers.yaml").read_text(encoding="utf-8"))


def approval_valid(a: dict, h: str, approvers: dict, today: date) -> str | None:
    """None when the approval is a valid signature by a registered approver in that role; otherwise the reason."""
    reg = approvers["approvers"].get(a.get("by"))
    if reg is None:
        return f"approver {a.get('by')} is not registered"
    if a.get("role") not in reg["roles"] or a.get("role") not in approvers["approver_roles"]:
        return f"{a.get('by')} may not approve as {a.get('role')}"
    if a.get("hash") != h:
        return f"approval by {a.get('by')} does not match the current content (edited after approval)"
    if date.fromisoformat(str(a.get("date"))) > today:
        return f"approval by {a.get('by')} is dated in the future"
    if not verify(reg["public_key"], a.get("signature", ""), {"hash": h, "role": a["role"], "date": str(a["date"])}):
        return f"approval by {a.get('by')} has no valid signature"
    return None


def validate(dev: dict, authority: dict, today: date, approvers: dict | None = None) -> list[str]:
    errs = [f"{dev.get('id')}: missing {k}" for k in REQUIRED if not dev.get(k)]
    t = authority["deviation_types"].get(dev.get("type"))
    if t is None:
        return errs + [f"{dev.get('id')}: unknown deviation type {dev.get('type')!r}"]
    if not t["approvers"]:
        return errs + [f"{dev.get('id')}: {dev['type']} is never allowed"]
    exp = dev.get("expires")
    exp = date.fromisoformat(str(exp)) if exp else None
    approvals = dev.get("approvals", [])
    if exp and approvals:
        first = min(date.fromisoformat(str(a["date"])) for a in approvals)
        if (exp - first).days > t["max_days"]:
            errs.append(f"{dev['id']}: lasts longer than {t['max_days']} days")
    if exp and exp < today:
        errs.append(f"{dev['id']}: expired on {exp}: revoke or renew")
    h = content_hash(dev)
    approvers = approvers or load_approvers()
    roles, keys = set(), set()
    for a in approvals:
        reg = approvers["approvers"].get(a.get("by"), {})
        if reg.get("public_key") in keys:
            errs.append(f"{dev['id']}: {a.get('by')} uses a key that already approved: one person, counted once")
            continue
        why = approval_valid(a, h, approvers, today)
        if why:
            errs.append(f"{dev['id']}: {why}")
        elif a.get("by") == dev.get("requested_by"):
            errs.append(f"{dev['id']}: requester approved their own deviation")
        else:
            roles.add(a.get("role"))
            keys.add(reg.get("public_key"))
    missing = set(t["approvers"]) - roles
    if missing:
        errs.append(f"{dev['id']}: missing valid approval by {sorted(missing)}")
    return errs


def load_deviations(root: Path = ROOT) -> dict[str, dict]:
    return {d["id"]: d for d in (yaml.safe_load(p.read_text(encoding="utf-8"))
                                 for p in sorted((root / "intent" / "deviations").glob("DEV-*.yaml")))}


def apply(resolved: dict, devs: list[dict], authority: dict, today: date, approvers: dict | None = None) -> dict:
    """Extend a resolved intent with its valid deviations; invalid ones are reported and contribute nothing."""
    out = {**resolved, "flows": list(resolved["flows"]), "errors": list(resolved["errors"]), "exceptions": []}
    for d in devs:
        errs = validate(d, authority, today, approvers)
        if d.get("app") != resolved["app"]:
            errs.append(f"{d.get('id')}: belongs to {d.get('app')!r}, not {resolved['app']!r}")
        if errs:
            out["errors"] += errs
            continue
        out["exceptions"].append(d["id"])
        for f in d["scope"].get("flows", []):
            out["flows"].append(Flow(f"{d['id']}", f["from"], f["to"], int(f["port"]), f["proto"]))
    return out


def drift(observed: list[Flow], allowed: list[Flow]) -> list[Flow]:
    """Observed flows that neither the golden path nor a valid deviation explains."""
    ok = {(f.src, f.dst, f.port, f.proto) for f in allowed}
    return [f for f in observed if (f.src, f.dst, f.port, f.proto) not in ok]
