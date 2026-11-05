"""Release gateway decision: may this object leave its enclave at a lower label?

Inputs: the request, the inspection results of each pipeline stage, signed approvals, the approver registry and the
requester's recent releases. Output: a decision with reasons and, when released, a signed-ready manifest that covers
only the sanitised rendition. Pure function; the pipeline tools produce the inspection results.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from signing import verify

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_STAGES = ["identify", "malware", "disarm", "metadata", "content"]


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "release-gateway.yaml").read_text(encoding="utf-8"))


def digest(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def approval_payload(req: dict, rendition_sha256: str | None) -> dict:
    """What a release officer signs: the whole release, so the manifest cannot misstate the original."""
    return {"request": req["id"], "original": req["original_sha256"], "rendition": rendition_sha256,
            "from_label": req["from_label"], "to_label": req["to_label"], "enclave": req["enclave"]}


def decide(req: dict, inspections: dict, approvals: list[dict], approvers: dict, history: list[dict], gw: dict) -> dict:
    reasons = []
    order = gw["labels_order"]
    steps = order.index(req["from_label"]) - order.index(req["to_label"])
    if steps <= 0:
        reasons.append("not a release: the target label is not lower")
    for st in REQUIRED_STAGES:
        r = inspections.get(st)
        if r is None:
            reasons.append(f"stage {st} did not run")
        elif not r.get("passed"):
            reasons.append(f"stage {st} failed: {r.get('finding', 'no detail')}")
    if inspections.get("identify", {}).get("type") not in gw["allowed_types"]:
        reasons.append(f"type {inspections.get('identify', {}).get('type')} is not allowed to leave")
    if not inspections.get("disarm", {}).get("rendition_sha256"):
        reasons.append("no sanitised rendition: the original never leaves")
    day = [h for h in history if h["requester"] == req["requester"] and h["day"] == req["day"]]
    if len(day) + 1 > gw["quota"]["max_releases_per_day"] or sum(h["bytes"] for h in day) + req["bytes"] > gw["quota"]["max_bytes_per_day"]:
        reasons.append("quota exceeded: aggregation review required")
    need = gw["approvals"]["one_step"] if steps == 1 else gw["approvals"]["two_or_more"]
    payload = approval_payload(req, inspections.get("disarm", {}).get("rendition_sha256"))
    role = gw["approvals"]["role"]
    requester_key = approvers["approvers"].get(req["requester"], {}).get("public_key")
    valid, keys = set(), set()
    for a in approvals:
        reg = approvers["approvers"].get(a.get("by"))
        if not reg or a.get("by") == req["requester"] or reg["public_key"] == requester_key:
            continue
        if role not in reg["roles"] or role not in approvers.get("approver_roles", []):
            continue
        if str(reg.get("certified_until", "")) < req["day"]:
            reasons.append(f"{a['by']} is not a currently certified release officer")
            continue
        if reg["public_key"] in keys:
            reasons.append(f"{a['by']} uses a key that already approved: one person, counted once")
            continue
        if verify(reg["public_key"], a.get("signature", ""), payload):
            valid.add(a["by"])
            keys.add(reg["public_key"])
    if len(valid) < need:
        reasons.append(f"needs {need} release officer approval(s) other than the requester, has {len(valid)}")
    if reasons:
        return {"released": False, "reasons": reasons}
    manifest = {"request": req["id"], "original_sha256": req["original_sha256"], "rendition_sha256": payload["rendition"],
                "from_label": req["from_label"], "to_label": req["to_label"], "approvers": sorted(valid),
                "stages_passed": REQUIRED_STAGES, "original_stays_in": req["enclave"]}
    return {"released": True, "reasons": [], "manifest": manifest}
