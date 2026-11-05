"""The one execution path for every automated (or manual) action: identity, policy decision, autonomy level,
approval when required, execution, and an attested, hash-chained run record with a trace id.

Engines (Argo, Ansible, Flux, OpenTofu) call this path; analyst agents may only submit proposals.
"""

from __future__ import annotations

import hashlib
import json
import uuid

from autonomy import decide as autonomy_level
from signing import verify as verify_signature

NEEDS_APPROVAL = {"human", "gated"}


def request_hash(req: dict) -> str:
    return hashlib.sha256(json.dumps(req, sort_keys=True, default=str).encode()).hexdigest()


def approval_payload(req_hash: str, role: str, nonce: str, expires: str) -> dict:
    return {"request": req_hash, "role": role, "nonce": nonce, "expires": expires}


def approval_ok(a: dict, req_hash: str, requester: str, approvers: dict, consumed: set, now: str) -> bool:
    """A signed, unexpired, unused approval of this exact request by a registered approver in an approving role,
    not the requester."""
    reg = approvers["approvers"].get(a.get("by"))
    return bool(reg and a.get("by") != requester and a.get("role") in reg["roles"]
                and a.get("role") in approvers["approver_roles"]
                and a.get("nonce") and a["nonce"] not in consumed and str(a.get("expires", "")) >= now
                and verify_signature(reg["public_key"], a.get("signature", ""),
                                     approval_payload(req_hash, a["role"], a["nonce"], str(a["expires"]))))


def run(req: dict, autonomy: dict, policy_ok: bool, approvals: list[dict], chain: list[dict], execute,
        approvers: dict | None = None, notify=None) -> dict:
    """req: {subject: {type, id}, action, tier, contexts, target, now}. Returns the appended record.
    notify(rec) tells a person at once; the notify level refuses to act without it, and a level that needs approval
    refuses without `now`, so an approval's expiry is always checked."""
    rec = {"trace_id": req.get("trace_id") or uuid.uuid4().hex, "subject": req["subject"], "action": req["action"],
           "target": req.get("target"), "tier": req["tier"], "request_hash": request_hash(req)}
    rec.update({k: req[k] for k in ("sop", "step") if k in req})   # a procedure's run: which procedure, which step (ADR-0159)
    level = autonomy_level(autonomy, req["tier"], req["action"], req.get("contexts", []))
    rec["level"] = level
    if req["subject"]["type"] == "agent" and req.get("mode") != "propose":
        rec["result"] = "refused: agents only propose"
    elif not policy_ok:
        rec["result"] = "refused: policy decision deny"
    elif level == "forbidden":
        rec["result"] = "refused: forbidden in this tier and context"
    elif req.get("mode") == "propose":
        rec["result"] = "proposed: enters review"
    elif level == "notify" and notify is None:
        rec["result"] = "refused: the notify level needs a notifier"
    elif level in NEEDS_APPROVAL and not req.get("now"):
        rec["result"] = "refused: no time to check approvals against"
    else:
        approvers = approvers or {"approvers": {}, "approver_roles": []}
        consumed = {n for r in chain for n in r.get("approval_nonces", [])}
        now = req.get("now", "")
        valid, keys = [], set()
        for a in approvals:
            if approval_ok(a, rec["request_hash"], req["subject"]["id"], approvers, consumed, now):
                key = approvers["approvers"][a["by"]]["public_key"]
                if key not in keys:
                    valid.append(a)
                    keys.add(key)
        need = autonomy.get("min_approvers", {}).get(req["action"], 1)
        if level in NEEDS_APPROVAL and len(valid) < need:
            rec["result"] = f"waiting: {need} approval(s) by distinct persons required, {len(valid)} valid"
        else:
            rec["approved_by"] = [a["by"] for a in valid]
            rec["approval_nonces"] = [a["nonce"] for a in valid]
            rec["result"] = f"executed: {execute(req)}"
            if level == "notify":
                rec["notified"] = str(notify(rec))
    rec["prev"] = chain[-1]["hash"] if chain else "genesis"
    rec["hash"] = hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()
    chain.append(rec)
    return rec


def verify(chain: list[dict]) -> bool:
    prev = "genesis"
    for r in chain:
        body = {k: v for k, v in r.items() if k != "hash"}
        if r["prev"] != prev or hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest() != r["hash"]:
            return False
        prev = r["hash"]
    return True
