"""Escrowed recovery passphrase for a boot stick's encrypted home (platform/boot-stick.yaml, recovery).

Released only when both persons are in: the user proves identity with an eID signature over this very request
(identity matched to the pseudonym through the sealed identity register), and a security officer of that site's
OpenBao instance approves through an OpenBao control group. The passphrase goes to the stick encrypted to its session
key, is single-use, and a new one is escrowed afterwards.
"""

from __future__ import annotations

from datetime import datetime, timedelta

MAX_AGE = timedelta(minutes=15)


def release(req: dict, eid: dict, cg: dict, register: dict, officers: set[str], used: set[str], now: datetime) -> tuple[bool, list[str]]:
    """req: {pseudonym, stick, nonce, at}; eid: {chain_ok, revoked, signed: {pseudonym, stick, nonce}, nrn_hash};
    cg: OpenBao control group state {approvals: [names], required, created}; register: pseudonym -> nrn_hash."""
    why = []
    if not eid.get("chain_ok") or eid.get("revoked"):
        why.append("eID certificate invalid or revoked")
    if eid.get("signed") != {k: req[k] for k in ("pseudonym", "stick", "nonce")}:
        why.append("eID signature does not cover this request")
    if register.get(req["pseudonym"]) != eid.get("nrn_hash"):
        why.append("eID holder is not the person behind this pseudonym")
    approvers = set(cg.get("approvals", [])) & officers
    if len(approvers) < cg.get("required", 1):
        why.append("security officer approval missing (OpenBao control group)")
    if req["pseudonym"] in approvers:
        why.append("four eyes: the user cannot approve their own recovery")
    if not (timedelta(0) <= now - req["at"] <= MAX_AGE) or not (timedelta(0) <= now - cg["created"] <= MAX_AGE):
        why.append("request or approval expired")
    if req["nonce"] in used:
        why.append("request already used")
    if not why:
        used.add(req["nonce"])
    return not why, why
