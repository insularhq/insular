"""Four-eyes release of a boot stick's encrypted home (platform/boot-stick.yaml, release_modes).

The home key is split: one share is unlocked by the user's FIDO2 key, the other is held by the key access service and
released only against a fresh, single-use approval by a security officer who is not the user, bound to this user,
this stick and this request. In-person mode combines the user's and the officer's FIDO2 shares offline.
"""

from __future__ import annotations

from datetime import datetime, timedelta

MAX_APPROVAL_AGE = timedelta(minutes=10)


def required_mode(cfg: dict, label: str, triggers: set[str]) -> str:
    """The release mode for this sign-in: the label's default, raised to four-eyes by any risk trigger."""
    mode = cfg["release_modes"]["by_label"][label]
    if cfg["release_modes"].get("risk_triggers_enabled") and triggers & set(cfg["release_modes"]["risk_triggers"]):
        mode = "four-eyes-online" if mode == "self" else mode
    return mode


def release(request: dict, approval: dict | None, now: datetime, used_nonces: set[str], officers: set[str]) -> tuple[bool, list[str]]:
    """Whether the key access service releases the second share. All reasons are returned, deny overrides."""
    why = []
    if approval is None:
        return False, ["no approval: a security officer must release this sign-in"]
    if approval["approver"] not in officers:
        why.append("approver is not a security officer")
    if approval["approver"] == request["user"]:
        why.append("four eyes: the approver cannot be the user")
    for k in ("user", "stick", "request_id"):
        if approval.get(k) != request.get(k):
            why.append(f"approval is bound to another {k}")
    if not (timedelta(0) <= now - approval["at"] <= MAX_APPROVAL_AGE):
        why.append("approval is not fresh")
    if approval["nonce"] in used_nonces:
        why.append("approval already used")
    if not approval.get("approver_session_online"):
        why.append("the officer's own session is not connected and verified")
    if not why:
        used_nonces.add(approval["nonce"])
    return not why, why
