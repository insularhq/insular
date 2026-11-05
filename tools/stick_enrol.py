"""Enrolment ceremony: from a blank stick to a personal stick that signs in before the network (platform/boot-stick.yaml,
enrolment). A security officer, signed in on their own connected device, launches it; the user is present (in person
or verified remotely) and enrols their own FIDO2 keys and PINs, which the officer never sees.
"""

from __future__ import annotations

from datetime import datetime

from stick_release import release


def enrol(cfg: dict, ticket: dict, approval: dict, evidence: dict, now: datetime, used: set[str], officers: set[str]) -> tuple[bool, list[str]]:
    """Whether the enrolment may complete and the stick be handed over. Deny overrides; every reason is returned."""
    ok, why = release({"user": ticket["user"], "stick": ticket["stick"], "request_id": ticket["id"]}, approval, now, used, officers)
    steps = [s["step"] for s in cfg["enrolment"]["steps"]]
    missing = [s for s in steps if not evidence.get(s)]
    why += [f"step not evidenced: {s}" for s in missing]
    if evidence.get("fido2_keys_enrolled", 0) < 2:
        why.append("two FIDO2 keys (primary and backup) must be enrolled")
    if evidence.get("pin_seen_by_officer"):
        why.append("the officer must never see or set the user's PIN")
    if evidence.get("image_version", 0) < ticket["image_version_min"]:
        why.append("stick image below the tenant's minimum")
    if "offline-test" in missing:
        why.append("handover only after a successful sign-in with the network disconnected")
    return ok and not why, why
