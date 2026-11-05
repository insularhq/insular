"""Multi-perimeter egress for the remote browser (platform/egress.yaml).

A destination is reachable only when it is on the signed allow-list AND every perimeter applies it. An allow-list
change needs at least two approvers (distinct persons, approver roles, never the requester) and is applied by at least
two independent automation pipelines, each of which verifies the approvals itself. A destination present on a
perimeter but not on the allow-list is an incident; one missing from a perimeter is simply unreachable (fail closed).
"""

from __future__ import annotations


def change_ok(change: dict, cfg: dict) -> tuple[bool, list[str]]:
    why = []
    approvers = {a["person"] for a in change.get("approvals", []) if a.get("signature_valid") and a.get("role") in cfg["approver_roles"]}
    approvers.discard(change.get("requested_by"))
    if len(approvers) < cfg["min_approvers"]:
        why.append(f"needs {cfg['min_approvers']} approvers other than the requester with valid signatures")
    if not change.get("expires"):
        why.append("an allow-list entry needs an expiry")
    return not why, why


def check(cfg: dict, allowlist: set[str], applied: dict[str, set[str]], verified_by: dict[str, bool]) -> dict:
    """applied: perimeter -> destinations it lets through; verified_by: pipeline -> whether it verified the approvals."""
    pipelines = {p["pipeline"] for p in cfg["perimeters"].values()}
    findings = []
    if len(pipelines) < cfg["min_pipelines"]:
        findings.append(f"perimeters must be applied by at least {cfg['min_pipelines']} independent pipelines")
    for name, per in cfg["perimeters"].items():
        if not verified_by.get(per["pipeline"]):
            findings.append(f"{name}: pipeline {per['pipeline']} did not verify the approvals itself")
        extra = applied.get(name, set()) - allowlist
        if extra:
            findings.append(f"incident: {name} lets through {sorted(extra)} which is not on the signed allow-list")
    reachable = set(allowlist)
    for name in cfg["perimeters"]:
        reachable &= applied.get(name, set())
    return {"reachable": reachable, "findings": findings}
