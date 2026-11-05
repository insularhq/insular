"""Reference authorisation model for every subject kind (persons, workloads, devices, infrastructure, agents).

Request shape follows the OpenID AuthZEN Authorization API: subject, action, resource, context; plus an actor chain
for delegation. Deny overrides: RBAC, ABAC and adaptive context must all pass. Production evaluation is OPA; this
module pins the semantics in tests.

Roles come only from grant records: a role claim in a token is a
hint for applications and counts for nothing here. Pass the realm's grant records (tools/records.py load) as `grants`;
without them every role-gated rule denies.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MAX_CHAIN = 2
MAX_SKEW = timedelta(minutes=2)


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "identity.yaml").read_text(encoding="utf-8"))


def fresh(subject: dict, name: str, registry: dict, now: datetime):
    a = subject.get("attributes", {}).get(name)
    if a is None or name not in registry["attributes"]:
        return None
    age = now - datetime.fromisoformat(a["at"])
    if age < -MAX_SKEW:
        return None   # dated in the future: never fresh
    return a["value"] if age <= timedelta(hours=registry["attributes"][name]["ttl_hours"]) else None


def check_policy(policy: dict, registry: dict) -> list[str]:
    errs = []
    for rule in policy["rules"]:
        for attr in list(rule.get("require_attributes", {})) + list(rule.get("require_context", {})):
            if attr in registry["forbidden_attributes"]:
                errs.append(f"{rule['id']}: uses forbidden attribute {attr}")
            elif attr not in registry["attributes"]:
                errs.append(f"{rule['id']}: uses unregistered attribute {attr}")
    return errs


def grant_roles(grants: dict | None, anchor: str, now: datetime) -> set[str] | None:
    """The roles a subject holds now: its effectively active functional and activation grants (skew-safe and
    suspension-aware, tools/access_state.py); an eligibility alone holds no role. None when no grant data is given."""
    if grants is None:
        return None
    from access_state import effective_grants
    return {g["role"] for g in effective_grants(grants, now)
            if g["subject"]["anchor"] == anchor and g["class"] in ("functional", "activation")}


def allows(rule: dict, subject: dict, ctx: dict, registry: dict, now: datetime, grants: dict | None = None) -> list[str]:
    why = []
    if subject["type"] not in rule["subject_types"]:
        why.append(f"{subject['type']} not allowed")
    if rule.get("roles"):
        held = grant_roles(grants, subject.get("anchor", subject["id"]), now)
        if held is None:
            why.append("role: no grant records given; roles come only from grants, never from a token (AZ-5)")
        elif not held & set(rule["roles"]):
            why.append("role")
    for name, want in rule.get("require_attributes", {}).items():
        v = fresh(subject, name, registry, now)
        if v is None or (v not in want if isinstance(want, list) else v != want):
            why.append(f"attribute {name}")
    for name, want in rule.get("require_context", {}).items():
        v = fresh_context(ctx, name, registry, now)
        if v is None or (v not in want if isinstance(want, list) else v != want):
            why.append(f"context {name} (missing, stale, untimestamped or wrong)")
    return why


def fresh_context(ctx: dict, name: str, registry: dict, now: datetime):
    """Context signals obey the same freshness as attributes: {value, at}; a bare value counts as missing (PKI-04)."""
    c = ctx.get(name)
    if not isinstance(c, dict) or "value" not in c or "at" not in c:
        return None
    return fresh({"attributes": {name: c}}, name, registry, now)


def decide(req: dict, policy: dict, registry: dict, now: datetime, grants: dict | None = None) -> dict:
    """Return {'decision': bool, 'reasons': [...]}. Every actor in the chain must be allowed on its own."""
    rule = next((r for r in policy["rules"] if r["action"] == req["action"]["name"]
                 and r["resource_type"] == req["resource"]["type"]), None)
    if rule is None:
        return {"decision": False, "reasons": ["no rule: default deny"]}
    chain = [req["subject"]] + req.get("actors", [])
    reasons = []
    if len(chain) - 1 > MAX_CHAIN:
        reasons.append("delegation chain too long")
    if rule.get("irreversible") and any(s["type"] == "agent" for s in chain):
        reasons.append("agents never perform irreversible actions")
    for s in chain:
        reasons += [f"{s['id']}: {w}" for w in allows(rule, s, req.get("context", {}), registry, now, grants)]
    tenant = req["resource"].get("tenant")
    if tenant is not None:
        for s in chain:
            if fresh(s, "tenant", registry, now) != tenant:
                reasons.append(f"{s['id']}: not a member of tenant {tenant} (cross-tenant access denied)")
    return {"decision": not reasons, "reasons": reasons}
