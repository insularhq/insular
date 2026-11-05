"""KeyClerk's configuration for this deployment, rendered from the registers (ADR-0176).

The registers stay the one source of the rules (platform/access-lifecycle.yaml, identity.yaml, places.yaml,
access-paths.yaml); config/keyclerk/keyclerk.yaml is their rendering in the engine's configuration schema, committed so
the engine can run on its own (KEYCLERK_CONFIG) and checked here so it never drifts; gitops/lab/identity/keyclerk.yaml is
the same text for the lab unit. setup() configures the pinned
engine for every tool and test in this repository.

Usage: python tools/keyclerk_config.py render | check
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "config" / "keyclerk" / "keyclerk.yaml"
RING = ROOT / "gitops" / "lab" / "identity" / "keyclerk.yaml"   # the same text for the lab unit
PIN = ROOT / "requirements-keyclerk.txt"
HEADER = ("# Rendered by tools/keyclerk_config.py from the registers; do not edit by hand (ADR-0176).\n"
          "# The KeyClerk engine reads this file; the registers are the source.\n")


def _y(rel: str) -> dict:
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def build() -> dict:
    al, ident = _y("platform/access-lifecycle.yaml"), _y("platform/identity.yaml")
    pl, ap = _y("platform/places.yaml"), _y("platform/access-paths.yaml")
    fr = ident["accounts"]["functional_roles"]["max_hours"] if "accounts" in ident else ident["functional_roles"]["max_hours"]
    xa = al["external_access"]
    return {
        "roles": {k: {kk: vv for kk, vv in v.items() if kk in ("plane", "class", "scope_max")}
                  for k, v in al["roles"].items() if isinstance(v, dict)},
        "grant_limits": {
            "activation_max_hours": al["grant_classes"]["activation"]["max_hours"],
            "functional_max_hours": fr,
            "phase_one": True,   # special_roles.phase_one: single-operator start-up mode until a second person enrols
            "operator_kind": "vdhome",
            "subject_kinds": ["vdhome", "tenant", "external", "edge-born"],
            "scope_levels": ["federation", "tenant", "isle", "islet", "skiff", "resource"],
            "operator_tenant_roles": ["consultant"],
            "tenant_infrastructure_roles": ["site-sysadmin"],
        },
        "external_access": {
            "categories": {k: {"max_days": v["max_days"]} for k, v in xa["categories"].items()
                           if isinstance(v, dict) and "max_days" in v},
            "steps": {"during": {"reminder_days": xa["steps"]["during"]["reminder_days"]},
                      "offboarding": {"retention": {"account_delete_days":
                                                    xa["steps"]["offboarding"]["retention"]["account_delete_days"]}}},
            "totals": {k: v for k, v in xa["totals"].items() if k != "rule"},
        },
        "delegation": al["delegated_administration"]["rule_data"],
        "attributes": {k: {kk: vv for kk, vv in v.items() if kk in ("provided_by", "authority", "ttl_hours", "pedigree",
                                                                       "may_widen", "allowed_values", "self_write", "offline")}
                       for k, v in ident["attributes"].items()},
        "situation": al["situation_response"]["rule_data"],
        "risk_port": al["delegated_administration"]["risk_port"]["rule_data"],   # require_trust: fail closed
        "places": {"kinds": pl["physical"]["kinds"], "nest_same_kind": pl["physical"]["nest_same_kind"]},
        "access_paths": ap["rule_data"],
        "availability": ap["availability"]["rule_data"],
        "reconcile": al["keyclerk_engine"]["reconcile_limits"],
        "approvals": {"proofs": al["keyclerk_engine"]["approvals"]["proofs"],
                      "max_age_seconds": al["keyclerk_engine"]["approvals"]["max_age_seconds"],
                      "acr": al["keyclerk_engine"]["approvals"]["acr"],
                      "accepted_without_proof": seed_approvals()},
        "identity_sources": al["keyclerk_engine"]["identity_sources"],     # ADR-0182
    }


def seed_approvals() -> list[dict]:
    """The approvals in the records every instance started from: reviewed in git, made before proofs existed, so the
    deployment pins them record by record (engine decision 0006). Every later approval needs the broker's proof."""
    from keyclerk.approvals import KEYED, record_hash   # each pin bound to the record as approved; the
    out = []                                            # kinds follow the engine's, which checks every one (0.26.3)
    for f in sorted((ROOT / "instances").glob("*/grants.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for kind, field in KEYED:
            for r in doc.get(kind) or []:
                out += [{"record": str(r[field]), "by": str(a), "sha256": record_hash(kind, r)} for a in r.get("approved_by") or []]
        for s in doc.get("suspensions") or []:
            out += [{"record": str(s["suspension_id"]), "by": str(a), "sha256": record_hash("suspensions", s)}
                    for a in (s.get("lifted") or {}).get("by") or []]
    return sorted(out, key=lambda x: (x["record"], x["by"]))


def render_text() -> str:
    return HEADER + yaml.safe_dump(build(), sort_keys=False, allow_unicode=False)


def _pin() -> dict:
    pins = yaml.safe_load((ROOT / "frameworks" / "external-pins.yaml").read_text(encoding="utf-8"))["pins"]
    return next(p for p in pins if p["name"] == "keyclerk")


def pinned_version() -> str:
    """The engine version this repository pins (frameworks/external-pins.yaml, ADR-0178)."""
    return _pin()["tag"].lstrip("v")


def pinned_commit() -> str:
    return _pin()["commit"]


def setup() -> None:
    """Configure the installed engine with this deployment's configuration; refuse an engine of another version."""
    import keyclerk
    from keyclerk import config
    if keyclerk.__version__ != pinned_version():
        raise RuntimeError(f"keyclerk {keyclerk.__version__} is installed, this repository pins {pinned_version()} "
                           f"(pip install the pinned commit, or pip install -e the engine checked out at it)")
    import external_pins
    errs = external_pins.check_package(_pin())
    if errs:
        raise RuntimeError("; ".join(errs))
    config.configure(build())


def main(argv: list[str]) -> int:
    if argv[:1] == ["render"]:
        for out in (OUT, RING):
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(render_text(), encoding="utf-8", newline="\n")
        return 0
    errs = []
    for out in (OUT, RING):
        if not out.exists() or out.read_text(encoding="utf-8") != render_text():
            errs.append(f"stale: {out.relative_to(ROOT)}: run python tools/keyclerk_config.py render")
    from keyclerk import config
    errs += config.validate(build())
    try:
        setup()
    except RuntimeError as e:
        errs.append(str(e))
    for e in errs:
        print(e, file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
