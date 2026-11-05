"""Intent to configuration: compile an application intent (functions, data label, users) through the security
architect's patterns, the label's exposure rules and isolation floors into flows, controls and a runtime class.

The resolver is deterministic and refuses rather than guesses: unknown functions, technical fields in an intent,
missing prerequisites, exposures the label forbids and protocols the component does not declare are errors. An LLM
may draft an intent from a conversation; only this resolver turns it into technical configuration.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from model import Flow

ROOT = Path(__file__).resolve().parent.parent
TECHNICAL_FIELDS = {"port", "ports", "cidr", "cidrs", "protocol", "protocols", "proto", "ip", "firewall", "flows"}
INTENT_FIELDS = {"app", "purpose", "component", "node", "functions", "data_label", "users", "ddil", "deviations", "placement"}


def load_yaml(rel: str) -> dict:
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def resolve(intent: dict, patterns: dict | None = None, isolation: dict | None = None,
            ingress: str = "caddy") -> dict:
    patterns = patterns or load_yaml("catalog/patterns.yaml")
    isolation = isolation or load_yaml("platform/isolation.yaml")
    errors: list[str] = []
    technical = TECHNICAL_FIELDS & set(intent)
    if technical:
        errors.append(f"intent declares technical fields {sorted(technical)}: declare functions, not ports")
    unknown_fields = set(intent) - INTENT_FIELDS - TECHNICAL_FIELDS
    if unknown_fields:
        errors.append(f"unknown intent fields {sorted(unknown_fields)}")
    label = intent.get("data_label")
    if label not in patterns["exposure_allowed"]:
        errors.append(f"unknown data label {label!r}")
    comp = patterns["components"].get(intent.get("component"))
    if comp is None:
        errors.append(f"component {intent.get('component')!r} is not vetted")
    node = intent.get("node", intent.get("app"))
    names = {"self": node, "ingress": ingress, "self-db": f"{node}-db"}
    flows, controls = [], set()
    for fn in intent.get("functions", []):
        p = patterns["patterns"].get(fn)
        if p is None:
            errors.append(f"function {fn!r} has no approved pattern: ask the security architect")
            continue
        for req in p.get("requires", []):
            if req not in intent["functions"]:
                errors.append(f"function {fn!r} requires {req!r}")
        if label in patterns["exposure_allowed"] and p["exposure"] not in patterns["exposure_allowed"][label]:
            errors.append(f"function {fn!r} has exposure {p['exposure']!r}, not allowed for {label} data")
        controls |= set(p["controls"])
        for f in p["flows"]:
            src, dst = names.get(f["from"], f["from"]), names.get(f["to"], f["to"])
            if "port" in f:
                port, proto = f["port"], f["proto"]
            else:
                target = patterns["components"].get(f["component"]) if f.get("component") else comp
                listens = (target or {}).get("listens", {})
                if f["protocol"] not in listens:
                    errors.append(f"component {intent.get('component')!r} does not declare protocol {f['protocol']!r}")
                    continue
                port, proto = listens[f["protocol"]], "tcp"
            flows.append(Flow(f"{intent.get('app')}:{fn}", src, dst, int(port), proto))
    if intent.get("placement"):
        authority = load_yaml("catalog/authority.yaml")
        allowed = authority["golden_path"]["placement"].get(label, [])
        if intent["placement"] not in allowed:
            errors.append(f"placement {intent['placement']!r} is outside the golden path for {label}: needs a placement-exception deviation")
    runtime = isolation["isolation_floor"].get(label)
    return {"app": intent.get("app"), "flows": flows, "controls": sorted(controls), "runtime": runtime,
            "errors": errors}


if __name__ == "__main__":
    import json
    import sys
    r = resolve(yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8")))
    r["flows"] = [f.__dict__ for f in r["flows"]]
    print(json.dumps(r, indent=2))
    sys.exit(1 if r["errors"] else 0)
