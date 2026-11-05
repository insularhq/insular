"""Data products on one backbone: contract checks, the no-bilateral rule, and subscription decisions.

A subscription is allowed when the consumer's environment label is at least the product's label, the purpose is in
the product's usage policy, and the consumer's own access decision passes. A consumer below the product's label is
routed to the release gateway instead of being refused silently or connected directly.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LABELS = ["Internal", "Sensitive", "Restricted"]
REQUIRED = ("owner", "label", "schema", "purposes", "ddil", "retention_days")


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "data-platform.yaml").read_text(encoding="utf-8"))


def check(dp: dict) -> list[str]:
    errs = []
    for pid, p in dp["products"].items():
        errs += [f"{pid}: missing {k}" for k in REQUIRED if not p.get(k)]
        if p.get("label") not in LABELS:
            errs.append(f"{pid}: unknown label {p.get('label')}")
    for i in dp["integrations"]:
        if "backbone" not in (i["from"], i["to"]):
            errs.append(f"bilateral integration {i['from']} -> {i['to']}: connect to the backbone instead")
    return errs


def connections(systems: int) -> dict:
    return {"bilateral": systems * (systems - 1) // 2, "backbone": systems}


def subscribe(product: dict, consumer: dict, access_allowed: bool) -> dict:
    if not access_allowed:
        return {"decision": "deny", "why": "access decision denied for this consumer"}
    if consumer["purpose"] not in product["purposes"]:
        return {"decision": "deny", "why": f"purpose {consumer['purpose']} not in the usage policy"}
    if LABELS.index(consumer["environment_label"]) < LABELS.index(product["label"]):
        return {"decision": "release-gateway", "why": f"consumer at {consumer['environment_label']} is below {product['label']}: only sanitised releases"}
    return {"decision": "allow", "why": "label, purpose and access all pass"}


def check_overlays(dp: dict) -> list[str]:
    """Federated governance: a domain overlay may only tighten the global policy."""
    errs = []
    glob = dp["mesh"]["global_policy"]
    for dom, ov in dp["mesh"].get("domain_overlays", {}).items():
        for label, days in ov.get("max_retention_days", {}).items():
            if days > glob["max_retention_days"][label]:
                errs.append(f"domain {dom}: retention {days} for {label} exceeds the global {glob['max_retention_days'][label]}")
    return errs


def resolve_product(intent: dict, dp: dict) -> dict:
    """Self-serve: compile a data product intent into everything the platform must create for it."""
    glob = dp["mesh"]["global_policy"]
    errs = [f"missing {k}" for k in glob["required"] if not intent.get(k)]
    label = intent.get("label")
    if label not in glob["labels"]:
        errs.append(f"unknown label {label}")
        return {"errors": errs}
    cap = glob["max_retention_days"][label]
    dom = dp["mesh"].get("domain_overlays", {}).get(intent.get("domain"), {})
    cap = min(cap, dom.get("max_retention_days", {}).get(label, cap))
    if intent.get("retention_days", 0) > cap:
        errs.append(f"retention {intent['retention_days']} days exceeds the allowed {cap} for {label} in domain {intent.get('domain')}")
    name, ver = intent.get("name"), intent.get("version", 1)
    masking = glob["labels"].index(label) >= glob["labels"].index(glob["personal_data_masking_from"])
    out = {
        "errors": errs,
        "subject": f"products.{intent.get('domain')}.{name}.v{ver}",
        "schema_registry": f"{name}-v{ver}",
        "table": f"{intent.get('domain')}.{name}_v{ver}" if intent.get("tabular") else None,
        "catalog_entry": {"owner": intent.get("owner"), "domain": intent.get("domain"), "label": label},
        "access_policy": {"purposes": intent.get("purposes"), "min_consumer_label": label, "mask_personal_data": masking},
        "quality_suite": intent.get("quality_suite"),
        "lineage": True,
        "destruction": {"after_days": intent.get("retention_days"), "method": "crypto-erasure"},
        "review": {"every_months": intent.get("review_months")},
        "dataspace_asset": f"edc:{name}-v{ver}" if intent.get("share_with_partners") else None,
    }
    return out
