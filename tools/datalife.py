"""Data and AI lifecycle rules: output labels, inference routing, agent registration, and per-product protection
and retention checks."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LABELS = ["Internal", "Sensitive", "Restricted"]


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "data-ai.yaml").read_text(encoding="utf-8"))


def output_label(input_labels: list[str]) -> str:
    """An answer carries the highest label of everything that went into it."""
    return max(input_labels, key=LABELS.index) if input_labels else LABELS[-1]


AI_EGRESS_CONTRACT = "ai-egress-gate"
EXTERNAL_FORWARD = "external-forward"
_RANK = {"none": 0, "partial": 1, "candidate": 2, "ready": 3}


def external_ai_egress_providers(contracts: dict | None = None, root: Path = ROOT) -> list[str]:
    """ADR-0164 point 3: the registered providers of the AI egress gate contract that may carry an external route:
    readiness at least candidate AND the external forward feature scored yes. Read from catalog/contracts.yaml unless
    a contracts document is given; a missing contract, implementation or feature counts as no (fail closed)."""
    if contracts is None:
        contracts = yaml.safe_load((root / "catalog" / "contracts.yaml").read_text(encoding="utf-8"))
    gate = ((contracts or {}).get("contracts") or {}).get(AI_EGRESS_CONTRACT) or {}
    out = []
    for name, impl in (gate.get("implementations") or {}).items():
        feature = (impl.get("features") or {}).get(EXTERNAL_FORWARD)
        if feature is True or feature == "yes":   # YAML 1.1 reads a bare yes as True
            if _RANK.get(impl.get("readiness"), 0) >= _RANK["candidate"]:
                out.append(name)
    return out


def route_inference(label: str, endpoint: dict, consent: bool, pseudonymised: bool, contracts: dict | None = None) -> dict:
    if endpoint["kind"] == "local":
        if LABELS.index(label) > LABELS.index(endpoint["max_label"]):
            return {"allowed": False, "why": f"{label} is above the endpoint's {endpoint['max_label']}"}
        return {"allowed": True, "why": "local endpoint within its label"}
    if label == "Restricted":
        return {"allowed": False, "why": "Restricted never leaves for an external model"}
    # ADR-0164 point 3: an external route needs a registered AI egress gate provider that forwards externally,
    # whatever the caller claims about consent or pseudonymisation
    if not external_ai_egress_providers(contracts):
        return {"allowed": False, "why": "no registered ai-egress-gate provider with readiness candidate or better forwards externally: AI egress fails closed (ADR-0164)"}
    if not (consent and pseudonymised):
        return {"allowed": False, "why": "external model needs the client's named consent and ai-egress-gate pseudonymisation"}
    return {"allowed": True, "why": "consented and pseudonymised"}


def check_agent(agent: dict, cfg: dict, today: date) -> list[str]:
    errs = [f"agent {agent.get('id')}: missing {f}" for f in cfg["ai"]["agents"]["registry_fields"] if not agent.get(f)]
    if agent.get("delegator") == agent.get("id"):
        errs.append(f"agent {agent.get('id')}: cannot delegate to itself")
    exp = agent.get("expires")
    if exp and date.fromisoformat(str(exp)) - today > timedelta(days=cfg["ai"]["agents"]["max_lifetime_days"]):
        errs.append(f"agent {agent.get('id')}: registration longer than {cfg['ai']['agents']['max_lifetime_days']} days")
    if agent.get("autonomy") == "autonomous" and agent.get("max_label") == "Restricted":
        errs.append(f"agent {agent.get('id')}: no autonomous agent on Restricted data")
    return errs


def check_products(cfg: dict) -> list[str]:
    errs = []
    for pid, p in cfg["products"].items():
        for k in ("criticality", "rto_hours", "rpo_hours", "retention_days", "backup_retention_days", "review_months"):
            if p.get(k) is None:
                errs.append(f"{pid}: missing {k}")
        if p.get("rpo_hours", 0) > p.get("rto_hours", 0) * 24:
            errs.append(f"{pid}: RPO implausibly larger than the RTO window")
        if p.get("criticality") == "high" and p.get("rpo_hours", 99) > 4:
            errs.append(f"{pid}: high criticality needs RPO of at most 4 hours")
        if p.get("backup_retention_days", 0) > 35:
            errs.append(f"{pid}: backups outlive deletion by more than 35 days, destruction would not complete")
    return errs
