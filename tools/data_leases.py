"""Data lease checks (ADR-0095): every product has an owner whose ownership is a lease and a steward who is someone
else; every consumer of the backbone holds a current lease from the owner (new or renewal) or the steward (renewal
only), for a purpose the product allows, no longer than its kind allows for the product's label; derived and
sub-leases end with their parents; aggregates name a minimum group size; lease kinds, early ends, offline grace, key
custody and plaintext residency are complete; shred is two-person and blocked by legal hold; custody sees ciphertext
only. Recently lapsed leases are reported; leases lapsed beyond the record window must be marked ended.
Usage: python tools/data_leases.py
"""
from __future__ import annotations

import re
import sys
from datetime import date, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LABELS = ["Internal", "Sensitive", "Restricted"]
DUR = re.compile(r"^(\d+)([smhd])$")
UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}
CONSUMING = ("subscription", "edc")
STATUSES = ("active", "suspended", "ended")
OBLIGATIONS = ("none", "legal", "safety")


def _y(rel: str):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def _d(v) -> date:
    return v if isinstance(v, date) else date.fromisoformat(str(v))


def _s(v) -> int:
    m = DUR.match(str(v))
    return int(m.group(1)) * UNIT[m.group(2)] if m else -1


def load() -> dict:
    sys.path.insert(0, str(ROOT / "tools"))
    from data_policy import limits
    return {"dl": _y("policies/data-leases.yaml"), "dp": _y("platform/data-platform.yaml"),
            "cls": _y("platform/classification.yaml"), "pol": limits()}


def _products(d: dict, today: date, errs: list[str], lapsed: list[str]) -> dict[str, str]:
    dl, dp = d["dl"], d["dp"]
    stewards = {p: dom["owner"] for dom in dp["mesh"]["domains"].values() for p in dom["products"]}
    own_max = dl["lease_kinds"]["ownership"]["max_days"]
    grace = dl["offline"]["key_grace"]
    for name, p in dp["products"].items():
        if name not in stewards:
            errs.append(f"product {name}: no domain, so no steward")
        elif dl["grants"]["steward_is_not_owner"] and stewards[name] == p.get("owner"):
            errs.append(f"product {name}: the steward is the owner, so there is no fallback")
        if not p.get("owner") or not p.get("owner_until"):
            errs.append(f"product {name}: needs an owner and owner_until (ownership is a lease)")
            continue
        until = _d(p["owner_until"])
        if until > today + timedelta(days=own_max[p["label"]]):
            errs.append(f"product {name}: ownership lease runs past {own_max[p['label']]} days from today")
        if until < today:
            lapsed.append(f"product {name}: ownership lapsed {until}; steward {stewards.get(name)} acts")
        if p.get("ddil") == "must-run-local" and _s(grace[p["label"]]) <= 0:
            errs.append(f"product {name}: must run local but {p['label']} has no offline key grace")
    return stewards


def _leases(d: dict, today: date, stewards: dict[str, str], errs: list[str], lapsed: list[str]) -> set[str]:
    dl, dp = d["dl"], d["dp"]
    kinds, products, grants = dl["lease_kinds"], dp["products"], dl["grants"]
    leases = dp.get("leases", [])
    by_id = {l.get("id"): l for l in leases}
    current: set[str] = set()
    seen: set[str] = set()
    for l in leases:
        lid = l.get("id", "?")
        if lid in seen:
            errs.append(f"lease {lid}: duplicate id")
        seen.add(lid)
        k, p = kinds.get(l.get("kind")), products.get(l.get("product"))
        if not k or not p:
            errs.append(f"lease {lid}: unknown kind or product")
            continue
        start, end = _d(l["from"]), _d(l["until"])
        if l.get("purpose") not in p["purposes"]:
            errs.append(f"lease {lid}: purpose {l.get('purpose')} is not allowed by {l['product']}")
        by, steward = l.get("granted_by"), stewards.get(l["product"])
        if l.get("grant") not in grants["types"]:
            errs.append(f"lease {lid}: grant must be one of {grants['types']}")
        if by == p["owner"]:
            if p.get("owner_until") and start > _d(p["owner_until"]):
                errs.append(f"lease {lid}: granted by {by} after the ownership lease ended")
        elif by == steward:
            if l.get("grant") not in grants["steward_may"]:
                errs.append(f"lease {lid}: the steward may only renew, not grant {l.get('grant')}")
        else:
            errs.append(f"lease {lid}: granted by {by}, not the owner or steward of {l['product']}")
        if not l.get("consumer") or not l.get("scope"):
            errs.append(f"lease {lid}: needs a consumer and a scope")
        if l.get("onward") not in dl["onward"]["allowed"]:
            errs.append(f"lease {lid}: onward must be one of {dl['onward']['allowed']}")
        if l.get("obligation", "none") not in OBLIGATIONS:
            errs.append(f"lease {lid}: obligation must be one of {OBLIGATIONS}")
        if l["kind"] == "subscription":
            limit = d["pol"]["subscription_max_days"][p["label"]]          # policy packs (ADR-0100)
        else:
            limit = k["max_days"][p["label"]] if isinstance(k.get("max_days"), dict) else None
        if end <= start or (limit is not None and (end - start).days > limit):
            errs.append(f"lease {lid}: {(end - start).days} days exceeds {limit} for {l['kind']} of {p['label']} data")
        parents = list(l.get("derived_from", [])) + ([l["parent"]] if l.get("parent") else [])
        for pid in parents:
            if pid not in by_id:
                errs.append(f"lease {lid}: parent or input {pid} unknown")
            elif end > _d(by_id[pid]["until"]):
                errs.append(f"lease {lid}: ends after its parent or input {pid}")
        if l.get("aggregated") and (l.get("min_group_size") or 0) < d["pol"]["min_group_size"]:
            errs.append(f"lease {lid}: an aggregated scope needs min_group_size >= {d['pol']['min_group_size']}")
        status = l.get("status")
        if status not in STATUSES:
            errs.append(f"lease {lid}: status must be one of {STATUSES}")
        if status == "suspended":
            since = l.get("suspended_on")
            if not since or (today - _d(since)).days > dl["ending"]["suspend"]["max_days"]:
                errs.append(f"lease {lid}: suspended beyond {dl['ending']['suspend']['max_days']} days (resume or revoke)")
        if end < today and status != "ended":
            if (today - end).days > dl["lapsed_record_days"]:
                errs.append(f"lease {lid}: ended {end} but still marked {status}")
            else:
                lapsed.append(f"lease {lid}: ended {end}; flows stop")
        if status == "active" and start <= today <= end:
            current.add(l["consumer"])
    return current


def _rules(d: dict) -> list[str]:
    dl, errs = d["dl"], []
    for name, k in dl["lease_kinds"].items():
        if not k.get("granted_by") or not k.get("on_expiry") or not k.get("renew"):
            errs.append(f"lease kind {name}: needs granted_by, renew and on_expiry")
        lim = k.get("max_days") if "max_days" in k else k.get("max_ttl")
        if isinstance(lim, dict):
            vals = [lim[x] if "max_days" in k else _s(lim[x]) for x in LABELS]
            if vals != sorted(vals, reverse=True):
                errs.append(f"lease kind {name}: limits must shrink from Internal to Restricted")
    if not dl["lease_kinds"]["training"].get("retire_after_revoke_days"):
        errs.append("lease kind training: a trained model needs retire_after_revoke_days")
    if not dl["lease_kinds"]["emergency"].get("max_chain"):
        errs.append("lease kind emergency: needs max_chain so it cannot replace a grant")
    end = dl["ending"]
    if not end["suspend"]["reversible"] or end["revoke"]["reversible"] or end["shred"]["reversible"]:
        errs.append("ending: suspend is reversible, revoke and shred are not")
    if not end["shred"].get("two_person") or end["shred"].get("blocked_by") != "legal-hold":
        errs.append("ending: shred needs two persons and is blocked by a legal hold")
    if not end["suspend"].get("max_days"):
        errs.append("ending: suspend needs max_days")
    if not 0 < (end["revoke"].get("purge_attestation_s") or 0) <= 86400 or not end["revoke"].get("second_taker_when"):
        errs.append("ending: revoke needs a purge attestation deadline within a day and second-taker obligations")
    errs += [f"ending {e}: propagation SLO missing or above 300 s" for e, v in end.items()
             if not isinstance(v.get("propagation_slo_s"), int) or v["propagation_slo_s"] > 300]
    grace = [_s(dl["offline"]["key_grace"][x]) for x in LABELS]
    if min(grace) < 0 or grace != sorted(grace, reverse=True):
        errs.append("offline: key_grace must be durations that shrink from Internal to Restricted")
    if dl["key_custody"].get("kas_replicas_min", 0) < 3 or not dl["key_custody"].get("restore_rule"):
        errs.append("key custody: at least 3 key access replicas and a restore rule that replays the shred ledger")
    missing = {"logs", "prompts-and-model-context", "search-indexes"} - set(dl["plaintext_residency"]["never_in"])
    if missing or dl["plaintext_residency"].get("max_ttl") != "key-release":
        errs.append(f"plaintext residency: bounded by the key lease and never in {sorted(missing) or 'the listed sinks'}")
    if d["cls"]["layers"].get("backup-storage", {}).get("sees") != "ciphertext":
        errs.append("custody: backup storage must see ciphertext only, or ending a lease would break restore")
    return errs


def check(d: dict, today: date | None = None) -> tuple[list[str], list[str]]:
    """Returns (errors, lapsed)."""
    # a published copy is judged at the day it was exported, the private side at today
    stamp = ROOT / "ci" / "exported-on.txt"
    today = today or (date.fromisoformat(stamp.read_text(encoding="utf-8").strip()) if stamp.exists() else date.today())
    errs: list[str] = []
    lapsed: list[str] = []
    stewards = _products(d, today, errs, lapsed)
    current = _leases(d, today, stewards, errs, lapsed)
    consumers = {i["to"] for i in d["dp"]["integrations"] if i["from"] == "backbone" and i["via"] in CONSUMING}
    errs += [f"consumer {c}: reads from the backbone without a current lease" for c in sorted(consumers - current)]
    return errs + _rules(d), lapsed


if __name__ == "__main__":
    data = load()
    problems, ended = check(data)
    print(f"products {len(data['dp']['products'])}, leases {len(data['dp'].get('leases', []))}, lapsed {len(ended)}")
    for x in ended:
        print("LAPSED", x)
    for x in problems:
        print("ERROR", x)
    sys.exit(1 if problems else 0)
