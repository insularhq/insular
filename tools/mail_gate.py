"""The mail gate (ADR-0105): every submitted message passes here before any recipient sees it.

Steps:
1. Every linked unit must be one the sender holds a lease for. Failures read the same whether or not the unit exists.
2. Every address resolves to exactly one known person or role through a fresh directory. Lists expand to their
   members; nested lists are refused; external addresses sit in the federation ring.
3. Attachments must be cited units. Unscannable ones (encrypted, or nested deeper than the limit) are refused.
4. Body and subject are scanned in the ring; personal data the message does not cite holds the message for the sender.
5. The message envelope is derived from the cited units plus the authored body (ADR-0104).
6. One decision per recipient through the policy engine: deliver, hold (a request with its SLA), or refuse.
   Bounces carry a reason code and a request id, never content.
7. Headers: SIO-Label (RFC 7444) and a STANAG 4778 binding (ADR-0103). Restricted mail gets a neutral subject.
8. Any error fails closed with a temporary failure: nothing is delivered.

Usage (library): gate(d, submission, directory, today)
"""
from __future__ import annotations

import hashlib
import sys
from datetime import datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


def _cfg() -> dict:
    return yaml.safe_load((ROOT / "platform" / "channels.yaml").read_text(encoding="utf-8"))["mail_gate"]


def _ref(*parts) -> str:
    return "req-" + hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:12]


def resolve_recipients(addresses: list[str], directory: dict, cfg: dict) -> tuple[list[dict], list[dict]]:
    """(resolved recipients, refusals). Directory entries: {kind: person-role|list|external, principal, ring, members}."""
    out, refused, seen = [], [], set()
    for a in addresses:
        a = a.strip().lower()
        domain = a.rsplit("@", 1)[-1]
        if domain not in cfg["tenant_domains"]:
            if any(domain != t and (domain.replace("-", "").replace("0", "o") == t.replace("-", "") or domain.endswith("." + t)) for t in cfg["tenant_domains"]):
                refused.append({"to": a, "code": "lookalike-domain"})
                continue
            out.append({"to": a, "principal": None, "ring": "federation", "external": True})
            continue
        e = directory.get(a)
        if e is None:
            refused.append({"to": a, "code": "unknown-recipient"})
            continue
        if e["kind"] == "list":
            for m in e["members"]:
                me = directory.get(m)
                if me is None or me["kind"] == "list":
                    refused.append({"to": a, "code": "nested-or-unknown-list-member"})
                    continue
                if m not in seen:
                    seen.add(m)
                    out.append({"to": m, "principal": me["principal"], "ring": me["ring"], "external": False, "via": a})
            continue
        if a not in seen:
            seen.add(a)
            out.append({"to": a, "principal": e["principal"], "ring": e["ring"], "external": False})
    return out, refused


def gate(d: dict, sub: dict, directory: dict, today: str = "2026-10-10") -> dict:
    """sub: {sender, sender_ring, band, site_band, addresses, subject, body, links: [envelope], purpose, attachments: [...]}
    band and site_band come from the sender's session and site; a missing one decides as black."""
    try:
        return _gate(d, sub, directory, today)
    except Exception as e:  # noqa: BLE001 - fail closed on anything unexpected
        return {"result": "tempfail", "reason": f"gate error, nothing delivered ({type(e).__name__})", "deliveries": []}


def _gate(d: dict, sub: dict, directory: dict, today: str) -> dict:
    from data_provenance import current_lease, derive, route, source_envelope
    from oversight import dlp_scan
    from security_labels import canonical, sio_label, stanag4778, xml
    cfg = _cfg()
    order = d["pv"]["rings"]["order"]
    age = (datetime.fromisoformat(today + "T12:00:00") - datetime.fromisoformat(directory["_meta"]["synced"])).total_seconds() / 3600
    if age > cfg["directory_max_age_hours"]:
        return {"result": "tempfail", "reason": "recipient directory is stale; retry after the next sync", "deliveries": []}
    purpose = sub["purpose"]
    for unit in sub.get("links", []):        # 1. the sender must hold what they link, uniform answer
        if not all(current_lease(d, s, sub["sender"], purpose, today) for s in unit["sources"]):
            return {"result": "rejected", "code": "link-not-available", "request": _ref(sub["sender"], len(sub.get("links", []))),
                    "deliveries": []}
    for att in sub.get("attachments", []):   # 3. attachments are cited units or refused
        if att.get("encrypted") or att.get("depth", 0) > cfg["max_archive_depth"]:
            return {"result": "rejected", "code": "attachment-unscannable", "deliveries": []}
        if not att.get("unit"):
            return {"result": "rejected", "code": "attachment-not-a-unit", "hint": "share it as a linked unit", "deliveries": []}
    key = cfg["dlp_key"].encode()
    scan = dlp_scan(sub["subject"] + "\n" + sub["body"], "Internal", key)
    personal = set(scan["counts"]) & {"email", "iban", "phone"}
    cited_personal = any(d["dp"]["products"][s]["label"] != "Internal" for u in sub.get("links", []) for s in u["sources"])
    if personal and not cited_personal:   # 4. personal data the message does not cite
        return {"result": "held-for-sender", "code": "uncited-personal-data", "found": sorted(personal), "deliveries": []}
    body_unit = source_envelope(d, cfg["body_product"], as_of=today, subject={"message": _ref(sub["sender"], sub["subject"], sub["body"])})
    env = derive(d, list(sub.get("links", [])) + [body_unit], sub["sender"], "compose message", at=today)
    recipients, refusals = resolve_recipients(sub["addresses"], directory, cfg)
    deliveries = [{"to": r["to"], "decision": "refused", "code": r["code"], "request": _ref(r["to"], env["digest"])} for r in refusals]
    for r in recipients:                      # 6. one decision per recipient
        widening = order.index(r["ring"]) > order.index(sub["sender_ring"])
        req = {"kind": "release" if widening or r["external"] else "access", "target_ring": r["ring"] if widening or r["external"] else sub["sender_ring"],
               "purpose": purpose, "requester": sub["sender"]} | ({"reader": r["principal"]} if r["principal"] and not r["external"] else {})
        req |= {k: sub[k] for k in ("band", "site_band") if k in sub}
        dec = route(d, env, req, today)
        row = {"to": r["to"], "decision": {"allowed-by-policy": "deliver", "needs-approval": "hold", "refused": "refused"}[dec["decision"]],
               "request": _ref(r["to"], env["digest"])}
        if dec["decision"] == "needs-approval":
            row |= {"approvers": dec["approvers"], "sla_hours": dec["sla_hours"]}
        if dec["decision"] == "refused":
            row |= {"code": "policy-refused"}
        deliveries.append(row)
    lab = canonical(env)
    restricted = env["label"] == "Restricted"
    headers = {"SIO-Label": sio_label(lab).split(": ", 1)[1], "X-VDH-Binding": xml_digest(stanag4778(lab, env))}
    bounces = [{"to": sub["sender"], "about": x["to"], "code": x["code"], "request": x["request"]} for x in deliveries if x["decision"] == "refused"]
    return {"result": "processed", "envelope": env, "subject": cfg["neutral_subject"][env["label"]] if restricted else sub["subject"],
            "headers": headers, "deliveries": deliveries, "bounces": bounces, "stored": "ciphertext under the conversation product key"}


def xml_digest(binding_xml: str) -> str:
    """The binding travels by digest in the header; the container itself is stored with the message."""
    return "sha256:" + hashlib.sha256(binding_xml.encode()).hexdigest()
