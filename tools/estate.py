"""Physical estate: facilities, networks, tokens, HSMs, servers and shipments (inventory/estate.yaml). Checks custody
and logistics invariants and lists what is still to establish, so unknowns stay visible instead of being guessed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
UNKNOWN = "to-establish"


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "inventory" / "estate.yaml").read_text(encoding="utf-8"))


def unknowns(est: dict) -> list[str]:
    out = []
    for section in ("facilities", "networks", "hsms", "hardware_tokens", "servers"):
        for k, v in (est.get(section) or {}).items():
            out += [f"{section}.{k}.{f}" for f, x in v.items() if x == UNKNOWN]
            if v.get("exists") is False:
                out.append(f"{section}.{k}: does not exist yet")
    return out


def check(est: dict) -> list[str]:
    errs, fac = [], est["facilities"]
    for section in ("hsms", "hardware_tokens"):
        for k, v in est[section].items():
            holder = v.get("issued_to") or v.get("custodian")
            if not holder:
                errs.append(f"{k}: issued to nobody")
            if v.get("facility") not in fac:
                errs.append(f"{k}: held at an unknown facility {v.get('facility')}")
    shares = [v for v in est["hardware_tokens"].values() if "break-glass share" in v["purpose"]]
    if len({v["issued_to"] for v in shares}) != len(shares) or len({v["facility"] for v in shares}) != len(shares):
        errs.append("break-glass shares must sit with different holders at different facilities")
    hsms = list(est["hsms"].values())
    if len({h["custodian"] for h in hsms}) < len(hsms) or len({h["facility"] for h in hsms}) < len(hsms):
        errs.append("root HSMs must sit with different custodians at different facilities")
    for n, v in (est.get("networks") or {}).items():
        if v["facility"] not in fac and v["facility"] != "none":
            errs.append(f"network {n}: unknown facility")
    for s, v in (est.get("servers") or {}).items():
        if v.get("facility") not in fac:
            errs.append(f"server {s}: not placed at a known facility")
        if not v.get("tpm_ek_hash"):
            errs.append(f"server {s}: no TPM endorsement key recorded before shipping")
    for sh in est.get("shipments") or []:
        if not sh.get("seal_ids") or sh.get("packed_by") == sh.get("witnessed_by"):
            errs.append(f"shipment {sh['id']}: needs seals and a witness other than the packer")
        if sh.get("state") == "activated" and not (sh.get("received_by") and sh.get("seal_intact") is True):
            errs.append(f"shipment {sh['id']}: activated without a confirmed intact seal")
    return errs


def main() -> int:
    est = load()
    for u in unknowns(est):
        print("TO ESTABLISH", u)
    errs = check(est)
    for e in errs:
        print("ERROR", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
