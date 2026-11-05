"""Content-blind oversight for the DPO and the security officer (ADR-0097).

- oversight_view: an allowlist of envelope fields. Originator counts are suppressed below the group floor, dates are
  coarsened to the month, and digests are pseudonymised per case, so views cannot be linked across cases.
- DLP runs inside the data's ring. Detectors validate what they find (IBAN mod-97, Belgian and international phone
  formats). A verdict carries counts, a label finding and hits per registered list, never matched text and never
  fingerprints. A clean verdict means no detection, not "no personal data".
- Protected lists (exact data match) are registered by the data owner. They need a minimum size, carry a per-list
  salt and have a query budget, so they cannot serve as a membership oracle for one person.
- aggregate: oversight dashboards sum verdicts and suppress counts below the group floor.
"""
from __future__ import annotations

import hashlib
import hmac
import re

MIN_GROUP = 10
ALLOWED = ("label", "releasable_to", "purposes", "sources")
DETECTORS = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "iban": re.compile(r"\b[A-Za-z]{2}[0-9]{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,3})?\b"),
    "phone": re.compile(r"(?<![0-9A-Za-z])(?:\+32|0032|0)[ ./-]?[1-9](?:[ ./-]?[0-9]){7,8}(?![0-9])"),
}
ORDER = ("iban", "email", "phone")   # validated IBANs are masked first so other detectors never fire inside them
PERSONAL = {"email", "iban", "phone"}
LABELS = ["Internal", "Sensitive", "Restricted"]


def _iban_ok(raw: str) -> bool:
    s = re.sub(r"\s", "", raw).upper()
    if not 15 <= len(s) <= 34:
        return False
    num = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(num) % 97 == 1


def _norm(kind: str, raw: str) -> str:
    if kind == "email":
        return raw.strip().lower()
    s = re.sub(r"[\s./-]", "", raw).lower()
    if kind == "phone":
        s = re.sub(r"^(\+32|0032|0)", "32", s)
    return s


def find(content: str) -> list[tuple[str, str]]:
    """(type, normalised value) pairs, validated; stays inside the ring."""
    out, text = [], content
    for t in ORDER:
        for m in DETECTORS[t].finditer(text):
            raw = m.group(0)
            if t == "iban":
                # the pattern can swallow following words as groups ("... 6769 approved"): trim trailing groups
                # until the checksum holds or the candidate is too short to be an IBAN
                cand = raw
                while cand and not _iban_ok(cand) and len(re.sub(r"\s", "", cand)) > 15:
                    cand = re.sub(r"[ ]?[A-Za-z0-9]{1,4}$", "", cand)
                raw = cand if cand and _iban_ok(cand) else None
                if raw is None:
                    continue
                text = text.replace(raw, " " * len(raw), 1)
            out.append((t, _norm(t, raw)))
    return out


def _fp(key: bytes, salt: str, kind: str, value: str) -> str:
    return hmac.new(key, f"{salt}|{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def register_list(list_id: str, owner: str, values: list[tuple[str, str]], key: bytes, salt: str,
                  min_size: int = 50, budget: int = 100) -> dict:
    """A protected list, registered by the data owner; values are hashed inside the ring."""
    if len(set(values)) < min_size:
        raise ValueError(f"protected list {list_id}: at least {min_size} values, or it becomes a membership probe")
    prints = {_fp(key, salt, k, _norm(k, v)) for k, v in values}
    return {"id": list_id, "owner": owner, "salt": salt, "prints": prints, "budget": budget, "used": 0}


def dlp_scan(content: str, label: str, key: bytes, lists: list[dict] | None = None) -> dict:
    """The verdict that leaves the ring: counts, label finding, hits per registered list. No text, no fingerprints."""
    found = find(content)
    counts: dict[str, int] = {}
    for t, _ in found:
        counts[t] = counts.get(t, 0) + 1
    hits = {}
    for lst in lists or []:
        if lst["used"] >= lst["budget"]:
            hits[lst["id"]] = "budget-exhausted"
            continue
        lst["used"] += 1
        hits[lst["id"]] = sum(1 for t, v in found if _fp(key, lst["salt"], t, v) in lst["prints"])
    under = bool(PERSONAL & set(counts)) and LABELS.index(label) < LABELS.index("Sensitive")
    return {"counts": counts, "list_hits": hits, "finding": "under-labelled" if under else None,
            "meaning": "no detection is not the absence of personal data"}


def aggregate(verdicts: list[dict], k: int = MIN_GROUP) -> dict:
    """Totals per type over many verdicts for the oversight pane; a total below k is shown as '<k'."""
    tot: dict[str, int] = {}
    for v in verdicts:
        for t, c in v["counts"].items():
            tot[t] = tot.get(t, 0) + c
    return {t: (c if c >= k else f"<{k}") for t, c in tot.items()}


def oversight_view(d: dict, env: dict, case_key: bytes, k: int = MIN_GROUP) -> dict:
    """Allowlisted fields only; counts suppressed below k; month-level dates; per-case digest pseudonyms."""
    reg = d["dp"]["principals"]
    pseud = lambda x: hmac.new(case_key, x.encode(), hashlib.sha256).hexdigest()[:16]
    kinds = lambda xs: sorted({reg.get(x, {}).get("kind", "unknown") for x in xs if x})
    n = len(env["originators"])
    v = {f: env[f] for f in ALLOWED}
    v.update({"ref": pseud(env["digest"]), "valid_until_month": str(env["valid_until"])[:7],
              "originator_kinds": kinds(env["originators"]), "originator_count": n if n >= k else f"<{k}",
              "steps": [{"activity": s["activity"], "actor_kind": kinds([s["actor"]])[0],
                         "inputs": [pseud(i) for i in s["inputs"]], "signed": bool(s.get("signature"))}
                        for s in env["chain"]],
              "uplifted": bool(env.get("uplifted_by"))})
    return v
