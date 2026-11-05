"""Policy engine over the common policy model (policies/model.yaml) and every pack in policies/packs/.

- effective(context): the rules in force for a context (scope values, date, trust band), after time supersession and
  scope specificity; legacy keeps an old rule when the new rule's scope does not cover it.
- analyse(): conflicts (overlapping scope and time, contradictory and unresolved), discrepancies (same topic, other
  values in other scopes), gaps (register risks with neither a mitigating rule nor an accepted risk), invalid risk
  raising (no or expired acceptance, trust demand above the anchor), sunsets ahead.
Run: python tools/policy_engine.py
"""

from __future__ import annotations

import itertools
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DECISION_REQUIRED_FROM = "2026-10-14"   # ADR-0145: from here on every new rule carries its decision
BANDS = ["none", "low", "medium", "high"]


def load(root: Path = ROOT) -> tuple[dict, list[dict]]:
    model = yaml.safe_load((root / "policies" / "model.yaml").read_text(encoding="utf-8"))
    rules = []
    for p in sorted((root / "policies" / "packs").glob("*.yaml")):
        pack = yaml.safe_load(p.read_text(encoding="utf-8"))
        for r in pack["rules"]:
            rules.append({**r, "pack": pack["id"], "pack_kind": pack["kind"]})
    return model, rules


def _d(x) -> date | None:
    return None if x in (None, "") else (x if isinstance(x, date) else date.fromisoformat(str(x)))


def _valid(r: dict, day: date) -> bool:
    return _d(r["valid_from"]) <= day and (r.get("valid_until") is None or day <= _d(r["valid_until"]))


def _matches(scope: dict, ctx: dict) -> bool:
    return all(ctx.get(dim) in vals for dim, vals in (scope or {}).items())


def _specificity(r: dict) -> int:
    return len(r.get("scope") or {})


def _overlap(a: dict, b: dict) -> bool:
    """Could one context match both scopes?"""
    for dim in set(a or {}) & set(b or {}):
        if not set(a[dim]) & set(b[dim]):
            return False
    return True


def _time_overlap(a: dict, b: dict) -> bool:
    a0, b0 = _d(a["valid_from"]), _d(b["valid_from"])
    a1, b1 = _d(a.get("valid_until")) or date.max, _d(b.get("valid_until")) or date.max
    return a0 <= b1 and b0 <= a1


def _supersedes(new: dict, old: dict) -> bool:
    for s in new.get("supersedes", []) or []:
        if s["rule"] == old["id"] and _overlap(s.get("scope") or new.get("scope"), old.get("scope")):
            return True
    return False


def register_risks(model: dict) -> list[dict]:
    """All risks of the register or registers named in the model (ADR-0078 adds the infrastructure register)."""
    regs = model["risk"]["register"]
    out = []
    for rel in ([regs] if isinstance(regs, str) else regs):
        out += yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))["risks"]
    return out


def _affected_exists(x: dict) -> bool:
    kind, ident = x.get("kind"), str(x.get("id", ""))
    if kind == "capability":
        from contracts import load as cload
        return ident in cload()["contracts"]["contracts"]
    if kind == "seam":
        seams = yaml.safe_load((ROOT / "platform" / "seams.yaml").read_text(encoding="utf-8"))["seams"]
        return any(s.get("id") == ident for s in seams)
    if kind == "register":
        path, _, key = ident.partition("#")
        f = ROOT / path
        return f.exists() and (not key or f"{key}:" in f.read_text(encoding="utf-8"))
    return False


def validate(model: dict, rules: list[dict], today: date) -> list[str]:
    errs, ids = [], set()
    risks = {r["id"] for r in register_risks(model)}
    for r in rules:
        for k in model["rule_schema"]["required"]:
            if k not in r:
                errs.append(f"{r.get('id')}: missing {k}")
        if r["id"] in ids:
            errs.append(f"{r['id']}: duplicate rule id")
        ids.add(r["id"])
        if r["effect"] not in model["effects"]:
            errs.append(f"{r['id']}: unknown effect {r['effect']}")
        for dim in (r.get("scope") or {}):
            if dim not in model["scope_dimensions"]:
                errs.append(f"{r['id']}: unknown scope dimension {dim}")
        for m in r.get("mitigates", []):
            if m not in risks:
                errs.append(f"{r['id']}: mitigates unknown risk {m}")
        # ADR-0145: a rule taking effect from 2026-10-14 names who decided it, when, and the record that carries it;
        # the decision comes before the rule takes effect, and the record exists
        dec = r.get("decision")
        if dec is None and str(r.get("valid_from", "")) >= DECISION_REQUIRED_FROM:
            errs.append(f"{r['id']}: a rule from {DECISION_REQUIRED_FROM} needs a decision (by, date, record)")
        elif dec is not None:
            if not {"by", "date", "record"} <= set(dec):
                errs.append(f"{r['id']}: decision needs by, date and record")
            elif str(dec["date"]) > str(r["valid_from"]):
                errs.append(f"{r['id']}: decided on {dec['date']}, after it takes effect on {r['valid_from']}")
            elif not list((ROOT / "intent" / "decisions").glob(f"{dec['record']}-*.md")):
                errs.append(f"{r['id']}: decision record {dec['record']} not found in intent/decisions")
        for x in r.get("affects") or []:   # ADR-0146: what a rule changes must exist in the model
            if not _affected_exists(x):
                errs.append(f"{r['id']}: affects unknown {x.get('kind')} {x.get('id')}")
        anchor = model["trust_anchors"].get(r.get("anchor"))
        if anchor is None:
            errs.append(f"{r['id']}: unknown trust anchor {r.get('anchor')}")
        elif r.get("min_trust") and BANDS.index(r["min_trust"]) > BANDS.index(anchor["max_trust"]):
            errs.append(f"{r['id']}: demands trust {r['min_trust']} but its anchor {r['anchor']} gives at most {anchor['max_trust']}")
        if r.get("raises_risk"):
            acc = r.get("acceptance") or {}
            missing = [k for k in model["risk"]["acceptance_requires"] if k not in acc]
            if missing:
                errs.append(f"{r['id']}: raises risk without a complete acceptance (missing {missing})")
            elif acc["role"] not in model["risk"]["acceptance_roles"]:
                errs.append(f"{r['id']}: accepted by role {acc['role']}, not an acceptance role")
            elif _d(acc["until"]) < today:
                errs.append(f"{r['id']}: risk acceptance expired on {acc['until']}")
            if not r.get("min_trust"):
                errs.append(f"{r['id']}: raises risk without a minimum trust band")
        for s in r.get("supersedes", []) or []:
            if s["rule"] not in {x["id"] for x in rules}:
                errs.append(f"{r['id']}: supersedes unknown rule {s['rule']}")
    return errs


MODES = ["off", "announce", "observe", "warn", "enforce"]


def band_floor(model: dict | None = None) -> dict:
    model = model or yaml.safe_load((ROOT / "policies" / "model.yaml").read_text(encoding="utf-8"))
    return model["band_enforcement"]["floor"]


def mode(r: dict, band: str, floors: dict) -> str:
    """The enforcement mode of a rule in a band: its rollout stage, raised to the band's floor (only ever tighter)."""
    return MODES[max(MODES.index(r.get("rollout", "enforce")), MODES.index(floors[band]))]


def effective(rules: list[dict], ctx: dict, day: date, floors: dict | None = None) -> dict:
    """topic -> {rule, effect, parameter, mode, conflicts, blocked, residual}; ctx holds scope values, 'trust' and 'band'.
    Mirrored by policy/vdh/decide.rego; a differential test keeps the two in agreement."""
    trust = ctx.get("trust", "none")
    band = ctx.get("band") or "black"   # a missing band is the strictest, never green
    floors = floors or band_floor()
    matching = [r for r in rules if _valid(r, day) and _matches(r.get("scope"), ctx)]
    # a rule that raises risk applies only at or above its minimum trust; a rule that may not apply cannot supersede,
    # so the stricter rule it would have replaced stands
    allowed = lambda r: not r.get("raises_risk") or BANDS.index(trust) >= BANDS.index(r["min_trust"])
    blocked_all = [r for r in matching if not allowed(r)]
    cands = [r for r in matching if allowed(r)]
    cands = [r for r in cands if not any(_supersedes(n, r) for n in cands if n is not r)]
    out = {}
    for topic in sorted({r["topic"] for r in matching}):
        usable = [r for r in cands if r["topic"] == topic]
        blocked = [r["id"] for r in blocked_all if r["topic"] == topic]
        if not usable:
            out[topic] = {"rule": None, "effect": None, "parameter": None, "mode": "off", "conflicts": [], "blocked": sorted(blocked), "residual": None}
            continue
        top = max(_specificity(r) for r in usable)
        best = sorted((r for r in usable if _specificity(r) == top), key=lambda r: r["id"])

        def param(r):
            if (r.get("by_band") or {}).get(band) is not None:
                return r["by_band"][band]
            if (r.get("by_trust") or {}).get(trust) is not None:
                return r["by_trust"][trust]
            return r.get("parameter")
        vals = {f"{r['effect']}|{param(r)}" for r in best}
        out[topic] = {"rule": best[0]["id"], "effect": best[0]["effect"], "parameter": param(best[0]), "mode": mode(best[0], band, floors),
                      "conflicts": [r["id"] for r in best] if len(vals) > 1 else [], "blocked": sorted(blocked),
                      "residual": best[0].get("residual")}
    return out


def analyse(model: dict, rules: list[dict], today: date, horizon_days: int = 180) -> dict:
    conflicts, discrepancies = [], []
    for a, b in itertools.combinations(rules, 2):
        if a["topic"] != b["topic"]:
            continue
        related = _supersedes(a, b) or _supersedes(b, a)
        same = (a["effect"], a.get("parameter"), a.get("by_trust")) == (b["effect"], b.get("parameter"), b.get("by_trust"))
        if same or related:
            continue
        if _overlap(a.get("scope"), b.get("scope")) and _time_overlap(a, b) and _specificity(a) == _specificity(b):
            conflicts.append(f"{a['topic']}: {a['id']} ({a['pack']}) and {b['id']} ({b['pack']}) overlap with different effects and neither supersedes the other")
        else:
            show = lambda r: r.get("parameter") or r.get("by_trust") or r["effect"]
            discrepancies.append(f"{a['topic']}: {a['id']} = {show(a)} vs {b['id']} = {show(b)}")
    reg = register_risks(model)
    mitigated = {m for r in rules for m in r.get("mitigates", [])}
    gaps = sorted(x["id"] for x in reg if x["id"] not in mitigated and not x.get("accepted"))
    sunsets = sorted(f"{r['id']} ends {r['valid_until']}" for r in rules if r.get("valid_until") and 0 <= (_d(r["valid_until"]) - today).days <= horizon_days)
    return {"errors": validate(model, rules, today), "conflicts": conflicts, "discrepancies": discrepancies,
            "gaps": gaps, "sunsets": sunsets}


def main() -> int:
    model, rules = load()
    a = analyse(model, rules, date.today())
    for k, v in a.items():
        print(f"{k}: {len(v)}")
        for x in v:
            print(f"  {x}")
    return 1 if a["errors"] or a["conflicts"] else 0


if __name__ == "__main__":
    sys.exit(main())
