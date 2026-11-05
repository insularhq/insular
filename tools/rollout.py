"""Progressive, scoped enforcement: which mode a control is in for a subject on a day, what a focal-point deny becomes
in that mode, whether a rollout may advance, and which loud notices are due. Model: platform/enforcement-rollout.yaml.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXPERIENCE = {"warn", "enforce", "default", "on"}


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "enforcement-rollout.yaml").read_text(encoding="utf-8"))


def _d(x) -> date:
    return x if isinstance(x, date) else date.fromisoformat(str(x))


def mode_on(rollout: dict, day: date, modes: list[str]) -> str:
    current = modes[0]
    for s in rollout["stages"]:
        if _d(s["from"]) <= day:
            current = s["mode"]
    return current


def validate(rollout: dict, cfg: dict) -> list[str]:
    modes = list(cfg["feature_modes"] if "feature" in rollout else cfg["control_modes"])
    errs, rid = [], rollout["id"]
    st = rollout["stages"]
    order = [modes.index(s["mode"]) for s in st]
    if order != sorted(order) or len(set(order)) != len(order):
        errs.append(f"{rid}: stages must strictly tighten (no skipping back, no repeats)")
    dates = [_d(s["from"]) for s in st]
    if dates != sorted(dates):
        errs.append(f"{rid}: stage dates must not go backwards")
    first_seen = {s["mode"]: _d(s["from"]) for s in reversed(st)}
    for s in st:
        if s["mode"] in EXPERIENCE:
            ann = first_seen.get("announce")
            if ann is None or (_d(s["from"]) - ann).days < cfg["notice_days"]:
                errs.append(f"{rid}: {s['mode']} on {s['from']} is not announced {cfg['notice_days']} days ahead")
    if "enforce" in first_seen:
        seen = [first_seen[m] for m in ("observe", "warn") if m in first_seen]
        if not seen or (first_seen["enforce"] - min(seen)).days < cfg["min_observe_days"]:
            errs.append(f"{rid}: enforce needs {cfg['min_observe_days']} days of observe or warn first")
    kind = rollout["scope"]["kind"]
    if kind not in cfg["scopes"]:
        errs.append(f"{rid}: unknown scope {kind}")
    elif rollout["signed_by"]["role"] != cfg["decision_makers"][kind]["role"]:
        errs.append(f"{rid}: a {kind} rollout is signed by {cfg['decision_makers'][kind]['role']}, not {rollout['signed_by']['role']}")
    for e in rollout.get("exemptions", []):
        if not e.get("until") or not e.get("reason"):
            errs.append(f"{rid}: exemption for {e.get('subject')} needs a reason and an expiry")
    return errs


def effective(cfg: dict, control: str, scope_chain: list[tuple[str, str]], day: date) -> str:
    """The mode for a subject whose scopes are scope_chain [(kind, id), ...]: the strictest applicable stage.
    Overlays only tighten, so the platform floor can never be lowered by a more specific scope."""
    modes = list(cfg["control_modes"])
    applicable = [r for r in cfg["rollouts"] if r.get("control") == control and
                  ((r["scope"]["kind"], r["scope"]["id"]) in scope_chain or r["scope"]["kind"] == "platform")]
    return max((mode_on(r, day, modes) for r in applicable), key=modes.index, default="off")


def apply(decision: dict, mode: str, subject: str, rollout: dict | None, day: date) -> dict:
    """What a focal-point decision becomes under the rollout mode. Allows pass unchanged."""
    if decision["decision"]:
        return {"allow": True, "mode": mode, "record": None}
    if mode == "off":
        return {"allow": True, "mode": mode, "record": None}
    if mode in ("announce", "observe"):
        return {"allow": True, "mode": mode, "record": {"would_deny": subject, "reasons": decision["reasons"]}}
    enforce_from = next((s["from"] for s in (rollout or {}).get("stages", []) if s["mode"] == "enforce"), None)
    if mode == "warn":
        msg = f"this will be blocked from {enforce_from}: {(rollout or {}).get('fix', '')}".strip()
        return {"allow": True, "mode": mode, "warning": f'Warning: 299 - "{msg}"',
                "record": {"would_deny": subject, "reasons": decision["reasons"]}}
    for e in (rollout or {}).get("exemptions", []):
        if e["subject"] == subject and _d(e["until"]) >= day:
            return {"allow": True, "mode": mode, "record": {"exempted": subject, "until": str(e["until"])}}
    return {"allow": False, "mode": mode, "record": {"denied": subject, "reasons": decision["reasons"]}}


def readiness(rollout: dict, day: date, modes: list[str], observed: int, would_deny: int) -> dict:
    """Whether the next stage may take effect on its date. Moving to enforce with more would-denies than accepted holds."""
    nxt = next((s for s in rollout["stages"] if _d(s["from"]) > day), None)
    if nxt is None:
        return {"next": None, "advance": False, "reason": "final stage reached"}
    rate = would_deny / observed if observed else 1.0
    limit = rollout["readiness"]["max_would_deny_rate"]
    if nxt["mode"] == "enforce" and rate > limit:
        return {"next": nxt, "advance": False, "hold": True,
                "reason": f"would block {would_deny} of {observed} ({rate:.0%}), above the accepted {limit:.0%}: decision card to {rollout['signed_by']['role']}"}
    return {"next": nxt, "advance": True, "reason": f"would block {would_deny} of {observed} ({rate:.0%}), within {limit:.0%}"}


def notices(cfg: dict, rollout: dict, day: date, affected: dict[str, int] | None = None) -> list[dict]:
    """Loud announcements due today: a countdown before every experience-changing stage, plus personal notices."""
    out = []
    scope = f"{rollout['scope']['kind']} {rollout['scope']['id']}"
    for s in rollout["stages"]:
        if s["mode"] not in EXPERIENCE:
            continue
        left = (_d(s["from"]) - day).days
        if left in cfg["countdown_days"]:
            verb = "blocks" if s["mode"] == "enforce" else "warns"
            when = "today" if left == 0 else f"in {left} day{'s' if left != 1 else ''}"
            n = len(affected or {})
            text = f"{rollout['title']}: {when} ({s['from']}) the check {verb} for {scope}."
            if n:
                text += f" {n} would be affected today."
            out.append({"audience": scope, "channels": cfg["channels"], "text": text + f" Fix: {rollout['fix']}"})
            for subject, count in sorted((affected or {}).items()):
                out.append({"audience": subject, "channels": ["mail", "push", "portal-banner"],
                            "text": f"{rollout['title']} {verb} {when}; you were affected {count} time(s) this week. Fix: {rollout['fix']}"})
    return out
