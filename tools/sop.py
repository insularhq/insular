"""Standard operating procedures as code (ADR-0159): check the register, plan a run, run it through the one execution
path, and undo it.

A procedure (platform/sops.yaml) is walked through by a person (wizard) or runs on its own (automatic). Either way every
action step goes through tools/automate.py (policy decision, autonomy level, approval, hash-chained record), every run
is announced while it runs, and every action has a way back. Agents only propose a run (platform/automation.yaml
agent_surface). Usage: python tools/sop.py (checks the register).
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from autonomy import decide as autonomy_level  # noqa: E402
from automate import run as execute_path  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
KINDS = {"check", "action", "verify", "inform"}
UNATTENDED = {"notify", "autonomous"}


def load(root: Path = ROOT) -> dict:
    y = lambda rel: yaml.safe_load((root / rel).read_text(encoding="utf-8"))
    return {"sops": y("platform/sops.yaml"), "autonomy": y("governance/autonomy.yaml"),
            "classes": y("platform/observability.yaml")["events_and_alarms"]["alert_classes"],
            "automation": y("platform/automation.yaml")}


def check(d: dict) -> list[str]:
    errs = []
    reg, auto = d["sops"], d["autonomy"]
    actions, tiers = auto["actions"], set(auto["max_autonomy"])
    channels = set(reg["announce_channels"])
    for sid, s in reg["sops"].items():
        trig = s.get("trigger", {})
        if trig.get("alert_class") and trig["alert_class"] not in d["classes"]:
            errs.append(f"{sid}: unknown alert class {trig['alert_class']}")
        if not trig:
            errs.append(f"{sid}: no trigger")
        if s.get("tier") not in tiers:
            errs.append(f"{sid}: unknown tier {s.get('tier')}")
        if s.get("mode") not in ("wizard", "automatic"):
            errs.append(f"{sid}: mode must be wizard or automatic")
        ann = set(s.get("announce", []))
        if "pane" not in ann or ann - channels:
            errs.append(f"{sid}: announce must include the pane and only known channels")
        ids = [st.get("id") for st in s.get("steps", [])]
        if len(ids) != len(set(ids)) or not ids:
            errs.append(f"{sid}: steps need unique ids")
        if not any(st.get("kind") == "verify" for st in s.get("steps", [])) and s.get("mode") == "automatic":
            errs.append(f"{sid}: an automatic procedure verifies its result")
        for st in s.get("steps", []):
            if st.get("kind") not in KINDS:
                errs.append(f"{sid}.{st.get('id')}: unknown step kind {st.get('kind')}")
            if st.get("kind") != "action":
                continue
            a = st.get("action")
            if a not in actions:
                errs.append(f"{sid}.{st['id']}: unknown action {a}")
                continue
            undo = st.get("undo")
            if undo is None:
                errs.append(f"{sid}.{st['id']}: every action names its undo")
            elif undo == "none":
                if not st.get("undo_reason"):
                    errs.append(f"{sid}.{st['id']}: undo none needs a reason")
                if actions[a]["direction"] == "increase":
                    errs.append(f"{sid}.{st['id']}: an action that widens access cannot go without an undo")
            elif undo not in actions:
                errs.append(f"{sid}.{st['id']}: unknown undo action {undo}")
            if s.get("mode") == "automatic":
                if not actions[a]["reversible"]:
                    errs.append(f"{sid}.{st['id']}: an irreversible action is never automatic")
                lvl = autonomy_level(auto, s["tier"], a)
                if lvl not in UNATTENDED:
                    errs.append(f"{sid}.{st['id']}: {a} is {lvl} in {s['tier']}, so the procedure must be a wizard")
        if s.get("mode") == "automatic" and not ({"alert-room", "ntfy"} & ann):
            errs.append(f"{sid}: an automatic procedure is announced beyond the pane")
    surface = d["automation"].get("agent_surface", {})
    for t in surface.get("tools", []):
        if t.get("effect") not in ("read", "propose"):
            errs.append(f"agent_surface tool {t.get('name')}: an agent tool only reads or proposes")
    return errs


def plan(sop: dict, autonomy: dict, contexts: list[str] = ()) -> list[dict]:
    """The wizard: each step with who acts. Action steps carry their level; human and gated wait for a person."""
    out = []
    for st in sop["steps"]:
        if st["kind"] == "action":
            lvl = autonomy_level(autonomy, sop["tier"], st["action"], list(contexts))
            waits = lvl in ("human", "gated", "forbidden") or sop["mode"] == "wizard"
            out.append({**st, "level": lvl, "waits_for_person": waits})
        else:
            out.append({**st, "waits_for_person": st["kind"] == "check" and sop["mode"] == "wizard"})
    return out


def run(sid: str, sop: dict, entity: str, subject: dict, autonomy: dict, policy_ok, chain: list, execute, notify,
        now: str, contexts: list[str] = ()) -> list[dict]:
    """Run the procedure's action steps through the execution path, in order; stop at the first that does not
    execute (waiting, refused) and return the records. Each record names the procedure and the step."""
    recs = []
    for st in sop["steps"]:
        if st["kind"] != "action":
            continue
        req = {"subject": subject, "action": st["action"], "tier": sop["tier"], "contexts": list(contexts),
               "target": entity, "now": now, "trace_id": f"{sid}:{entity}:{now}", "sop": sid, "step": st["id"]}
        rec = execute_path(req, autonomy, policy_ok(req), [], chain, execute, notify=notify)
        recs.append(rec)
        if not rec["result"].startswith("executed"):
            break
    return recs


def undo_plan(sop: dict, records: list[dict]) -> list[dict]:
    """The way back: the undo of every executed action, latest first; actions that restore declared state need none."""
    steps = {st["id"]: st for st in sop["steps"]}
    out = []
    for rec in reversed(records):
        st = steps.get(rec.get("step"))
        if st and rec["result"].startswith("executed") and st.get("undo") not in (None, "none"):
            out.append({"action": st["undo"], "target": rec.get("target"), "undoes": rec["hash"]})
    return out


if __name__ == "__main__":
    problems = check(load())
    for p in problems:
        print("ERROR", p)
    sys.exit(1 if problems else 0)
