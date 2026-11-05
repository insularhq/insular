"""Policy operations checks (ADR-0092): rule lifecycle fields, by_band only tightens, bands only tighten, no rule id ever
disappears from git history, and the policy alert classes exist. Usage: python tools/policy_ops.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
BANDS = ["green", "amber", "red", "black"]
DUR = re.compile(r"^(\d+)([smhd]?)$")
UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def _y(rel: str):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def load() -> dict:
    from policy_engine import load as pload
    model, rules = pload()
    return {"ops": _y("policies/policy-ops.yaml"), "model": model, "rules": rules, "obs": _y("platform/observability.yaml")}


def magnitude(v) -> float | None:
    """Comparable size of a by_band value: durations and numbers; None when not comparable."""
    if isinstance(v, (int, float)):
        return float(v)
    m = DUR.match(str(v).strip())
    return float(m.group(1)) * UNIT[m.group(2)] if m else None


def tightening_errors(r: dict) -> list[str]:
    bb = r.get("by_band") or {}
    if not bb:
        return []
    seq = [(b, bb[b]) for b in BANDS if b in bb]   # only the bands the rule sets; green may come from by_trust
    errs = []
    if r["effect"] in ("limit",):
        mags = [(b, magnitude(v)) for b, v in seq]
        if any(m is None for _, m in mags):
            return [f"{r['id']}: by_band values of a limit must be numbers or durations"]
        for (b1, m1), (b2, m2) in zip(mags, mags[1:]):
            if m2 > m1:
                errs.append(f"{r['id']}: by_band loosens from {b1} to {b2}")
    elif r["effect"] == "require":
        order = ["allow", "allow within quota", "step-up", "deny"]
        if all(str(v) in order for _, v in seq):
            idx = [order.index(str(v)) for _, v in seq]
            errs += [f"{r['id']}: by_band loosens toward green" for a, b in zip(idx, idx[1:]) if b < a]
    return errs


def remembered(rules: list[dict]) -> list[str]:
    now = {r["id"] for r in rules}
    seen: set[str] = set()
    for f in (ROOT / "policies" / "packs").glob("*.yaml"):
        rel = f.relative_to(ROOT).as_posix()
        for rev in subprocess.run(["git", "rev-list", "HEAD", "--", rel], cwd=ROOT, capture_output=True, text=True).stdout.split():
            text = subprocess.run(["git", "show", f"{rev}:{rel}"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8").stdout
            try:
                seen |= {r["id"] for r in (yaml.safe_load(text) or {}).get("rules", []) if isinstance(r, dict) and "id" in r}
            except yaml.YAMLError:
                continue
    return sorted(seen - now)


def check(d: dict) -> list[str]:
    ops, errs = d["ops"], []
    lc = ops["lifecycle"]
    for r in d["rules"]:
        errs += [f"{r['id']}: missing {k}" for k in lc["required_on_every_rule"] if not r.get(k)]
        if r.get("status") and r["status"] not in lc["statuses"]:
            errs.append(f"{r['id']}: unknown status {r['status']}")
        errs += tightening_errors(r)
    floors = d["model"]["band_enforcement"]["floor"]
    from policy_engine import MODES
    if [MODES.index(floors[b]) for b in BANDS] != sorted(MODES.index(floors[b]) for b in BANDS):
        errs.append("band floors must only tighten from green to black")
    alerts = d["obs"]["events_and_alarms"]["alert_classes"]
    errs += [f"alert class {a} missing (ADR-0092)" for a in ("policy-deny-spike", "policy-eval-error", "rule-never-hit") if a not in alerts]
    errs += [f"rule {x}: deleted (in git history, gone now); supersede or retire instead" for x in remembered(d["rules"])]
    errs += [f"rule {rid}: names test {t}, which does not exist" for rid, t in unknown_tests(d)]
    return errs


def known_tests() -> set[str]:
    """Model tests and Rego tests: the only names a rule's tests field may use."""
    names = set(re.findall(r"^def (test_\w+)\(", (ROOT / "tests" / "test_model.py").read_text(encoding="utf-8"), re.M))
    for f in (ROOT / "policy").rglob("*_test.rego"):
        names |= set(re.findall(r"^(test_\w+)\s", f.read_text(encoding="utf-8"), re.M))
    return names


def unknown_tests(d: dict) -> list[tuple[str, str]]:
    known = known_tests()
    return [(r["id"], t) for r in d["rules"] for t in (r.get("tests") or []) if t not in known]


def untested(d: dict) -> list[str]:
    return sorted(r["id"] for r in d["rules"] if not r.get("tests"))


if __name__ == "__main__":
    data = load()
    problems = check(data)
    print(f"rules {len(data['rules'])}, untested {len(untested(data))}")
    for p in problems:
        print("ERROR", p)
    sys.exit(1 if problems else 0)
