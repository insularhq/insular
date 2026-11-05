"""Intent as code: completeness, enforcement and anti-pattern detection, plus the generated context for implementers.

check(): every goal has a fitness function and a decision record; every principle names enforcing tests that exist;
every anti-pattern has a detector (test, regex, path, or an explicit 'review'); regex and path detectors run over the
repository. render(): intent/CONTEXT.md, the brief every implementer (including an LLM) reads first.
"""

from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SCAN_EXCLUDE = ("intent/", ".git/", ".pytest_cache/", "__pycache__/", ".hypothesis/")   # .hypothesis: Hypothesis caches
TESTS = "tests/"


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "intent" / "intent.yaml").read_text(encoding="utf-8"))


def test_names(root: Path = ROOT) -> set[str]:
    names = set()
    for f in (root / "tests").glob("test_*.py"):
        names |= set(re.findall(r"^def (test_\w+)\(", f.read_text(encoding="utf-8"), re.M))
    return names


def repo_files(root: Path = ROOT, include_tests: bool = False):
    """Every non-binary file, whatever its suffix (a key saved as .pem or .key is still found)."""
    for p in root.rglob("*"):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or rel.startswith(SCAN_EXCLUDE) or (rel.startswith(TESTS) and not include_tests):
            continue
        if bytes(1) in p.read_bytes()[:4096]:
            continue
        yield rel, p


def detect(intent: dict, root: Path = ROOT) -> list[str]:
    hits = []
    for ap_id, ap in intent["anti_patterns"].items():
        d = ap["detector"]
        if d["type"] == "regex":
            rx = re.compile(d["pattern"])
            for rel, p in repo_files(root, d.get("include_tests", False)):
                for n, line in enumerate(p.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{ap_id} {ap['text']}: {rel}:{n}")
        elif d["type"] == "path":
            for rel, _ in repo_files(root):
                if fnmatch.fnmatch(rel, d["glob"]) and not any(fnmatch.fnmatch(rel, a) for a in d.get("allow", [])):
                    hits.append(f"{ap_id} {ap['text']}: {rel}")
    return hits


def check(root: Path = ROOT) -> list[str]:
    intent = load(root)
    errors = []
    tests = test_names(root)
    adrs = {p.name.split("-")[0] + "-" + p.name.split("-")[1] for p in (root / "intent" / "decisions").glob("ADR-*.md")}
    for gid, g in intent["goals"].items():
        for key in ("fitness", "target", "source", "decided_by"):
            if not g.get(key):
                errors.append(f"{gid}: missing {key}")
        if g.get("decided_by") not in adrs:
            errors.append(f"{gid}: decision record {g.get('decided_by')} not found")
        if g.get("source") and not (root / g["source"]).exists():
            errors.append(f"{gid}: fitness source {g['source']} does not exist")
    for pid, p in intent["principles"].items():
        if not p.get("enforced_by"):
            errors.append(f"{pid}: not enforced by any test")
        for t in p.get("enforced_by", []):
            if t not in tests:
                errors.append(f"{pid}: enforcing test {t} does not exist")
        if p.get("decided_by") not in adrs:
            errors.append(f"{pid}: decision record {p.get('decided_by')} not found")
    for aid, a in intent["anti_patterns"].items():
        d = a.get("detector") or {}
        if d.get("type") not in ("regex", "path", "test", "review"):
            errors.append(f"{aid}: no detector")
        if d.get("type") == "test" and d.get("name") not in tests:
            errors.append(f"{aid}: detector test {d.get('name')} does not exist")
    return errors + detect(intent, root)


def render(root: Path = ROOT) -> str:
    i = load(root)
    out = ["# Implementer brief (generated from intent/intent.yaml; do not edit)", "",
           f"Intent version {i['version']}. Read this before any change. Regenerate with `python tools/intent.py render`.",
           "", "## Mission", "", i["mission"].strip(), "", "## Goals", ""]
    out += [f"- **{k}** {g['text']} (fitness: {g['fitness']}; target {g['target']})" for k, g in i["goals"].items()]
    out += ["", "## Non-goals (never do these)", ""] + [f"- {n}" for n in i["non_goals"]]
    out += ["", "## Principles and their enforcing checks", ""]
    out += [f"- **{k}** {p['text']} [{', '.join(p['enforced_by'])}]" for k, p in i["principles"].items()]
    out += ["", "## Anti-patterns (the gate rejects these)", ""]
    out += [f"- **{k}** {a['text']} ({a['detector']['type']})" for k, a in i["anti_patterns"].items()]
    out += ["", "## How to work", "",
            "1. Work only inside the scope of the task you were given; honour what it puts out of scope.",
            "2. Write or extend the acceptance tests first; never weaken, skip or delete an existing check.",
            "3. Run the repository's gate and report its output verbatim; done means the gate is green.",
            "4. If the task conflicts with intent, stop and ask; intent changes need a new ADR in `intent/decisions/`.",
            "5. State sources for every fact (versions, licences, laws); mark anything unverified as unverified.", ""]
    return "\n".join(out)


if __name__ == "__main__":
    if sys.argv[1:] == ["render"]:
        (ROOT / "intent" / "CONTEXT.md").write_text(render(), encoding="utf-8", newline="\n")
        print("intent/CONTEXT.md written")
    else:
        errs = check()
        print("\n".join(errs) or "intent: complete, enforced, no anti-patterns detected")
        sys.exit(1 if errs else 0)
