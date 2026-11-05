"""Sources of truth inside the stack (ADR-0077): one master per fact class and scope, declared state in git, site
facts mastered at the site, observed state never authoritative, and every fact says what a site does alone.

Usage: python tools/sources_of_truth.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ("master", "scope", "written_by", "flows_to", "wan_down", "reconcile")


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "sources-of-truth.yaml").read_text(encoding="utf-8"))


def check(d: dict) -> list[str]:
    errs = []
    scopes, kinds = set(d["scopes"]), set(d["reconcile_kinds"])
    for name, f in d["facts"].items():
        errs += [f"{name}: missing {k}" for k in REQUIRED if not f.get(k)]
        if f.get("scope") not in scopes:
            errs.append(f"{name}: unknown scope {f.get('scope')}")
        if f.get("reconcile") not in kinds:
            errs.append(f"{name}: unknown reconcile kind {f.get('reconcile')}")
        master = str(f.get("master", "")).lower()
        if master == "none" and "never authoritative" not in str(f.get("note", "")):
            errs.append(f"{name}: a fact without a master must say it is never authoritative")
        if f.get("reconcile") in ("site-mastered", "issued") and f.get("scope") != "site":
            errs.append(f"{name}: site-mastered and issued facts live at site scope")
        if f.get("reconcile") == "replicated" and f.get("scope") == "site":
            errs.append(f"{name}: a replicated fact is mastered above the site")
        if f.get("reconcile") == "generated" and master not in ("none",) and "git" not in master:
            errs.append(f"{name}: generated facts come from git")
        if "central" in str(f.get("wan_down", "")).lower():
            errs.append(f"{name}: WAN-down behaviour depends on the centre")
        for view in ("glpi", "backstage", "spog"):
            if master.startswith(view):
                errs.append(f"{name}: {view} is a view, never a master")
    return errs


if __name__ == "__main__":
    problems = check(load())
    for p in problems:
        print("ERROR", p)
    sys.exit(1 if problems else 0)
