"""Provenance and supportability: is every component alive, supportable and reachable through an EU or European path?

Deterministic core (check, flags, eu_path, report) over catalog/provenance.yaml and catalog/interfaces.yaml; a thin
network adapter (refresh) re-measures the signals from the forges. The check fails on an archived or stale runtime
component, an unaccepted bus factor, and a sovereignty gap that is not listed with its mitigation.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(root: Path = ROOT) -> tuple[dict, dict]:
    prov = yaml.safe_load((root / "catalog" / "provenance.yaml").read_text(encoding="utf-8"))
    iface = yaml.safe_load((root / "catalog" / "interfaces.yaml").read_text(encoding="utf-8"))["capabilities"]
    return prov, iface


def _days(since: str | None, today: date) -> float:
    if not since:
        return float("inf")
    return (today - date.fromisoformat(str(since)[:10])).days


def flags(name: str, prov: dict, today: date) -> list[str]:
    c, pol = prov["components"][name], prov["policy"]
    s = c.get("signals")
    if s is None:   # own code
        return []
    out = []
    if s.get("archived"):
        out.append("archived")
    if min(_days(s.get("release_date"), today), _days(s.get("last_activity"), today)) > pol["stale_days"]:
        out.append("stale")
    authors = s.get("authors_last_100_commits")
    if authors is not None and authors < pol["bus_factor_min_authors"]:
        out.append("bus-factor")
    if c["region"] == "non-eu" and c["kind"] in ("company", "individual"):
        out.append("relicence-risk")
    return out


def _own_path(name: str, prov: dict) -> str | None:
    c = prov["components"][name]
    if c["region"] in ("eu", "europe", "own"):
        return f"steward {c['steward']} ({c['home']})"
    local = set(prov["eu_countries"]) | set(prov["europe_countries"]) | {"BE"}
    for s in c.get("support", []):
        if s.rsplit("(", 1)[-1].rstrip(")") in local:
            return f"support {s}"
    if name in prov.get("self_supported", {}):
        return "self-supported by VDHome"
    return None


def eu_path(name: str, prov: dict, iface: dict) -> str | None:
    """The EU or European path for a component, or None: its own, or one through an alternate in the same capability."""
    own = _own_path(name, prov)
    if own:
        return own
    for cap, spec in iface.items():
        if name in spec["implementations"]:
            for alt in spec.get("alternatives", []):
                if alt in prov["components"] and "stale" not in flags(alt, prov, date.fromisoformat(prov["checked"])):
                    p = _own_path(alt, prov)
                    if p:
                        return f"exit to {alt} ({p})"
    return None


def check(prov: dict, iface: dict, today: date) -> list[str]:
    errors = []
    comps = prov["components"]
    runtime = {c for spec in iface.values() for c in spec["implementations"]}
    for cap, spec in iface.items():
        for c in spec["implementations"] + spec.get("alternatives", []):
            if c not in comps:
                errors.append(f"{cap}: {c} has no provenance entry")
    for name, c in comps.items():
        if c["role"] == "runtime" and name not in runtime and name not in ("Coraza", "OWASP CRS"):
            errors.append(f"{name}: marked runtime but implements no capability")
        f = flags(name, prov, today)
        if "archived" in f:
            errors.append(f"{name}: archived")
        if "stale" in f and c["role"] == "runtime":
            errors.append(f"{name}: stale runtime component (no release or commit in {prov['policy']['stale_days']} days)")
        if "bus-factor" in f and c["role"] == "runtime" and name not in prov.get("bus_factor_accepted", {}):
            errors.append(f"{name}: bus factor below {prov['policy']['bus_factor_min_authors']} authors and not accepted")
    gaps = {n for n, c in comps.items() if c["role"] == "runtime" and eu_path(n, prov, iface) is None}
    accepted = set(prov.get("sovereignty_gaps_accepted", {}))
    errors += [f"{n}: sovereignty gap not accepted (no EU or European path)" for n in sorted(gaps - accepted)]
    errors += [f"{n}: listed as a sovereignty gap but has an EU or European path now: remove it" for n in sorted(accepted - gaps)]
    return errors


def report(prov: dict, iface: dict, today: date) -> dict:
    comps = prov["components"]
    by_region: dict[str, int] = {}
    for c in comps.values():
        if c["role"] == "runtime":
            by_region[c["region"]] = by_region.get(c["region"], 0) + 1
    return {
        "runtime_by_region": by_region,
        "flags": {n: f for n in comps if (f := flags(n, prov, today))},
        "eu_paths": {n: eu_path(n, prov, iface) for n, c in comps.items() if c["role"] == "runtime"},
    }


# --- network adapter: re-measure signals (not used by the tests) ---------------------------------------------------

def _gh(path: str):
    r = subprocess.run(["gh", "api", path], capture_output=True, text=True, encoding="utf-8")
    return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None


def refresh(prov: dict, today: date) -> dict:
    for name, c in prov["components"].items():
        src = c.get("source") or ""
        if src.split("/", 1)[0] != "github.com":
            continue
        repo = src.removeprefix("github.com/")
        meta = _gh(f"repos/{repo}")
        if not meta:
            continue
        rel = _gh(f"repos/{repo}/releases/latest") or {}
        commits = _gh(f"repos/{repo}/commits?per_page=100") or []
        authors = {(x.get("author") or {}).get("login") or x["commit"]["author"]["name"] for x in commits}
        oldest = commits[-1]["commit"]["committer"]["date"][:10] if commits else None
        c["signals"] = {"last_release": rel.get("tag_name", c["signals"].get("last_release")),
                        "release_date": (rel.get("published_at") or "")[:10] or c["signals"].get("release_date"),
                        "last_activity": meta["pushed_at"][:10], "authors_last_100_commits": len(authors),
                        "days_for_last_100_commits": (today - date.fromisoformat(oldest)).days if oldest else None,
                        "archived": meta["archived"]}
    prov["checked"] = today.isoformat()
    return prov


def main() -> int:
    prov, iface = load()
    today = date.today()
    if sys.argv[1:] == ["refresh"]:
        prov = refresh(prov, today)
        print("refreshed; write back by hand after review (the YAML keeps its comments in git)")
        print(json.dumps({n: c.get("signals") for n, c in prov["components"].items()}, indent=1)[:4000])
        return 0
    errs = check(prov, iface, date.fromisoformat(prov["checked"]))
    print(json.dumps(report(prov, iface, date.fromisoformat(prov["checked"])), indent=1))
    for e in errs:
        print("ERROR", e)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
