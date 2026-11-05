"""Find every cycle in the administration dependency graph (runtime dependencies plus repair needs) and require each
cycle to contain at least one repair edge with a declared out-of-band break path."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(root: Path = ROOT) -> dict:
    return yaml.safe_load((root / "platform" / "bootstrap.yaml").read_text(encoding="utf-8"))


def cycles(edges: dict[str, list[str]]) -> list[list[str]]:
    found, seen = [], set()

    def dfs(node, path):
        for nxt in edges.get(node, []):
            if nxt in path:
                cyc = path[path.index(nxt):] + [nxt]
                key = frozenset(zip(cyc, cyc[1:]))
                if key not in seen:
                    seen.add(key)
                    found.append(cyc)
            else:
                dfs(nxt, path + [nxt])
    for n in edges:
        dfs(n, [n])
    return found


def check(b: dict) -> list[str]:
    edges = {k: list(v) for k, v in b["depends_on"].items()}
    for k, v in b["repair_needs"].items():
        edges.setdefault(k, []).extend(v)
    errs = []
    for cyc in cycles(edges):
        pairs = [f"{a}->{c}" for a, c in zip(cyc, cyc[1:])]
        if not any(p in b["breaks"] for p in pairs):
            errs.append("unbroken cycle: " + " -> ".join(cyc))
    for p in b["breaks"]:
        a, c = p.split("->")
        if c not in b["repair_needs"].get(a, []):
            errs.append(f"break {p} does not match a repair edge")
    return errs
