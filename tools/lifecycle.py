"""Lifecycle order for an instance of a given size: bootstrap (dependencies first), decommission (reverse)."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SIZES = ["S", "M", "L"]


def components(size: str, root: Path = ROOT) -> list[str]:
    sz = yaml.safe_load((root / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    out = [c["component"] for c in sz["core"]]
    for m in sz["modules"].values():
        if m["size"] in SIZES and SIZES.index(m["size"]) <= SIZES.index(size):
            out += [c["component"] for c in m.get("components", [])]
    return out


def bootstrap_order(comps: list[str], needs: dict[str, list[str]]) -> list[str]:
    """Topological order; raises on a missing dependency entry or a cycle."""
    order, state = [], {}

    def visit(c, stack):
        if c == "host":
            return
        if c not in needs:
            raise KeyError(f"no lifecycle entry for {c}")
        if state.get(c) == "done":
            return
        if state.get(c) == "active":
            raise ValueError("cycle: " + " -> ".join(stack + [c]))
        state[c] = "active"
        for d in needs[c]:
            if d != "host" and d not in comps:
                raise KeyError(f"{c} needs {d}, which is not in this size")
            visit(d, stack + [c])
        state[c] = "done"
        order.append(c)
    for c in comps:
        visit(c, [])
    return order


def decommission_order(order: list[str]) -> list[str]:
    return list(reversed(order))
