"""Temporary Isle election and smart meshing (ADR-0116): which PoP acts as the local centre when PoPs see
each other but no Isle. Path failover through a peer is the overlay's job (SD-WAN or dynamic routing), not this
module's.

Like OSPF's designated-router election: highest priority wins, ties go to the highest PoP UID, priority 0 is never
eligible, and a stand-in that holds a live lease is not preempted by a better-ranked newcomer. Only PoPs in the same
parent site ring with a current membership lease take part. Any reachable Isle ends the role.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Pop:
    uid: str                 # persistent unique identifier (ADR-0096); compared as a string, so use one fixed format
    ring_site: str           # the parent site ring it is a member of
    member_until: datetime   # end of its membership lease (ADR-0106)
    priority: int = 1        # 0 = never stands in


def rank(p: Pop) -> tuple[int, str]:
    return (p.priority, p.uid)


def eligible(pops: list[Pop], ring: str, now: datetime) -> list[Pop]:
    return sorted((p for p in pops if p.ring_site == ring and p.member_until > now and p.priority > 0),
                  key=rank, reverse=True)


def elect(pops: list[Pop], ring: str, now: datetime, isle_reachable: bool,
          holder: str | None = None, holder_lease_live: bool = False) -> dict:
    """Return {stand_in, backup, reason} for one partition of PoPs that can reach each other."""
    if isle_reachable:
        return {"stand_in": None, "backup": None, "reason": "an Isle is reachable: no stand-in"}
    cand = eligible(pops, ring, now)
    if not cand:
        return {"stand_in": None, "backup": None, "reason": "no eligible PoP"}
    uids = [p.uid for p in cand]
    if holder in uids and holder_lease_live:
        rest = [u for u in uids if u != holder]
        return {"stand_in": holder, "backup": rest[0] if rest else None, "reason": "non-preemptive: the holder keeps a live lease"}
    return {"stand_in": uids[0], "backup": uids[1] if len(uids) > 1 else None, "reason": "highest priority, then highest UID"}


def merge(a: dict, b: dict, pops: dict[str, Pop]) -> str | None:
    """Two partitions meet, each with a stand-in: the lower-ranked one yields."""
    sa, sb = a.get("stand_in"), b.get("stand_in")
    if not sa or not sb:
        return sa or sb
    return max((sa, sb), key=lambda u: rank(pops[u]))
