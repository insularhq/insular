"""Time inputs to leases and freshness checks.

- utc(): every timestamp is read as aware UTC; a naive value counts as UTC, so mixing naive and aware values never
  crashes a validator (it used to raise TypeError instead of failing closed).
- future(): a value dated later than now plus the allowed clock skew is refused, so a future-dated head, register or
  signal never ages.
- floor(): where a validator keeps a watermark (the latest time it has accepted), now never goes below it.

The skew is data: policies/time-gating.yaml token_contract.clock_skew_s.

Residual: a rolled-back clock cannot be detected from a caller's `now` alone. Only a watermark limits it, and signed
time is what closes it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


@lru_cache(maxsize=1)
def skew() -> timedelta:
    tg = yaml.safe_load((ROOT / "policies" / "time-gating.yaml").read_text(encoding="utf-8"))
    return timedelta(seconds=int(tg["token_contract"]["clock_skew_s"]))


def utc(x) -> datetime:
    """A datetime or ISO 8601 string as aware UTC; anything else raises TypeError or ValueError."""
    if isinstance(x, str):
        x = datetime.fromisoformat(x.replace("Z", "+00:00"))
    if not isinstance(x, datetime):
        raise TypeError(f"not a timestamp: {x!r}")
    return x.replace(tzinfo=timezone.utc) if x.tzinfo is None else x.astimezone(timezone.utc)


def future(at, now) -> bool:
    """True when `at` lies beyond now plus the allowed skew."""
    return utc(at) - utc(now) > skew()


def floor(now, watermark=None) -> datetime:
    """now as aware UTC, never below the watermark: a clock set back cannot make old inputs young again."""
    n = utc(now)
    return n if watermark is None else max(n, utc(watermark))



# Offline time (access-lifecycle.yaml ddil.time). Two readings: the wall clock, and the anchor: a trusted time recorded
# with the boot clock reading at that moment, plus the boot clock since. Within the skew the wall clock stands; beyond
# it the later reading decides, so a wall clock set back or held still keeps nothing alive. Ends are judged on that
# trusted time, widenings (starts) on the earlier reading. A reboot restarts the boot clock and loses the anchor: until
# authenticated fresh time arrives, nothing is live and only reductions apply. An end is acted on late by at most the
# skew.

def _skew_s(skew_s) -> float:
    return skew().total_seconds() if skew_s is None else skew_s


def _readings(wall, anchor_wall, since_anchor_s):
    w = utc(wall)
    a = None if anchor_wall is None or since_anchor_s is None else utc(anchor_wall) + timedelta(seconds=since_anchor_s)
    return w, a


def trusted(wall, anchor_wall=None, since_anchor_s=None, skew_s=None) -> tuple[datetime, bool]:
    """(the trusted time, whether the two readings disagree by more than the skew). Within the skew the wall clock
    stands; beyond it the later reading decides (a wall clock set forward stands too, and ends come early)."""
    w, a = _readings(wall, anchor_wall, since_anchor_s)
    if a is not None and abs((a - w).total_seconds()) > _skew_s(skew_s):
        return max(w, a), True
    return w, False


def end_time(wall, anchor_wall=None, since_anchor_s=None, skew_s=None) -> datetime:
    """The time an end (lease, grant, cached right, the isolation horizon) is judged at."""
    return trusted(wall, anchor_wall, since_anchor_s, skew_s)[0]


def widen_time(wall, anchor_wall=None, since_anchor_s=None) -> datetime:
    """The time a widening is judged at: the earlier reading, so clock error only ever narrows."""
    w, a = _readings(wall, anchor_wall, since_anchor_s)
    return w if a is None else min(w, a)


def anchor_at_verify(signed_at, wall, anchor_wall=None, since_anchor_s=None, skew_s=None) -> datetime:
    """The new anchor when a signed object verifies in the same boot: the trusted time at that moment, never the raw
    wall reading, and never earlier than the object's own signed time. A signed time beyond the trusted time plus the
    skew is refused. After a reboot a signed object does not anchor; authenticated fresh time does."""
    now = end_time(wall, anchor_wall, since_anchor_s, skew_s)
    if (utc(signed_at) - now).total_seconds() > _skew_s(skew_s):
        raise ValueError(f"signed time {signed_at} lies beyond the trusted time {now} plus the allowed skew")
    return max(now, utc(signed_at))


def ratchet(wall, anchor_wall, since_anchor_s, skew_s=None) -> datetime:
    """The anchor recorded at every wake (at most an hour apart) with the boot reading: the later of the two raw
    readings, never the skew-tolerant trusted time, so time one reading loses is never reused and small differences
    never accumulate. skew_s is accepted for symmetry and not used: the ratchet never tolerates a lag."""
    w, a = _readings(wall, anchor_wall, since_anchor_s)
    return w if a is None else max(w, a)


def live(not_after, wall, anchor_wall=None, since_anchor_s=None, rebooted_since_anchor=False, skew_s=None) -> bool:
    """True while a right ending at not_after may still be used offline. Without an anchor (none yet, or lost to a
    reboot) nothing is live until authenticated fresh time restores it; reductions are never gated by this."""
    if rebooted_since_anchor or anchor_wall is None or since_anchor_s is None:
        return False
    return end_time(wall, anchor_wall, since_anchor_s, skew_s) < utc(not_after)
