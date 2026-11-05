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
