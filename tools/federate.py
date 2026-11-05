"""Federated green light: a parent (region or central) aggregates the signed status of its children.

Each child (site, edge island, region) computes its own four-state light and signs it with its own private key; the
parent holds only public keys, so it cannot forge a child's light. The parent never trusts silence:
a child that has not reported within its offline grace is UNKNOWN; a report dated in the future or with an
unverifiable signature is RED; a child reporting from a disconnected island keeps its state but is flagged. The
parent's own light is the worst of its children and its own controls.

A signed status names its child, its audience (the parent it is addressed to) and a monotonic sequence number. The
parent keeps the last accepted sequence per child and refuses an older one, so a captured GREEN cannot be replayed
over a current RED, nor a report for another parent be reused. Presenting the same latest
report again is a re-evaluation, not a replay.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from clock import skew, utc
from signing import sign as _sign
from signing import verify

ORDER = {"GREEN": 0, "AMBER": 1, "UNKNOWN": 2, "RED": 3}


def sign(private_key, status: dict) -> str:
    """status: {child, audience, seq, overall, evaluated_at[, disconnected]}."""
    return _sign(private_key, status)


def child_state(report: dict | None, public_key, now: datetime, grace: timedelta, *, child: str, parent: str,
                last: dict | None = None) -> tuple[str, list[str], bool]:
    """last: the last report accepted from this child ({seq, signature}), or None. Returns state, flags and whether
    the report is accepted as the child's latest (authentic, addressed to this parent, newer, not from the future)."""
    try:
        return _child_state(report, public_key, now, grace, child, parent, last)
    except (KeyError, TypeError, ValueError) as e:
        return "RED", [f"malformed report: {type(e).__name__}"], False


def _child_state(report: dict | None, public_key, now: datetime, grace: timedelta, child: str, parent: str,
                 last: dict | None) -> tuple[str, list[str], bool]:
    if report is None:
        return "UNKNOWN", ["never reported"], False
    if not verify(public_key, report["signature"], report["status"]):
        return "RED", ["signature does not verify"], False
    st = report["status"]
    if st["audience"] != parent or st["child"] != child:
        return "RED", [f"report addressed from {st['child']} to {st['audience']}, not from {child} to {parent}"], False
    seq = st["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise TypeError("seq")
    if last and (seq < last["seq"] or (seq == last["seq"] and report["signature"] != last["signature"])):
        return "RED", [f"replay: sequence {seq} is not newer than the last accepted {last['seq']}"], False
    at = utc(st["evaluated_at"])
    if at - utc(now) > skew():
        return "RED", [f"report dated in the future ({at})"], False
    age = utc(now) - at
    if age > grace:
        return "UNKNOWN", [f"silent for {age}, longer than offline grace {grace}"], True
    flags = ["reporting from a disconnected island (store-and-forward)"] if st.get("disconnected") else []
    state = st["overall"]
    if state not in ORDER:
        return "RED", [f"unknown state {state!r}"], True
    return state, flags, True


def aggregate(children: dict[str, dict | None], public_keys: dict, graces: dict[str, timedelta],
              own: str, now: datetime, *, parent: str, seen: dict) -> dict:
    """seen: child -> last accepted {seq, signature}; the parent persists it and aggregate() advances it."""
    out = {}
    for name in children:
        rep = children[name]
        st, flags, accepted = child_state(rep, public_keys[name], now, graces[name], child=name, parent=parent,
                                          last=seen.get(name))
        if accepted:
            seen[name] = {"seq": rep["status"]["seq"], "signature": rep["signature"]}
        out[name] = {"state": st, "flags": flags}
    overall = max([own] + [c["state"] for c in out.values()], key=ORDER.get)
    return {"overall": overall, "children": out}
