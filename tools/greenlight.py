"""Green light v0: per-control status from evidence, with confidence that decays as evidence ages.

Honest by construction:
- no evidence      -> UNKNOWN (never green);
- failed evidence  -> RED;
- passing evidence -> confidence 1.0 while fresh, then decays linearly to 0 at the tier's max age;
  GREEN at >= 0.7, AMBER below, RED when stale beyond the max age;
- overall status = the worst control status. The result is appended to a hash-chained status log, and the
  tool reports its own staleness (the aggregator itself must be observed: when it has not run, the light
  is not green).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from model import check_floors, load_pack  # noqa: E402

ORDER = {"GREEN": 0, "AMBER": 1, "UNKNOWN": 2, "RED": 3}


def confidence(age_days: float, max_age_days: float) -> float:
    fresh = max_age_days / 2
    if age_days <= fresh:
        return 1.0
    if age_days >= max_age_days:
        return 0.0
    return round(1.0 - (age_days - fresh) / (max_age_days - fresh), 3)


def evaluate(pack: dict, tier: str, evidence: list[dict], now: datetime) -> dict:
    max_age = pack["tiers"][tier]["evidence_max_age_days"]
    by_source: dict[str, dict] = {}
    future = []
    for e in evidence:  # keep the newest item per source; evidence dated in the future is rejected
        at = datetime.fromisoformat(e["observed_at"])
        if at - now > timedelta(minutes=2):
            future.append(e["source"])
            continue
        if e["source"] not in by_source or at > datetime.fromisoformat(by_source[e["source"]]["observed_at"]):
            by_source[e["source"]] = e
    controls = {}
    for cid, spec in pack["controls"].items():
        items = [by_source[s] for s in spec["evidence"] if s in by_source]
        if len(items) < len(spec["evidence"]):
            status, conf = "UNKNOWN", 0.0
        elif any(not i["passed"] for i in items):
            status, conf = "RED", 0.0
        else:
            ages = [(now - datetime.fromisoformat(i["observed_at"])).total_seconds() / 86400 for i in items]
            conf = min(confidence(a, max_age) for a in ages)
            status = "GREEN" if conf >= 0.7 else ("AMBER" if conf > 0 else "RED")
        controls[cid] = {"status": status, "confidence": conf,
                         "missing": [s for s in spec["evidence"] if s not in by_source]}
    floors = check_floors(pack)
    overall = max((c["status"] for c in controls.values()), key=ORDER.get) if controls else "UNKNOWN"
    if floors:
        overall = "RED"
    return {"pack": pack["id"], "tier": tier, "evaluated_at": now.isoformat(), "overall": overall,
            "floor_errors": floors, "controls": controls, "rejected_future_evidence": future}


def append_chain(path: Path, result: dict) -> str:
    prev = "0" * 64
    if path.exists():
        lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if lines:
            prev = json.loads(lines[-1])["hash"]
    entry = {"prev": prev, "overall": result["overall"], "evaluated_at": result["evaluated_at"],
             "result_sha256": hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()}
    entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry["hash"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", default="medium-appetite")
    ap.add_argument("--evidence", type=Path, required=True, help="JSON list of {source, passed, observed_at}")
    ap.add_argument("--chain", type=Path, default=Path("build/status-chain.jsonl"))
    a = ap.parse_args(argv)
    res = evaluate(load_pack(), a.tier, json.loads(a.evidence.read_text(encoding="utf-8")), datetime.now(timezone.utc))
    a.chain.parent.mkdir(parents=True, exist_ok=True)
    head = append_chain(a.chain, res)
    print(json.dumps({"overall": res["overall"], "head": head,
                      "controls": {k: v["status"] for k, v in res["controls"].items()}}, indent=2))
    return 0 if res["overall"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
