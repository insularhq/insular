"""KeyClerk's footprint budget: the budget adds up, and a ring measurement over a limit,
over KeyClerk's share or over a volume fails."""
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import footprint as F  # noqa: E402

B = F.budget()


def _fits() -> dict:
    return {"containers": {r["name"]: r["request"] for r in B["keyclerk"]},
            "disk": {d["name"]: d["gb"] / 10 for d in B["disk"]}}


def test_the_budget_adds_up():
    assert F.check(B) == []
    assert B["share"]["limit"] <= 2560          # the README's claim: KeyClerk itself stays within about 2 GB per node


def test_a_share_that_is_not_the_sum_fails():
    b = copy.deepcopy(B)
    b["share"]["limit"] -= 1
    assert any("share limit" in e for e in F.check(b))


def test_neighbours_that_do_not_fit_the_node_fail():
    b = copy.deepcopy(B)
    b["neighbours"][0]["limit"] = b["neighbours"][0]["request"] = 6000
    assert any("node: limits" in e for e in F.check(b))


def test_a_measurement_within_budget_passes():
    assert F.verify(B, _fits()) == []


def test_a_container_over_its_limit_fails():
    m = _fits()
    m["containers"]["engine"] = 513
    assert F.verify(B, m) == ["engine: peak 513 MiB above its limit 512"]


def test_the_share_is_judged_with_counted_copies():
    m = _fits()
    for r in B["keyclerk"]:
        m["containers"][r["name"]] = r["limit"]          # every container at its limit is exactly the share
    assert F.verify(B, m) == []
    m["containers"]["opa"] = 129                          # one MiB over, counted twice
    errs = F.verify(B, m)
    assert any(e.startswith("opa:") for e in errs) and any(e.startswith("KeyClerk's share") for e in errs)


def test_an_unmeasured_container_and_an_unknown_volume_fail():
    m = _fits()
    del m["containers"]["verifier"]
    m["disk"]["scratch"] = 1
    assert set(F.verify(B, m)) == {"verifier: not measured", "scratch: a volume the budget does not name"}


def test_sign_in_events_kept_90_days_fit_the_database_row():
    row = next(d["gb"] for d in B["disk"] if d["name"] == "keyclerk-database")
    days = B["growth"]["sign_in_retention_days"]
    assert F.yearly_gb(B, 30_000, days) < row < F.yearly_gb(B, 30_000)   # 30,000 sign-ins a day: 90 days fit, a year does not
