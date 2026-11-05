"""KeyClerk's edge in the model: the pinned engine gives every verdict of the edge conformance set it
shipped at its pinned tag (vendored in frameworks/keyclerk/, pinned by hash), and its edge policy tests pass. The same
set is what ReliKey's agent runs, so a new engine pin is adopted only when the edge still agrees with it."""
import hashlib
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _pin():
    pins = yaml.safe_load((ROOT / "frameworks" / "external-pins.yaml").read_text(encoding="utf-8"))["pins"]
    return next(p for p in pins if p["name"] == "keyclerk-edge-conformance")


def _set():
    return json.loads((ROOT / next(iter(_pin()["files"]))).read_text(encoding="utf-8"))


def _policy_dir() -> Path:
    import keyclerk
    return Path(keyclerk.__file__).resolve().parent / "policy"


def _norm(x):
    if isinstance(x, dict):
        return {k: _norm(v) for k, v in x.items()}
    if isinstance(x, (list, set, tuple)):
        items = [_norm(v) for v in x]
        return sorted(items, key=json.dumps) if isinstance(x, set) or all(isinstance(v, str) for v in items) else items
    return x


def test_the_edge_set_is_the_one_shipped_with_the_pinned_engine():
    """The vendored set comes from the same commit as the engine pin, and the engine ships the modules it names."""
    pins = yaml.safe_load((ROOT / "frameworks" / "external-pins.yaml").read_text(encoding="utf-8"))["pins"]
    engine = next(p for p in pins if p["name"] == "keyclerk")
    assert _pin()["commit"] == engine["commit"] and _pin()["version"] == engine["tag"]
    s = _set()
    assert s["modules"]
    for name, sha in s["modules"].items():
        assert hashlib.sha256((_policy_dir() / f"{name}.wasm").read_bytes()).hexdigest() == sha, name


def test_the_pinned_engine_answers_every_edge_policy_case():
    from keyclerk import policy_wasm
    cases = _set()["cases"]
    assert len(cases) >= 15
    for c in cases:
        assert _norm(policy_wasm.load(c["policy"]).eval(c["entrypoint"], c["input"])) == _norm(c["expected"]), c["name"]


def test_the_pinned_engine_verifies_bundles_as_recorded():
    """Pinned keys, the serial floor, the horizon and the ceiling: the same verdict and the same live leases."""
    from keyclerk import edge as E
    cases = _set()["verifier"]["cases"]
    assert len(cases) >= 50
    for c in cases:
        errs, applied = E.verify_bundle(c["sealed"], c["pins"], c["state"],
                                        datetime.strptime(c["now"], E.ISO).replace(tzinfo=timezone.utc))
        assert (not errs) == c["expected"]["ok"], (c["name"], errs)
        assert [x["lease_id"] for x in applied.get("leases", [])] == c["expected"]["leases"], c["name"]
        assert [x["lease_id"] for x in applied.get("visit_leases", [])] == c["expected"]["visit_leases"], c["name"]
        assert (applied.get("state") if not errs else None) == c["expected"]["state"], c["name"]


def test_the_pinned_engine_gives_the_recorded_statement_ceiling_ending_unlock_and_module_verdicts():
    """Officer statements (one or two nodes, enrolment or rotation), ceilings, the ended notice bound to its enrolment
    keys, kc-unlock-v2 codes from both sides, policy modules by hash."""
    from keyclerk import edge_conformance as EC
    s = _set()
    assert EC.failures(s) == []
    for fam in EC.FAMILIES:
        assert len(s[fam]["cases"]) >= 3, fam
    assert any(c["expected"]["ok"] for c in s["ended"]["cases"]) and not all(c["expected"]["ok"] for c in s["ended"]["cases"])
    assert any(c["expected"]["code"] for c in s["unlock"]["cases"]) and any(c["expected"]["code"] is None for c in s["unlock"]["cases"])


def test_the_pinned_engines_edge_policy_tests_pass():
    """The engine's policy package with its tests (the edge tests need the rest of the package), the edge tests among
    those that ran."""
    opa = shutil.which("opa")
    assert opa, "opa must be installed (CI installs a pinned, checksummed binary)"
    d = _policy_dir()
    assert (d / "edge.rego").exists() and (d / "edge_test.rego").exists()
    r = subprocess.run([opa, "test", "-v", str(d)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:] + r.stderr[-2000:]
    assert "data.keyclerk.edge_test." in r.stdout
