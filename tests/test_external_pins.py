"""External pins: vendored FTEF files and the KeyClerk engine are pinned by content, and every
obligation Insular holds them to is bound to a test here that is not skipped."""
import copy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import external_pins as X  # noqa: E402


def test_a_changed_vendored_file_breaks_its_pin():
    p = copy.deepcopy(X.pin("ftef"))
    first = next(iter(p["files"]))
    p["files"][first]["sha256"] = "0" * 64
    assert any("differs from its pin" in e for e in X.check_vendored(p, False))


def test_another_engine_commit_is_refused():
    p = copy.deepcopy(X.pin("keyclerk"))
    p["commit"] = "0" * 40
    p["wheel_sha256"] = "0" * 64   # another pin is another commit and another release wheel
    assert any("pinned commit" in e for e in X.check_package(p))


def test_without_trust_input_group_memberships_stay_dormant():
    """KO: require_trust fails closed on this deployment's configuration."""
    from datetime import datetime, timezone
    import keyclerk_config
    keyclerk_config.setup()
    from keyclerk import reconcile, records
    doc = records.load(ROOT / "instances" / "vdh-demo" / "grants.yaml")
    at = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
    bare = reconcile.desired(doc, at)
    full = reconcile.desired(doc, at, reconcile.load_trusts(str(ROOT / "instances" / "vdh-demo" / "trust.yaml")))
    assert not any(g.startswith("/groups/") for g, _ in bare) and any(g.startswith("/groups/") for g, _ in full)
