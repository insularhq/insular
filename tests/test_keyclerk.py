"""KeyClerk: pins the invariants of the persona leases and the access portal
before any portal code exists: the portal holds no administrative power, approvals are signed over the content shown,
the reconciler is the single writer of personas, and a persona that nothing covers is a finding."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def _kc():
    return yaml.safe_load((ROOT / "platform" / "access-lifecycle.yaml").read_text(encoding="utf-8"))["keyclerk"]


def test_keyclerk_portal_holds_no_admin_power_and_signs_what_it_shows():
    portal = _kc()["portal"]
    assert "no Keycloak administrative role" in portal["no_admin_power"] and "only the reconciler changes the broker" in portal["no_admin_power"]
    sa = portal["signed_approvals"]   # confirm elsewhere, bind the purpose, verify and store the assertion
    assert "fetches the canonical record itself" in sa["confirm_view"] and "keyclerk-approval-v1" in sa["challenge"]
    assert "never as names" in sa["record"] and "JWT built-ins" in sa["verifier"]
    assert "reductions too" in portal["writes"] and "__Host-" in portal["tokens"]
    assert "server-side" in portal["tokens"] and "SameSite=Strict" in portal["tokens"]
    assert "Trusted Types" in portal["browser"] and "no third-party scripts" in portal["browser"]
    assert "never through the portal" in portal["uploads"]
    assert "never from a portal form" in portal["joiner_mover_leaver"]


def test_keyclerk_personas_are_leased_with_one_writer_and_orphans_are_findings():
    pl = _kc()["persona_leases"]
    assert "deleted when the last one ends" in pl["admin_persona"]
    assert "only writer of personas" in pl["writer"]
    assert "is a finding" in pl["finding"] and "security incident" in pl["finding"]


def test_keyclerk_open_source_package_keeps_the_model_private_and_waits_for_proof():
    oss = _kc()["open_source"]
    kept = " ".join(oss["kept_in_insular"])
    assert "registers, review findings and residuals" in kept and "DDIL edge pieces" in kept
    assert "test run proves that removal works" in oss["publish_when"]
    al = yaml.safe_load((ROOT / "platform" / "access-lifecycle.yaml").read_text(encoding="utf-8"))
    assert any(d["id"] == "licence" and "EUPL-1.2" in d["decision"] for d in al["decided"])   # ADR-0183
