"""The local KeyClerk deployment: ports on localhost only, configuration and records mounted read-only, the
client secret as a mounted file and never an argument, the reconciler and console from one pinned engine image."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import keyclerk_local as L  # noqa: E402


def test_the_pod_publishes_on_localhost_only_and_mounts_read_only():
    first, second = L.commands("9.9.9", ROOT.parent / "keyclerk")
    pod = first[0]
    assert all(p.startswith("127.0.0.1:") for p in pod[pod.index("-p") + 1::2] if ":" in p)
    desk, rec, con = second
    assert "--read-only" in rec and "--read-only" in con and "--read-only" in desk
    key_mounts = [x for c in (rec, con) for x in c if "records-signing.key" in x or "records.key" in x]
    assert not key_mounts and any("records.key" in x for x in desk)            # only the desk holds the signing key
    assert any(x.endswith(":/var/lib/keyclerk-desk:ro") for x in rec) and any(x.endswith(":/var/lib/keyclerk-desk:ro") for x in con)
    assert desk[desk.index("--oidc-client") + 1] == "keyclerk-desk" and "--insecure-no-auth" not in desk
    mounts = [rec[i + 1] for i, x in enumerate(rec) if x == "-v"]
    assert all(m.endswith(":ro,Z") for m in mounts if "/etc/keyclerk" in m or "/run/secrets" in m)
    assert "localhost/keyclerk:9.9.9" in rec and "localhost/keyclerk:9.9.9" in con
    secret_args = [rec[i + 1] for i, x in enumerate(rec) if x.endswith("secret-file")]
    assert len(secret_args) == 2 and all(s.startswith("/run/secrets/") for s in secret_args)   # files, never values
    assert "--signing-key" in rec and "--apply" in rec and "--allow-unsigned" not in rec      # signed records only
    assert rec[rec.index("--client") + 1] != rec[rec.index("--reader-client") + 1]          # writer and reader apart
    assert "--oidc-public-issuer" in con and "--insecure-no-auth" not in con                 # the console needs sign-in


def test_the_keycloak_image_is_the_pinned_digest():
    assert L.keycloak_image().startswith("quay.io/keycloak/keycloak@sha256:")


def test_workflows_never_manage_groups_and_every_destructive_step_is_guarded():
    """ADR-0181: membership is KeyClerk's; a delete or disable only runs while its reason still holds (Keycloak
    re-checks the if-condition before each delayed step, never the event that started the workflow)."""
    for w in L.workflows():
        uses = [s["uses"] for s in w["steps"]]
        assert set(uses) <= L.WORKFLOW_STEPS_ALLOWED, (w["name"], uses)
        assert not {"join-group", "leave-group", "grant-role", "revoke-role"} & set(uses)
        if {"delete-user", "disable-user"} & set(uses):
            guarded = "is-member-of" in w.get("if", "") or (w.get("on") == "user-authenticated"
                                                            and (w.get("concurrency") or {}).get("restart-in-progress"))
            assert guarded, w["name"]
            assert next(s for s in w["steps"] if s["uses"] in ("delete-user", "disable-user")).get("after"), w["name"]


def test_the_writer_holds_group_membership_only_and_approvals_need_a_passkey_level():
    """ADR-0181: no manage-users for the writer (fine-grained permissions instead), so no logout on removal; proofs
    must carry the approval level the realm binds to a passkey; the clients log out through the back channel."""
    import keyclerk_config
    assert "manage-users" not in L.CLIENTS["keyclerk-writer"][0]
    cfg = keyclerk_config.build()
    assert cfg["reconcile"]["logout_on_removal"] is False
    assert cfg["approvals"]["proofs"] == "required" and cfg["approvals"]["acr"] == L.APPROVAL_LEVEL
    first, second = L.commands("9.9.9", ROOT.parent / "keyclerk")
    desk = second[0]
    assert desk[desk.index("--dpop-client") + 1] == L.OTHER_FRONT_END
