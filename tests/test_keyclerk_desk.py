"""The KeyClerk desk on this deployment's records: Insular's checks and balances hold for changes
people make in the front end, not only for records written by hand."""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import keyclerk_config  # noqa: E402

keyclerk_config.setup()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat  # noqa: E402
from keyclerk import approvals, config, records  # noqa: E402
from keyclerk.desk import Desk, Refusal, Store  # noqa: E402

DEMO = ROOT / "instances" / "vdh-demo" / "grants.yaml"
W = lambda a: {"anchor": a, "roles": []}   # noqa: E731
OWNER, ANN, BERT, EVA = W("idp:2b9e-owner"), W("idp:7c1f-ann"), W("idp:91d0-bert"), W("idp:55bb-eva")


class Broker:
    """A stand-in for the realm's broker: signs ID tokens (RS256) the way Keycloak does after a fresh sign-in."""

    def __init__(self):
        import base64
        import json
        import time
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        self._b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        self._json, self._time, self._hashes, self._padding = json, time, hashes, padding
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def jwks(self):
        n = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "kid": "k", "use": "sig", "e": self._b64(n.e.to_bytes(3, "big")),
                          "n": self._b64(n.n.to_bytes(256, "big"))}]}

    def sign(self, nonce, anchor, acr="approval"):
        now = int(self._time.time())
        h = self._b64(self._json.dumps({"alg": "RS256", "kid": "k"}).encode())
        b = self._b64(self._json.dumps({"iss": "https://id.test/realms/vdh-demo", "aud": "keyclerk-desk", "nonce": nonce,
                                        "anchor": anchor, "iat": now, "auth_time": now - 5,
                                        **({"acr": acr} if acr else {})}).encode())
        s = self.key.sign(f"{h}.{b}".encode(), self._padding.PKCS1v15(), self._hashes.SHA256())
        return f"{h}.{b}.{self._b64(s)}"


@pytest.fixture
def broker():
    return Broker()


@pytest.fixture
def desk(tmp_path, broker):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    proofs = approvals.BrokerProofs({"https://id.test/realms/vdh-demo"}, {"keyclerk-desk"}, 300, "https://id.test/x",
                                    tmp_path / "keys.json", fetch=broker.jwks, acr=config.current()["approvals"]["acr"])
    d = Desk(Store(tmp_path / "store", key, DEMO), proofs=proofs)
    d.broker = broker
    return d


def signed(desk, who, cid):
    """An approval as this deployment requires it: a proof the broker signed for exactly this change and person."""
    return desk.approve(who, cid, desk.broker.sign(desk.statement(who, cid)["nonce"], who["anchor"]))


def test_through_the_desk_a_deputy_in_an_elevated_group_needs_a_key_from_outside_the_chain(desk):
    r = desk.propose(ANN, {"action": "add_member", "group": "finance", "anchor": "idp:44aa-dirk", "days": 30})
    assert r["outcome"] == "pending"
    with pytest.raises(Refusal):
        desk.approve(ANN, r["change_id"])                      # not one's own key
    with pytest.raises(Refusal):
        desk.approve(OWNER, r["change_id"])                    # the root is above every chain
    assert signed(desk, ANN, r["change_id"])["outcome"] == "pending"     # elevated: the proposer signs too (KeyClerk 0015)
    assert signed(desk, EVA, r["change_id"])["outcome"] == "applied"


def test_through_the_desk_nobody_acts_beyond_the_delegation_they_hold(desk):
    with pytest.raises(Refusal, match="no delegation"):
        desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    r = desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:7c1f-ann"})
    assert r["outcome"] == "refused" and "added themselves" in r["reasons"][0]
    r = desk.propose(BERT, {"action": "delegate", "group": "site-heverlee", "delegate": "idp:55bb-eva",
                            "powers": ["members", "subgroups"], "days": 30})
    assert r["outcome"] == "refused" and "wider than the parent" in " ".join(r["reasons"])


def test_desk_revisions_keep_history_and_are_signed(desk):
    desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    assert records.guard(records.load(DEMO), desk.store.load()) == []
    assert desk.store.verify_log() == [] and (desk.store.path / "records.yaml.sig").exists()


def test_desk_revisions_carry_a_signed_serial_that_never_goes_back(desk):
    first = desk.store.load()
    desk.propose(ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 30})
    second = desk.store.load()
    assert (first["revision"], second["revision"]) == (1, 2)
    assert records.guard(second, first) and records.guard(first, second) == []     # going back is refused


def test_one_person_cannot_flood_the_desk(desk):
    from keyclerk.desk import Throttled
    for _ in range(30):
        with pytest.raises(Refusal):
            desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    n = len(desk.store.log())
    with pytest.raises(Throttled):
        desk.propose(EVA, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    assert len(desk.store.log()) == n


def test_changes_waiting_at_once_never_share_an_id_on_this_deployments_records(desk):
    a = desk.propose(ANN, {"action": "add_member", "group": "finance", "anchor": "idp:44aa-dirk", "days": 30})
    b = desk.propose(ANN, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn", "days": 30})
    assert (a["outcome"], b["outcome"]) == ("pending", "pending")             # elevated: both wait for their proposer
    assert a["records"]["memberships"][0]["membership_id"] != b["records"]["memberships"][0]["membership_id"]
    assert signed(desk, ANN, b["change_id"])["outcome"] == "applied"           # applied while the other waits
    assert signed(desk, ANN, a["change_id"])["outcome"] == "pending"
    assert signed(desk, EVA, a["change_id"])["outcome"] == "applied"
    assert records.duplicate_ids(desk.store.load()) == []


def test_the_desk_repairs_a_crash_only_towards_a_revision_it_signed(desk):
    good = desk.store.raw()
    with (desk.store.path / "log.jsonl").open("ab") as h:
        h.write(b'{"seq": 9, "ha')
    (desk.store.path / "records.yaml").write_bytes(b"realm: forged\n")
    desk.store.close()
    again = Store(desk.store.path, desk.store.key_path)
    assert again.raw() == good and again.recovered and again.verify_log() == []


def test_on_this_deployment_a_plain_member_reads_only_what_concerns_them(desk):
    FINN = W("idp:66cc-finn")
    with pytest.raises(PermissionError):
        desk.people(FINN)
    with pytest.raises(LookupError):
        desk.group(FINN, "finance")
    assert desk.delegations(FINN) == [] and desk.changes(FINN)["log"] == []


def test_on_this_deployment_an_approval_is_the_approvers_own_signature(desk):
    policy = config.current()["approvals"]
    assert policy["proofs"] == "required"
    r = desk.propose(ANN, {"action": "add_member", "group": "finance", "anchor": "idp:44aa-dirk", "days": 30})
    with pytest.raises(Refusal, match="your own signature"):
        desk.approve(EVA, r["change_id"])                                  # a click is not a key here
    with pytest.raises(Refusal, match="authentication level"):             # a password sign-in, no passkey
        desk.approve(EVA, r["change_id"], desk.broker.sign(desk.statement(EVA, r["change_id"])["nonce"], "idp:55bb-eva", acr=None))
    with pytest.raises(Refusal, match="does not fit"):                     # a proof made for someone else
        desk.approve(EVA, r["change_id"], desk.broker.sign(desk.statement(EVA, r["change_id"])["nonce"], "idp:44aa-dirk"))
    assert signed(desk, ANN, r["change_id"])["outcome"] == "pending"           # the proposer's own signature (KeyClerk 0015)
    assert signed(desk, EVA, r["change_id"])["outcome"] == "applied"
    doc = desk.store.load()
    assert approvals.check(doc, desk.proofs, policy) == []                 # the reconciler finds every approval proven
    forged = {**doc, "memberships": [dict(m) for m in doc["memberships"]]}
    forged["memberships"][-1]["approved_by"] = ["idp:55bb-eva", "idp:2b9e-owner"]   # the desk's key alone adds a key
    assert approvals.check(forged, desk.proofs, policy)


def test_a_second_key_needs_standing_and_enforcing_it_changes_nothing_here(tmp_path):
    """ADR-0182: under enforce a plain person's key does not count, the officer's and a named approver's do, the
    root's never; the demo tenant runs warn, and with the operator appointed the impact list is empty."""
    import copy
    from datetime import datetime, timezone
    from keyclerk import delegation as D
    doc = records.load(DEMO)
    assert config.current()["delegation"]["second_key_standing"] == "warn"
    assert D.standing_impact(doc) == []
    now = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
    base = {"membership_id": "M-x", "group": "finance", "member": {"anchor": "idp:91d0-bert"}, "by": "idp:7c1f-ann",
            "under": next(d["delegation_id"] for d in doc["delegations"] if d["delegate"] == "idp:7c1f-ann"),
            "start": now.isoformat(), "end": "2026-11-20T00:00:00Z"}
    with D.standing_mode("enforce"):
        def counts(key):
            cand = copy.deepcopy(doc)
            cand["memberships"].append({**base, "approved_by": [key]})
            return not [e for e in D.membership_errors(cand, cand["memberships"][-1], at=now) if "second key" in e]
        assert not counts("idp:bb11-kai")                     # a person of the organisation, no standing
        assert counts("idp:31ee-ingrid")                      # the security officer
        assert counts("vdh:operator")                         # the named approver
        assert not counts("idp:2b9e-owner")                   # the root never counts


def test_the_persona_graph_shows_only_what_the_view_policy_allows(desk):
    """ADR-0182: a manager sees a member of their groups without accounts and only their part; a stranger is
    refused, and an unknown person answers the same; the realm's identity sources are named for a viewer."""
    g = desk.person_graph(BERT, "idp:55bb-eva")
    assert "account" not in {n["kind"] for n in g["nodes"]} and "hidden" not in g      # never a count of what you may not see (engine 0.16.2)
    with pytest.raises(PermissionError):
        desk.person_graph(W("idp:44aa-dirk"), "idp:7c1f-ann")
    with pytest.raises(PermissionError):
        desk.person_graph(W("idp:44aa-dirk"), "idp:0000-nobody")
    full = desk.person_graph(OWNER, "vdh:operator")
    names = {r["name"] for r in full["realm_sources"]}
    assert {"Staff sign-in", "VDHome operator", "Partner directory (Entra, brokered)"} <= names
    assert "unknown" not in {r["kind"] for r in full["realm_sources"]}


def test_the_delegation_tree_shows_a_deputy_their_branch_and_the_chain_above_only(desk):
    """ADR-0182: the owner sees the whole tree; bert sees the root, his delegation and dirk's below it, not
    ann's branch; someone holding no delegation sees an empty tree. Decided by the engine's compiled tree policy."""
    full = desk.delegation_tree(OWNER)
    assert full["whole"] and len([n for n in full["nodes"] if n["kind"] == "delegation"]) >= 3
    mine = desk.delegation_tree(BERT)
    names = {n["label"] for n in mine["nodes"] if n["kind"] == "delegation"}
    assert names == {"bert", "dirk"} and not mine["whole"]
    assert desk.delegation_tree(EVA)["nodes"] == []


def test_a_visit_admits_what_the_policy_allows_and_suspends_an_unconfirmed_guest(desk):
    """ADR-0182, on vdh-demo: ann hosts carla (driving, two laptops, a backpack) and one unregistered passenger;
    the front office (the guard) records the entries; the engine's compiled visits policy decides each one and the
    timers."""
    from datetime import datetime, timedelta, timezone
    from keyclerk.desk import Refusal
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    clock = {"t": t0}
    desk.clock = lambda: clock["t"]
    iso = lambda t: t.isoformat().replace("+00:00", "Z")   # noqa: E731
    r = desk.propose(ANN, {"action": "register_visit", "place": "place:heverlee", "purpose": "supplier meeting",
                           "start": iso(t0 + timedelta(hours=1)), "end": iso(t0 + timedelta(hours=2)),
                           "zones": ["zone:heverlee-depot"],
                           "attendees": [{"anchor": "ext:3a71-carla",           # person-first visits
                                          "kit": [{"class": "it-device", "count": 2}, {"class": "bag", "count": 1}]},
                                         {"unregistered": True, "label": "passenger"}],
                           "vehicles": [{"plate": "2-XXX-111", "make": "Toyota", "model": "RAV4", "colour": "black",
                                         "driver": 1}]})
    assert r["outcome"] == "applied"
    vid, guard = r["records"]["visits"][0]["visit_id"], W("idp:ee01-guard")
    enter = lambda party, shown, **kw: desk.propose(guard, {"action": "record_entry", "visit_id": vid, "party": party,   # noqa: E731
                                                            "presented": shown, **kw})
    code = desk.visit_qr(W("ext:3a71-carla"), vid, "P1")["token"]       # a QR entry presents the guest's code
    assert enter("P1", "qr", vehicle=True, token=code)["outcome"] == "applied"
    with pytest.raises(Refusal, match="visitor badge"):
        enter("P2", "none")
    desk.propose(guard, {"action": "issue_badge", "visit_id": vid, "party": "P2", "kind": "visitor", "badge": "VB-0042"})
    assert enter("P2", "visitor-badge")["outcome"] == "applied"           # a badge counts once it was handed out
    with pytest.raises(Refusal, match="never"):
        enter("P2", "visitor-badge", zone="zone:heverlee-depot")
    clock["t"] = t0 + timedelta(minutes=15)
    assert {e["kind"] for e in desk.tick()} == {"reminded"}
    desk.propose(ANN, {"action": "confirm_guest", "visit_id": vid, "party": "P1"})
    clock["t"] = t0 + timedelta(minutes=20)
    assert [(e["kind"], e["party"]) for e in desk.tick()] == [("suspended", "P2")]   # P1 was confirmed: no suspension


def test_the_phone_scan_says_only_yes_or_no_and_a_guard_needs_the_current_code(desk):
    """ADR-0182, on vdh-demo: the guest's code names no person; a phone scan answers yes or no and
    until when, online; a guard's QR entry needs the current code, and a new code revokes the old one."""
    from datetime import datetime, timedelta, timezone
    from keyclerk import qr
    from keyclerk.desk import Refusal
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    desk.clock = lambda: t0
    iso = lambda t: t.isoformat().replace("+00:00", "Z")   # noqa: E731
    vid = desk.propose(ANN, {"action": "register_visit", "place": "place:heverlee", "purpose": "scan check",
                             "start": iso(t0 + timedelta(hours=1)), "end": iso(t0 + timedelta(hours=2)),
                             "attendees": [{"anchor": "ext:3a71-carla"}]})["records"]["visits"][0]["visit_id"]
    carla, guard = W("ext:3a71-carla"), W("idp:ee01-guard")
    old = desk.visit_qr(carla, vid, "P1")["token"]
    assert "carla" not in old and set(qr.read(old)) == {"v", "p", "n", "e", "k"}
    assert desk.scan(old)["unescorted"] is False                          # not checked in yet
    desk.propose(carla, {"action": "issue_qr", "visit_id": vid, "party": "P1"})
    with pytest.raises(Refusal, match="newer code"):
        desk.propose(guard, {"action": "record_entry", "token": old, "presented": "qr"})
    new = desk.visit_qr(carla, vid, "P1")["token"]
    desk.propose(guard, {"action": "record_entry", "token": new, "presented": "qr"})
    ans = desk.scan(new)
    assert ans["unescorted"] is True and set(ans) == {"unescorted", "checked", "at", "until"}
    assert desk.scan(old)["unescorted"] is False


def test_vdh_demo_holds_privileged_power_only_through_admin_personas(desk):
    """ADR-0182, on vdh-demo: with the persona rule enforced (the engine default since 0.16.1) nothing
    changes: the root and every member of a privileged group act through an admin persona, and the daily-account
    memberships they replaced are retired, not rewritten."""
    from keyclerk import delegation as D
    from keyclerk.reconcile import check_records
    doc = desk.store.load()
    now = datetime(2026, 10, 23, 13, 0, tzinfo=timezone.utc)
    assert D.persona_mode() == "enforce" and D.persona_impact(doc, now) == []
    assert D.purpose_of(doc, D.root_at(doc, now)) == "admin"
    assert not check_records(doc)
    retired = {r["id"] for r in doc["admin_revocations"]}
    assert {f"M-vdh-demo-{n:04d}" for n in (6, *range(12, 20))} <= retired


def test_personas_workloads_and_agents_keep_their_place(desk):
    """ADR-0182, on vdh-demo: kai's daily account never joins a privileged group, his admin persona may;
    workloads and agents have owners, agents a director, and the persona graph shows who directs and owns them."""
    from datetime import datetime, timedelta, timezone
    from keyclerk import delegation as D
    from keyclerk.reconcile import check_records
    doc = desk.store.load()
    assert D.same(doc, "idp:bb11-kai", "adm:bb11-kai") and D.purpose_of(doc, "adm:bb11-kai") == "admin"
    assert not D.identity_errors(doc)
    kinds = {p["person"]: p["kind"] for p in doc["persons"]}
    assert [k for k in kinds.values()].count("workload") == 2 and [k for k in kinds.values()].count("agent") == 3
    now = datetime.now(timezone.utc)                                                      # only a live membership is judged
    base = {"group": "server-admins", "by": "adm:2b9e-owner", "under": "root",            # the root's admin persona
            "start": f"{now - timedelta(hours=1):%Y-%m-%dT%H:%M:%SZ}", "end": f"{now + timedelta(days=9):%Y-%m-%dT%H:%M:%SZ}",
            "approved_by": ["adm:31ee-ingrid"]}
    daily = {**doc, "memberships": doc["memberships"] + [{**base, "membership_id": "M-t-daily", "member": {"anchor": "idp:bb11-kai"}}]}
    admin = {**doc, "memberships": doc["memberships"] + [{**base, "membership_id": "M-t-admin", "member": {"anchor": "adm:bb11-kai"}}]}
    assert any("admin persona, not a daily account" in e for e in check_records(daily) if e.startswith("M-t-daily"))
    assert not any("admin persona" in e for e in check_records(admin) if e.startswith("M-t-admin"))
    g = desk.person_graph(OWNER, "agent:vdh-demo/triage")
    assert any(e["kind"] == "directs" for e in g["edges"]) and any(e["kind"] == "owns" for e in g["edges"])

