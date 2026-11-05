import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from gen_firewall import aerleon_policy, drift, host_rules, nft_preview  # noqa: E402
from greenlight import evaluate  # noqa: E402
from model import check_floors, flows, load_calm, load_pack, site_of  # noqa: E402

NOW = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
CALM_META = Path(__file__).resolve().parent.parent / "calm" / "meta-1.2"


def _evidence(age_days: float, passed=True, skip=()):
    sources = {s for c in load_pack()["controls"].values() for s in c["evidence"]}
    t = (NOW - timedelta(days=age_days)).isoformat()
    return [{"source": s, "passed": passed, "observed_at": t} for s in sorted(sources) if s not in skip]


def test_autonomy_matrix_principles():
    from autonomy import check, decide, load as load_a
    a = load_a()
    assert check(a) == []
    # reducing exposure can be automatic, widening it never without approval
    assert decide(a, "high-appetite", "quarantine-host") == "autonomous"
    assert decide(a, "high-appetite", "release-quarantine") == "gated"
    # the situation only lowers autonomy
    assert decide(a, "high-appetite", "rejoin-site", ["island-disconnected"]) == "human"
    assert decide(a, "high-appetite", "reconcile-config", ["evidence-unknown"]) == "gated"
    # irreversible actions are never autonomous, and a weakened matrix is caught
    bad = copy.deepcopy(a)
    bad["max_autonomy"]["high-appetite"]["destroy-keys"] = "autonomous"
    bad["max_autonomy"]["low-appetite"]["grant-access"] = "notify"
    errs = check(bad)
    assert any("irreversible" in e for e in errs) and any("widens access" in e for e in errs)


def test_federated_light_never_trusts_silence_and_surfaces_edge_problems():
    from datetime import timedelta as td
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from federate import aggregate, sign
    k = {n: Ed25519PrivateKey.generate() for n in ("site-a", "site-b", "island-c")}
    pub = {n: key.public_key() for n, key in k.items()}
    g = {n: td(hours=4) for n in k}

    def rep(name, overall, hours_ago, disconnected=False, key=None):   # ADR-0126: child, audience and seq are signed
        st = {"child": name, "audience": "region-1", "seq": 1, "overall": overall,
              "evaluated_at": (NOW - td(hours=hours_ago)).isoformat(), "disconnected": disconnected}
        return {"status": st, "signature": sign(key or k[name], st)}
    agg = lambda children: aggregate(children, pub, g, "GREEN", NOW, parent="region-1", seen={})

    ok = agg({"site-a": rep("site-a", "GREEN", 1), "site-b": rep("site-b", "GREEN", 1),
              "island-c": rep("island-c", "GREEN", 2, True)})
    assert ok["overall"] == "GREEN" and ok["children"]["island-c"]["flags"]
    silent = agg({"site-a": rep("site-a", "GREEN", 1), "site-b": rep("site-b", "GREEN", 9), "island-c": None})
    assert silent["overall"] == "UNKNOWN"
    forged = rep("site-a", "GREEN", 1); forged["signature"] = "AAAA"
    assert agg({"site-a": forged, "site-b": rep("site-b", "GREEN", 1), "island-c": rep("island-c", "AMBER", 1)})["overall"] == "RED"
    # the parent cannot forge a child's light with its own key, and a future-dated light is RED, not GREEN forever
    parent = Ed25519PrivateKey.generate()
    by_parent = rep("site-a", "GREEN", 1, key=parent)
    assert agg({"site-a": by_parent})["overall"] == "RED"
    future = rep("site-a", "GREEN", -24 * 200)
    r = agg({"site-a": future})
    assert r["overall"] == "RED" and "future" in r["children"]["site-a"]["flags"][0]


def test_capability_catalogue_covers_all_planes_with_evidence():
    import yaml as _y
    cat = _y.safe_load((Path(__file__).resolve().parent.parent / "catalog" / "capabilities.yaml").read_text(encoding="utf-8"))
    planes = set(cat["planes"])
    used = {c["plane"] for c in cat["capabilities"].values()}
    assert used == planes
    assert all(c["evidence"] and c["ddil"] in ("must-run-local", "degrade", "central-only") for c in cat["capabilities"].values())


def test_bom_is_fully_open_source_and_agpl_is_marked():
    import re as _re
    import yaml as _y
    bom = _y.safe_load((Path(__file__).resolve().parent.parent / "bom" / "bill-of-materials.yaml").read_text(encoding="utf-8"))
    allowed = set(bom["allowed_licences"])
    for c in bom["software"]:
        ids = set(_re.findall(r"[A-Za-z]+-[0-9.]+(?:-Clause)?|MIT|PostgreSQL|own", c["licence"]))
        assert ids and ids <= allowed, (c["name"], c["licence"])
        if "AGPL" in c["licence"]:
            assert c.get("agpl") is True, c["name"]
    assert "licence" not in " ".join(bom["paid"].values()).lower().replace("no software licences", "")


def test_raci_one_accountable_and_vdhome_never_on_tenant_content():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    raci = _y.safe_load((root / "governance" / "raci.yaml").read_text(encoding="utf-8"))
    for act, row in raci["activities"].items():
        assert sum("A" in str(v).split("/") for v in row.values()) == 1, act
    for act in ("tenant-content-monitoring", "user-lifecycle", "key-custody-tenant"):
        assert raci["activities"][act]["vdhome"] == "-", act
    assert raci["activities"]["notify-supervisory-authority"]["client"] == "A/R"


def test_isolation_floors_ordered_and_inspection_keeps_operator_blind():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    iso = _y.safe_load((root / "platform" / "isolation.yaml").read_text(encoding="utf-8"))
    order = iso["isolation_order"]
    floors = [order.index(iso["isolation_floor"][l]) for l in ("Internal", "Sensitive", "Restricted")]
    assert floors == sorted(floors) and set(iso["isolation_floor"].values()) <= set(iso["isolation_levels"])
    assert any("TLS interception" in f for f in iso["inspection"]["forbidden"])
    inc = _y.safe_load((root / "governance" / "incident.yaml").read_text(encoding="utf-8"))
    assert inc["clocks"]["gdpr-controller-to-authority"]["deadline_hours"] == 72
    assert inc["clocks"]["nis2-early-warning"]["deadline_hours"] == 24
    assert any(k["reversible"] is False for k in inc["kill_switches"])


def test_resolver_refuses_ports_unknown_functions_and_forbidden_exposure():
    from resolve import resolve
    base = {"app": "x", "component": "cryptpad", "functions": ["web-ui"], "data_label": "Sensitive", "users": "tenant"}
    assert any("technical fields" in e for e in resolve({**base, "ports": [8443]})["errors"])
    assert any("no approved pattern" in e for e in resolve({**base, "functions": ["ssh-from-anywhere"]})["errors"])
    assert any("not allowed for Restricted" in e for e in resolve({**base, "data_label": "Restricted"})["errors"])
    assert any("requires 'web-ui'" in e for e in resolve({**base, "functions": ["realtime-websocket"]})["errors"])
    ok = resolve({**base, "data_label": "Restricted", "functions": ["vpn-only-ui"]})
    assert ok["errors"] == [] and ok["runtime"] == "microvm"


def test_no_algorithm_or_legacy_alg_is_hard_coded_in_tools():
    import re as _re
    root = Path(__file__).resolve().parent.parent
    rx = _re.compile(r"\b(md5|sha1)\s*\(|['\"]alg['\"]\s*:\s*['\"](none|HS256|RS1)['\"]", _re.I)
    hits = [p.name for p in (root / "tools").glob("*.py") if rx.search(p.read_text(encoding="utf-8"))]
    assert hits == []


def _sizes():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    sz = _y.safe_load((root / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    order = ["S", "M", "L"]

    def comps(size):
        out = list(sz["core"])
        for m in sz["modules"].values():
            if m["size"] in order and order.index(m["size"]) <= order.index(size):
                out += m.get("components", [])
        return out
    return sz, order, comps


def test_sizes_grow_monotonically_without_duplicate_functions():
    sz, order, comps = _sizes()
    names = {s: {c["component"] for c in comps(s)} for s in order}
    assert names["S"] < names["M"] < names["L"]
    for s in order:
        fns = [f for c in comps(s) + sz["ci_only"] for f in c["functions"]]
        assert len(fns) == len(set(fns)), f"duplicate function in size {s}: {[f for f in fns if fns.count(f) > 1]}"
    assert all(m.get("pending") or m.get("components") for m in sz["modules"].values())
    assert all(m["size"] in ("M", "L") for m in sz["modules"].values() if m.get("pending"))
    # 16: OPA and the evaluator joined the core so S has its own decision point;
    # 17: pgBackRest, because S needs point-in-time recovery of its database (ADR-0024);
    # 18: the same gateway, database operator and CNI from S, so S upgrades to M and L without refactoring (ADR-0036)
    # 19: system-upgrade-controller, so hosts and K3s are only updated through git (ADR-0050); the host OS itself is not counted
    assert len([c for c in sz["core"] if c.get("runtime") not in ("kernel", "host", "wasm", "rules")]) <= 21   # 21 since the ADR-0172 amendment (Knot DNS with Knot Resolver, counted by ADR-0131 and ADR-0155); 19 since ADR-0050, 20 since ADR-0125 (Garage, the backup target); the WAF (Wasm and rules inside the gateway) is not a workload


def test_every_size_can_host_its_labels_and_bom_is_fully_accounted():
    import yaml as _y
    sz, order, comps = _sizes()
    root = Path(__file__).resolve().parent.parent
    iso = _y.safe_load((root / "platform" / "isolation.yaml").read_text(encoding="utf-8"))
    for s in order:
        have = {c["component"] for c in comps(s)}
        for label in sz["labels"][s]:
            prov = sz["isolation_providers"][iso["isolation_floor"][label]]
            assert prov is None or prov in have, f"size {s} cannot host {label}: needs {prov}"
    bom = {c["name"] for c in _y.safe_load((root / "bom" / "bill-of-materials.yaml").read_text(encoding="utf-8"))["software"]}
    used = {c["component"] for c in sz["core"] + sz["ci_only"]}
    used |= {p["name"] for c in sz["core"] for p in c.get("parts", [])}   # parts of a component (ADR-0006 amendment)
    used |= {c["component"] for m in sz["modules"].values() for c in m.get("components", [])}
    assert used <= bom, used - bom
    assert bom - used - set(sz["retired"]) == set(), bom - used - set(sz["retired"])


def test_openbao_pki_is_ecdsa_only_and_rsa_needs_a_deviation():
    sz, _, _ = _sizes()
    bao = next(c for c in sz["core"] if c["component"] == "OpenBao")
    assert "ECDSA-only" in bao["note"]
    assert sz["modules"]["rsa-legacy-ca"]["size"] == "deviation"


def test_infrastructure_inherits_the_highest_hosted_label_except_ciphertext_layers():
    import yaml as _y
    from classification import cohost, load, required_level
    root = Path(__file__).resolve().parent.parent
    cls = load()
    iso = _y.safe_load((root / "platform" / "isolation.yaml").read_text(encoding="utf-8"))
    hosted = ["Internal", "Restricted"]
    assert required_level(cls, "control-plane", hosted) == "Restricted"
    assert required_level(cls, "identity-broker", hosted) == "Restricted"
    assert required_level(cls, "backup-storage", hosted) is None and required_level(cls, "transport-network", hosted) is None
    # adjacent labels may share a kernel only behind the higher label's floor
    assert cohost(cls, "Internal", "Sensitive", "host-kernel", "sandboxed-container", iso) == []
    assert cohost(cls, "Internal", "Sensitive", "host-kernel", "container-hardened", iso)
    # the top label never shares a plaintext layer with a lower tenant; ciphertext layers may be shared
    assert cohost(cls, "Sensitive", "Restricted", "host-kernel", "dedicated-host", iso)
    assert cohost(cls, "Sensitive", "Restricted", "backup-storage", "container-hardened", iso) == []
    # appending a higher label later makes Restricted shareable with Sensitive behind its floor
    cls2 = {**cls, "labels": cls["labels"] + ["Restricted-High"]}
    iso2 = {**iso, "isolation_floor": {**iso["isolation_floor"], "Restricted-High": "dedicated-host"}}
    assert cohost(cls2, "Sensitive", "Restricted", "host-kernel", "microvm", iso2) == []
    assert cohost(cls2, "Restricted", "Restricted-High", "host-kernel", "dedicated-host", iso2)


def _grants(*held):
    """Grant records for authz tests: (anchor, role) pairs as active functional grants around NOW."""
    s, e = (NOW - timedelta(days=1)).isoformat(), (NOW + timedelta(days=1)).isoformat()
    return {"realm": "t", "revocations": [], "suspensions": [], "grants": [
        {"grant_id": f"G-t-{i:04d}", "subject": {"anchor": a, "kind": "tenant"}, "role": r, "plane": "tenant", "class": "functional",
         "scope": {"level": "tenant", "id": "t"}, "label_ceiling": "Sensitive", "justification": {"test": "x"}, "requested_by": "req",
         "approved_by": ["appr"], "start": s, "end": e} for i, (a, r) in enumerate(held, 1)]}


def test_one_authorisation_model_for_persons_workloads_devices_and_agents():
    import yaml as _y
    from authz import check_policy, decide, load
    root = Path(__file__).resolve().parent.parent
    reg = load()
    pol = _y.safe_load((root / "policies" / "vault-access.yaml").read_text(encoding="utf-8"))
    assert check_policy(pol, reg) == []
    t = (NOW - timedelta(minutes=10)).isoformat()
    old = (NOW - timedelta(hours=30)).isoformat()
    alice = {"type": "person", "id": "alice", "attributes": {"role": {"value": "tenant-admin", "at": t}, "acr": {"value": "phishing-resistant", "at": t}}}
    agent = {"type": "agent", "id": "summariser", "attributes": {"role": {"value": "consultant", "at": t}, "acr": {"value": "phishing-resistant", "at": t}}}
    cv = lambda v: {"value": v, "at": t}
    good = {"device_posture": cv("compliant"), "evidence_state": cv("GREEN")}
    req = lambda subj, act, res, ctx, actors=(): {"subject": subj, "action": {"name": act}, "resource": {"type": res}, "context": ctx, "actors": list(actors)}
    g = _grants(("alice", "tenant-admin"), ("bob", "consultant"), ("summariser", "consultant"))
    _decide = decide
    decide = lambda r, p, rg, n: _decide(r, p, rg, n, g)   # roles come from the grant records
    assert decide(req(alice, "read", "sensitive-document", good), pol, reg, NOW)["decision"] is False  # tenant-admin not in read roles
    bob = {**alice, "id": "bob", "attributes": {**alice["attributes"], "role": {"value": "consultant", "at": t}}}
    assert decide(req(bob, "read", "sensitive-document", good), pol, reg, NOW)["decision"]
    # adaptive: posture or unknown evidence denies regardless of role
    assert not decide(req(bob, "read", "sensitive-document", {**good, "device_posture": cv("unknown")}), pol, reg, NOW)["decision"]
    assert not decide(req(bob, "read", "sensitive-document", {**good, "evidence_state": cv("UNKNOWN")}), pol, reg, NOW)["decision"]
    # stale attributes count as absent
    stale = {**bob, "attributes": {**bob["attributes"], "acr": {"value": "phishing-resistant", "at": old}}}
    assert not decide(req(stale, "read", "sensitive-document", good), pol, reg, NOW)["decision"]
    # an agent acting for bob is allowed only where both are; never for irreversible actions
    assert decide(req(agent, "read", "sensitive-document", good, [bob]), pol, reg, NOW)["decision"]
    assert not decide(req(agent, "export", "engagement-archive", good, [alice]), pol, reg, NOW)["decision"]
    assert decide(req(alice, "export", "engagement-archive", good), pol, reg, NOW)["decision"]
    # workloads and devices use the same model
    wl = {"type": "workload", "id": "spiffe://vdh/t1/vault"}
    assert not decide(req(wl, "unwrap", "data-key", good), pol, reg, NOW)["decision"]  # no tenant grant
    granted = {**good, "tenant_unwrap_grant": cv("valid")}
    assert decide(req(wl, "unwrap", "data-key", granted), pol, reg, NOW)["decision"]
    assert not decide(req(wl, "unwrap", "data-key", {**granted, "evidence_state": cv("RED")}), pol, reg, NOW)["decision"]
    # PKI-04: a bare, untimestamped or stale context value counts as missing
    assert not decide(req(bob, "read", "sensitive-document", {"device_posture": "compliant", "evidence_state": "GREEN"}), pol, reg, NOW)["decision"]
    assert not decide(req(bob, "read", "sensitive-document", {**good, "device_posture": {"value": "compliant", "at": old}}), pol, reg, NOW)["decision"]
    assert not decide(req(wl, "read", "nothing-defined", good), pol, reg, NOW)["decision"]  # default deny
    # AZ-5: a role claim in the token without a grant record holds nothing
    r = _decide(req(bob, "read", "sensitive-document", good), pol, reg, NOW)
    assert not r["decision"] and any("never from a token" in x for x in r["reasons"])
    mallory = {**bob, "id": "mallory"}   # claims consultant in the token, holds no grant
    assert not decide(req(mallory, "read", "sensitive-document", good), pol, reg, NOW)["decision"]
    # a policy may not use forbidden or unregistered attributes
    bad = {"rules": [{"id": "x", "require_attributes": {"marital_status": "married", "shoe_size": 42}}]}
    errs = " ".join(check_policy(bad, reg))
    assert "forbidden attribute marital_status" in errs and "unregistered attribute shoe_size" in errs


def test_one_execution_path_with_gates_records_and_proposals_only_for_agents():
    import yaml as _y
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from automate import request_hash, run, verify
    from signing import public_b64, sign
    root = Path(__file__).resolve().parent.parent
    auto = _y.safe_load((root / "governance" / "autonomy.yaml").read_text(encoding="utf-8"))
    owner_key, rogue_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    reg = {"approver_roles": ["owner"], "approvers": {"owner-1": {"roles": ["owner"], "public_key": public_b64(owner_key)}}}
    from automate import approval_payload
    _n = iter(range(1000))
    def approve(by, key, req, role="owner", expires="2027-01-01"):
        nonce = f"n{next(_n)}"
        return {"by": by, "role": role, "nonce": nonce, "expires": expires,
                "signature": sign(key, approval_payload(request_hash(req), role, nonce, expires))}
    chain, done = [], []
    ex = lambda req: done.append(req["action"]) or "ok"
    wf = {"type": "workload", "id": "spiffe://vdh/site-a/argo"}
    r1 = run({"subject": wf, "action": "reconcile-config", "tier": "high-appetite"}, auto, True, [], chain, ex, reg)
    assert r1["level"] == "autonomous" and r1["result"].startswith("executed")
    req = {"subject": wf, "action": "grant-access", "tier": "high-appetite", "target": "user-x", "trace_id": "t1", "now": "2026-10-06"}
    assert run(req, auto, True, [], chain, ex, reg)["result"].startswith("waiting")
    # an unsigned, forged, unregistered or self approval does not count
    assert run(req, auto, True, [{"by": "owner-1", "role": "owner", "hash": request_hash(req)}], chain, ex, reg)["result"].startswith("waiting")
    assert run(req, auto, True, [approve("owner-1", owner_key, req, expires="2026-01-01")], chain, ex, reg)["result"].startswith("waiting")
    assert run(req, auto, True, [approve("owner-1", rogue_key, req)], chain, ex, reg)["result"].startswith("waiting")
    assert run(req, auto, True, [approve("mallory", rogue_key, req)], chain, ex, reg)["result"].startswith("waiting")
    other = {**req, "target": "user-y"}
    assert run(req, auto, True, [approve("owner-1", owner_key, other)], chain, ex, reg)["result"].startswith("waiting")
    good = approve("owner-1", owner_key, req)
    ok = run(req, auto, True, [good], chain, ex, reg)
    assert ok["result"].startswith("executed") and ok["approved_by"] == ["owner-1"]
    # UC-03: the same approval cannot be replayed
    assert run(req, auto, True, [good], chain, ex, reg)["result"].startswith("waiting")
    r = run({"subject": wf, "action": "reconcile-config", "tier": "high-appetite", "contexts": ["label-restricted"], "now": "2026-10-06"}, auto, True, [], chain, ex, reg)
    assert r["result"].startswith("waiting")
    assert run({"subject": wf, "action": "reconcile-config", "tier": "high-appetite"}, auto, False, [], chain, ex, reg)["result"].startswith("refused")
    agent = {"type": "agent", "id": "analyst-1"}
    assert run({"subject": agent, "action": "quarantine-host", "tier": "high-appetite"}, auto, True, [], chain, ex, reg)["result"] == "refused: agents only propose"
    assert run({"subject": agent, "action": "quarantine-host", "tier": "high-appetite", "mode": "propose"}, auto, True, [], chain, ex, reg)["result"].startswith("proposed")
    assert done == ["reconcile-config", "grant-access"]
    assert len(chain) == 13 and verify(chain)
    chain[3]["result"] = "executed: ok"
    assert not verify(chain)


def test_the_notify_level_tells_a_person_and_approvals_fail_closed_without_a_time():
    """governance/autonomy.yaml defines notify as 'a person is told at once and can undo'. The execution
    path refuses a notify-level action without a notifier and records what it told; a level that needs approval refuses
    a request without `now`, so an approval's expiry cannot pass by default."""
    import yaml as _y
    from automate import run, verify
    root = Path(__file__).resolve().parent.parent
    auto = _y.safe_load((root / "governance" / "autonomy.yaml").read_text(encoding="utf-8"))
    chain, done, told = [], [], []
    ex = lambda req: done.append(req["action"]) or "ok"
    wf = {"type": "workload", "id": "spiffe://vdh/site-a/argo"}
    req = {"subject": wf, "action": "quarantine-host", "tier": "low-appetite", "target": "node-2"}
    r = run(req, auto, True, [], chain, ex)
    assert r["level"] == "notify" and r["result"] == "refused: the notify level needs a notifier" and done == []
    r = run(req, auto, True, [], chain, ex, notify=lambda rec: told.append(rec["action"]) or "ntfy")
    assert r["result"] == "executed: ok" and r["notified"] == "ntfy" and told == ["quarantine-host"]
    g = run({"subject": wf, "action": "grant-access", "tier": "high-appetite", "target": "user-x"}, auto, True, [], chain, ex)
    assert g["result"] == "refused: no time to check approvals against"
    assert done == ["quarantine-host"] and verify(chain)


def test_self_hosting_has_no_unbroken_cycle_and_a_small_out_of_band_set():
    import copy as _c
    import yaml as _y
    from bootstrap_check import check, cycles, load
    b = load()
    assert check(b) == []
    edges = {k: list(v) for k, v in b["depends_on"].items()}
    for k, v in b["repair_needs"].items():
        edges.setdefault(k, []).extend(v)
    assert cycles(edges), "the repair loops must be visible, not hidden"
    assert len(b["out_of_band"]) <= 6 and all(v["drill"] for v in b["out_of_band"].values())
    # a new hidden loop is caught: K3s secrets through OpenBao would create k3s <-> openbao
    bad = _c.deepcopy(b); bad["depends_on"]["k3s"].append("openbao")
    assert any("unbroken cycle" in e and "k3s" in e for e in check(bad))
    # self-management never widens its own trust
    sm = b["self_management"]
    assert set(sm["allowed_in_band"]) <= {"observe", "restore", "reduce"}
    root = Path(__file__).resolve().parent.parent
    auto = _y.safe_load((root / "governance" / "autonomy.yaml").read_text(encoding="utf-8"))
    assert all(a not in auto["actions"] or auto["actions"][a]["direction"] != "increase" for a in sm["allowed_in_band"])


def test_communication_plan_reaches_the_right_people_independently_and_is_tested_daily():
    from notify import check_people, load, plan, test_state
    comm = load()
    ceo = {"id": "director", "criticality": "mission-critical", "depends_on": ["vault"], "delegate": "assistant",
           "channels": ["matrix", "push", "sms-gsm", "voice"]}
    analyst = {"id": "analyst", "criticality": "key-user", "depends_on": ["vault"], "delegate": "lead", "channels": ["matrix", "mail"]}
    other = {"id": "other", "criticality": "user", "depends_on": ["chat"], "channels": ["mail"]}
    assert check_people(comm, [ceo, analyst, other]) == []
    weak = {**ceo, "channels": ["matrix", "mail", "push"], "delegate": None}
    errs = " ".join(check_people(comm, [weak]))
    assert "without the network" in errs and "no delegate" in errs
    # an outage of the vault reaches the director first, platform-independent and offline channels first, up to the site contact
    p = plan({"trigger": "outage-detected", "capability": "vault"}, comm, [analyst, other, ceo], NOW)
    assert [x["person"] for x in p] == ["director", "analyst"]
    assert p[0]["channels"][0] in ("sms-gsm", "voice") and p[0]["ladder"] == ["person", "delegate", "site-contact", "service-owner"]
    # maintenance announced 24 h ahead is too late for the director (72 h) and the key user (48 h)
    m = plan({"trigger": "planned-maintenance", "capability": "vault", "starts_at": NOW + timedelta(hours=24)}, comm, [ceo, analyst], NOW)
    assert m[0]["late_notice"] and m[1]["late_notice"]
    # the communication tests themselves are a control
    fresh = {"daily_silent": NOW - timedelta(hours=3), "weekly_acknowledged": NOW - timedelta(days=2)}
    assert test_state(comm, fresh, NOW) == "GREEN"
    assert test_state(comm, {**fresh, "daily_silent": NOW - timedelta(hours=30)}, NOW) == "AMBER"
    assert test_state(comm, {**fresh, "weekly_acknowledged": None}, NOW) == "RED"


def test_environments_promote_signed_bundles_and_never_share_trust_or_real_data():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    env = _y.safe_load((root / "platform" / "environments.yaml").read_text(encoding="utf-8"))
    es = env["environments"]
    chain, cur = [], "development"
    while cur:
        chain.append(cur); cur = es[cur]["promotes_to"]
    assert chain == ["development", "test", "acceptance", "production"]
    for name, e in es.items():
        assert e["trust_domain"] == "own"
        # real or pseudonymised content inherits production's controls for its label
        if e["content"] in ("real", "pseudonymised"):
            assert e["controls"] in ("production", "production-equivalent"), name
        # wherever results or training must transfer, the data is representative of production
        if name in ("test", "acceptance", "education"):
            assert e["fidelity"]["schema"] == "same" and e["fidelity"]["volume"] == "representative", name
            assert e["fidelity"]["traffic"] != "none", name
    assert es["acceptance"]["content"] == "pseudonymised" and es["acceptance"]["max_label"] != "Internal"
    assert "no content" in env["profiles"]["extraction"] and "ai-egress-gate" in env["profiles"]["labelling"]
    assert es["education"]["release"] == "same-as-production"
    assert "ephemeral" in es["sandbox"]["lifetime"] and es["sandbox"]["budget_eur_per_day"] > 0
    pub = " ".join(env["publication"]["never_published"])
    assert "tenant identities" in pub and "secrets" in pub


def test_every_size_bootstraps_in_dependency_order_and_decommissions_in_reverse():
    import yaml as _y
    from lifecycle import bootstrap_order, components, decommission_order
    root = Path(__file__).resolve().parent.parent
    needs = _y.safe_load((root / "platform" / "lifecycle.yaml").read_text(encoding="utf-8"))["needs"]
    for size in ("S", "M", "L"):
        comps = components(size)
        order = bootstrap_order(comps, needs)
        assert set(order) == set(comps), size
        pos = {c: i for i, c in enumerate(order)}
        for c in comps:
            assert all(d == "host" or pos[d] < pos[c] for d in needs[c]), (size, c)
        assert decommission_order(order)[0] == order[-1]
    # S must not depend on anything outside S
    s = bootstrap_order(components("S"), needs)
    assert s.index("OpenBao") < s.index("Keycloak") < s.index("CryptPad")
    bad = {**needs, "K3s": ["host", "Keycloak"]}
    with pytest.raises(ValueError):
        bootstrap_order(components("S"), bad)


def test_return_after_absence_or_break_glass_is_classified_and_never_silently_trusted():
    from reconcile import ORDER, plan
    grace, max_abs = 8, 720
    seen = lambda h: {"last_seen": (NOW - timedelta(hours=h)).isoformat()}
    proven = {"chain_ok": True, "attestation_ok": True}
    short = plan(proven, seen(3), NOW, grace, max_abs)
    assert short["class"] == "short" and short["steps"][0] == "resync revocations" and short["readmission_authority"] == "autonomous"
    assert [s.replace("resync ", "") for s in short["steps"]] == ORDER
    # absence comes from the centre's records, not from what the site says
    liar = {**proven, "absent_hours": 1}
    assert plan(liar, seen(30), NOW, grace, max_abs)["class"] == "long"
    # what the site cannot prove counts as failed
    assert plan({"absent_hours": 1}, seen(1), NOW, grace, max_abs)["class"] == "stale"
    bg = plan({**proven, "break_glass_events": [
        {"id": "BG-1", "action": "opened local firewall for a field radio", "ratified": True},
        {"id": "BG-2", "action": "added a local admin account", "ratified": False},
        {"id": "BG-3", "action": "extended a session", "ratified": None}]}, seen(30), NOW, grace, max_abs)
    assert bg["class"] == "long" and bg["readmission_authority"] == "gated"
    assert bg["steps"][0].startswith("quarantine") and "rotate break-glass credentials" in bg["steps"]
    out = {a["id"]: a["outcome"] for a in bg["break_glass"]}
    assert out["BG-1"].startswith("ratified") and out["BG-2"].startswith("not ratified") and out["BG-3"].startswith("pending")
    # break-glass the site did not report, but the centre saw in the credential use log, still counts
    hidden = plan(proven, {**seen(1), "break_glass_uses": [{"id": "BG-9", "action": "ssh as root"}]}, NOW, grace, max_abs)
    assert hidden["class"] == "long" and "incident: break-glass use not reported by the site" in hidden["steps"]
    for site, centre in ((proven, seen(1000)), ({**proven, "chain_ok": False}, seen(2)),
                         ({**proven, "attestation_ok": False}, seen(2)), (proven, {**seen(2), "compromise_suspected": True})):
        p = plan(site, centre, NOW, grace, max_abs)
        assert p["class"] == "stale" and p["readmission_authority"] == "external"
        assert "wipe and reinstall from the signed image" in p["steps"] and "import data only through inspection" in p["steps"]


def test_data_platform_publishes_once_and_subscribes_through_policy_and_labels():
    import copy as _c
    from dataproducts import check, connections, load, subscribe
    dp = load()
    assert check(dp) == []
    # build the integration once: n connections instead of n*(n-1)/2
    c = connections(20)
    assert c["backbone"] == 20 and c["bilateral"] == 190
    # a point-to-point integration is rejected
    bad = _c.deepcopy(dp); bad["integrations"].append({"from": "hr-system", "to": "scheduling-app", "via": "file-drop"})
    assert any("bilateral" in e for e in check(bad))
    # a product without an owner or usage policy is rejected
    bad2 = _c.deepcopy(dp); bad2["products"]["hr-roster"].pop("purposes")
    assert any("missing purposes" in e for e in check(bad2))
    hr, sensors, cases = dp["products"]["hr-roster"], dp["products"]["sensor-telemetry"], dp["products"]["case-files-index"]
    assert subscribe(hr, {"purpose": "scheduling", "environment_label": "Sensitive"}, True)["decision"] == "allow"
    assert subscribe(hr, {"purpose": "marketing", "environment_label": "Sensitive"}, True)["decision"] == "deny"
    assert subscribe(hr, {"purpose": "scheduling", "environment_label": "Sensitive"}, False)["decision"] == "deny"
    # a consumer below the product's label goes through the release gateway, never directly
    assert subscribe(cases, {"purpose": "case-handling", "environment_label": "Internal"}, True)["decision"] == "release-gateway"
    assert subscribe(sensors, {"purpose": "analytics", "environment_label": "Restricted"}, True)["decision"] == "allow"
    # the backbone survives at the edge; MinIO is not used
    assert "leaf nodes" in dp["backbone"]["events"] and "MinIO is not used" in dp["backbone"]["storage"]


def test_data_and_ai_lifecycle_labels_inference_agents_and_protection():
    import copy as _c
    from datetime import date as _d
    from datalife import check_agent, check_products, load, output_label, route_inference
    cfg = load()
    # AI output inherits the highest input label
    assert output_label(["Internal", "Sensitive"]) == "Sensitive" and output_label([]) == "Restricted"
    local = {"kind": "local", "max_label": "Sensitive"}
    assert route_inference("Sensitive", local, False, False)["allowed"]
    assert not route_inference("Restricted", local, True, True)["allowed"]
    external = {"kind": "external"}
    assert not route_inference("Restricted", external, True, True)["allowed"]
    assert not route_inference("Internal", external, False, True)["allowed"]
    # revised under ADR-0164 points 3 and 6 (ADR-0087): consent and pseudonymisation claimed by the caller no longer
    # open an external route; only a registered AI egress gate that can forward externally does
    assert not route_inference("Internal", external, True, True)["allowed"]
    # agents are registered identities with an owner, a delegator, tools and an expiry
    agent = {"id": "summariser", "owner": "service-owner", "delegator": "consultant-1", "purpose": "summarise case files",
             "tools": ["read-vault"], "max_label": "Sensitive", "autonomy": "gated", "expires": "2026-12-01"}
    assert check_agent(agent, cfg, _d(2026, 10, 6)) == []
    errs = " ".join(check_agent({**agent, "expires": "2027-10-06", "owner": None}, cfg, _d(2026, 10, 6)))
    assert "missing owner" in errs and "longer than 90 days" in errs
    assert any("autonomous" in e for e in check_agent({**agent, "autonomy": "autonomous", "max_label": "Restricted"}, cfg, _d(2026, 10, 6)))
    # protection and retention per product are decided and consistent
    assert check_products(cfg) == []
    bad = _c.deepcopy(cfg); bad["products"]["hr-roster"]["backup_retention_days"] = 400
    bad["products"]["case-files-index"]["rpo_hours"] = 24
    errs = " ".join(check_products(bad))
    assert "destruction would not complete" in errs and "RPO of at most 4 hours" in errs
    # reuse first: vector search inside PostgreSQL; excluded tools stay excluded
    assert "pgvector inside the existing PostgreSQL" in cfg["ai"]["retrieval"]["vector_store"]
    assert {"Soda Core", "Weaviate", "Langfuse", "MinIO"} <= set(cfg["excluded"])
    assert "append-only" in cfg["protection"]["cyber_vault"] and "crypto-erasure" in cfg["lifecycle"]["destruction"]


def test_data_mesh_self_serve_products_and_federated_governance():
    import copy as _c
    from dataproducts import check_overlays, load, resolve_product
    dp = load()
    assert check_overlays(dp) == []
    for dom, d in dp["mesh"]["domains"].items():
        assert d["owner"] and all(p in dp["products"] for p in d["products"]), dom
    intent = {"name": "shift-plan", "domain": "people", "owner": "hr-service-owner", "label": "Sensitive",
              "schema": "shift-plan-v1", "purposes": ["scheduling"], "quality_suite": "shift-plan-checks",
              "lineage": True, "retention_days": 365, "review_months": 12, "tabular": True}
    r = resolve_product(intent, dp)
    assert r["errors"] == []
    assert r["subject"] == "products.people.shift-plan.v1" and r["table"] == "people.shift-plan_v1"
    assert r["access_policy"]["mask_personal_data"] and r["access_policy"]["min_consumer_label"] == "Sensitive"
    assert r["destruction"]["method"] == "crypto-erasure" and r["dataspace_asset"] is None
    # the domain overlay tightens: people may keep Sensitive data at most 730 days, though the global cap is 3650
    long = resolve_product({**intent, "retention_days": 1000}, dp)
    assert any("allowed 730" in e for e in long["errors"])
    assert resolve_product({**intent, "domain": "operations", "retention_days": 1000}, dp)["errors"] == []
    # a product without owner or quality checks is not a product
    bare = resolve_product({k: v for k, v in intent.items() if k not in ("owner", "quality_suite")}, dp)
    assert "missing owner" in bare["errors"] and "missing quality_suite" in bare["errors"]
    # a domain may not loosen the global policy
    loose = _c.deepcopy(dp); loose["mesh"]["domain_overlays"]["people"]["max_retention_days"]["Sensitive"] = 9999
    assert check_overlays(loose)
    # sharing with partners turns the product into a dataspace asset
    assert resolve_product({**intent, "share_with_partners": True}, dp)["dataspace_asset"] == "edc:shift-plan-v1"


def test_release_gateway_meets_every_ncsc_cross_domain_principle_and_states_its_prior_art():
    from release_gateway import load
    gw = load()
    principles = {"network-protocol-attack-protection", "content-based-attack-protection", "protect-against-unauthorised-export",
                  "session-isolation", "persistent-compromise-protection", "people-and-the-cds", "management",
                  "audit-and-accounting", "authentication", "data-in-transit-protection", "data-at-rest-protection",
                  "patching", "component-integrity"}
    assert set(gw["ncsc_cds_principles"]) == principles and all(gw["ncsc_cds_principles"].values())
    names = {o["name"] for o in gw["prior_art"]["open_source"]}
    assert {"Dangerzone", "Open Source Data Diode (OSDD)", "OpenTDF"} <= names
    assert "no maintained, complete open-source export guard" in gw["prior_art"]["gap"]


def test_sealed_artefact_travels_low_and_reopens_only_on_a_compliant_system():
    import copy as _c
    import json as _j
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sealed import KAS, build, reimport
    kas, signer = KAS(), Ed25519PrivateKey.generate()
    secret = b"Grid substation 14 isolation sequence: open breaker B2, then B5"
    parts = [{"id": "s1", "label": "Internal", "content": b"Maintenance window planned for week 42."},
             {"id": "s2", "label": "Restricted", "content": secret},
             {"id": "s3", "label": "Internal", "content": b"Contact the site lead for access."}]
    art = build(parts, "Internal", kas, signer, "2027-10-06T00:00:00+00:00")
    blob = _j.dumps(art)
    # the carrier holds no Restricted plaintext and reveals only a padded size bucket
    assert secret.decode() not in blob and "substation" not in blob
    assert art["manifest"]["contains_sealed"] == ["Restricted"]
    import base64 as _b
    assert len(_b.b64decode(art["manifest"]["sealed"]["s2"]["ciphertext"])) == 1024 + 16
    pub = signer.public_key()
    # on the low side (no attestation, no attributes) the sealed segment stays a placeholder
    low = reimport(art, pub, kas, {"id": "laptop", "trust_anchor_ok": False, "attributes": []}, NOW)
    assert low["ok"] and low["document"][1] == "[sealed Restricted segment]"
    # a compliant system without the attribute cannot open it either
    nocl = reimport(art, pub, kas, {"id": "sys-a", "trust_anchor_ok": True, "attributes": ["clearance:internal"]}, NOW)
    assert nocl["document"][1].startswith("[sealed")
    # a compliant, attested system with the attribute re-renders the original exactly
    ok = reimport(art, pub, kas, {"id": "sys-b", "trust_anchor_ok": True, "attributes": ["clearance:restricted"]}, NOW)
    assert ok["document"] == [p["content"].decode() for p in parts]
    # every key request is logged, granted or not
    assert [e["granted"] for e in kas.log] == [False, False, True]
    # tampering with the manifest or the bound policy is detected
    bad = _c.deepcopy(art); bad["manifest"]["sealed"]["s2"]["policy"]["attributes"] = []
    assert not reimport(bad, pub, kas, {"id": "sys-b", "trust_anchor_ok": True, "attributes": []}, NOW)["ok"]
    # revocation and expiry make every copy unreadable
    kas.revoked.add("s2")
    assert reimport(art, pub, kas, {"id": "sys-b", "trust_anchor_ok": True, "attributes": ["clearance:restricted"]}, NOW)["document"][1].startswith("[sealed")
    kas.revoked.clear()
    late = NOW.replace(year=2028)
    assert reimport(art, pub, kas, {"id": "sys-b", "trust_anchor_ok": True, "attributes": ["clearance:restricted"]}, late)["document"][1].startswith("[sealed")


def test_every_component_implements_an_open_interface_with_an_exit():
    import yaml as _y
    from lifecycle import components
    root = Path(__file__).resolve().parent.parent
    itf = _y.safe_load((root / "catalog" / "interfaces.yaml").read_text(encoding="utf-8"))
    sizes = _y.safe_load((root / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    caps = itf["capabilities"]
    implemented = {c for cap in caps.values() for c in cap["implementations"]}
    runtime = set(components("L"))
    runtime |= {c["component"] for m in sizes["modules"].values() for c in m.get("components", [])}
    # every runtime component, in every size and module, is an implementation of a named capability
    assert runtime - implemented == set(), sorted(runtime - implemented)
    import yaml as _yy
    contracted = set(_yy.safe_load((root / "catalog" / "contracts.yaml").read_text(encoding="utf-8"))["contracts"])
    for name, cap in caps.items():
        assert cap["interface"] and cap["exit"], name
        assert cap["lock_in"] in ("none", "low", "medium", "high"), name
        # contracted capabilities: lock-in is computed from the contract (ADR-0072, tested there); the others keep the
        # earlier rule: without a drop-in alternative the interface must be a standard (none/low)
        if name not in contracted and not cap["alternatives"]:
            assert cap["lock_in"] in ("none", "low"), name
    # high lock-in only for own code without an alternative, or where an export path carries the risk
    high = {n for n, c in caps.items() if c["lock_in"] == "high"}
    assert all("own code" in caps[n]["exit"] or "export" in caps[n]["exit"] for n in high), high
    assert any("front-ends talk only to versioned APIs" in r for r in itf["rules"])


def test_gateway_stays_a_dumb_pipe_and_does_not_become_an_esb():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    gw = _y.safe_load((root / "platform" / "gateway.yaml").read_text(encoding="utf-8"))
    assert {"payload transformation", "business rules", "orchestration of several backend calls",
            "hand-written filters or scripts"} <= set(gw["gateway_must_not"])
    # no route may claim transformation or orchestration as the gateway's job
    for name, r in gw["routes"].items():
        text = (r["via"] + " " + r["enforcement"]).lower()
        assert "transform" not in text and "orchestrat" not in text, name
    assert len(gw["not_an_esb"]) == 4


def test_stack_is_locked_versioned_and_released_only_through_the_full_pyramid():
    import copy as _c
    from datetime import date as _d
    import yaml as _y
    from lifecycle import components
    from stack import lock_errors, load, next_version, release_blockers
    root = Path(__file__).resolve().parent.parent
    cfg, lock = load("platform/stack-release.yaml"), load("platform/stack.lock.yaml")
    sizes = load("platform/sizes.yaml")
    bom = {c["name"]: c["licence"] for c in load("bom/bill-of-materials.yaml")["software"]}
    runtime = set(components("L")) | {c["component"] for m in sizes["modules"].values() for c in m.get("components", [])}
    runtime |= {p["name"] for c in sizes["core"] for p in c.get("parts", [])}   # parts are locked and reviewed too (ADR-0006 amendment)
    # every runtime component is in the lock with the BOM licence; a draft may have pending digests
    assert lock_errors(lock, runtime, bom, _d(2027, 10, 6)) == []
    released = _c.deepcopy(lock); released["status"] = "released"
    assert any("sha256 digest" in e for e in lock_errors(released, runtime, bom, _d(2027, 10, 6)))
    missing = _c.deepcopy(lock); missing["components"].pop("Keycloak")
    assert any("Keycloak: not pinned" in e for e in lock_errors(missing, runtime, bom, _d(2027, 10, 6)))
    eol = _c.deepcopy(lock); eol["components"]["K3s"]["eol"] = "2027-01-31"
    assert any("end of life" in e for e in lock_errors(eol, runtime, bom, _d(2027, 10, 6)))
    wrong = _c.deepcopy(lock); wrong["components"]["Grafana"]["licence"] = "Apache-2.0"
    assert any("differs from the bill of materials" in e for e in lock_errors(wrong, runtime, bom, _d(2027, 10, 6)))
    # the change class sets the version bump
    assert [next_version("1.4.2", c) for c in ("standard", "normal", "major")] == ["1.4.3", "1.5.0", "2.0.0"]
    # a release is blocked by any required stage that did not run or failed; majors need the most
    ok = {s: True for s in cfg["required_for"]["major"]}
    assert release_blockers(cfg, "major", ok) == [] and release_blockers(cfg, "patch", ok) == []
    assert release_blockers(cfg, "minor", {**ok, "chaos-ddil": False}) == ["chaos-ddil: failed"]
    assert "scenario: did not run" in release_blockers(cfg, "minor", {k: v for k, v in ok.items() if k != "scenario"})
    assert set(cfg["required_for"]["patch"]) <= set(cfg["required_for"]["minor"]) <= set(cfg["required_for"]["major"])
    assert {"upgrade", "recovery"} <= set(cfg["required_for"]["patch"])


def test_s_upgrades_to_m_and_l_by_adding_never_by_swapping():
    import yaml as _y
    from lifecycle import components
    root = Path(__file__).resolve().parent.parent
    ld = lambda rel: _y.safe_load((root / rel).read_text(encoding="utf-8"))
    itf, up, sizes = ld("catalog/interfaces.yaml"), ld("platform/upgrade-path.yaml"), ld("platform/sizes.yaml")
    S, M, L = set(components("S")), set(components("M")), set(components("L"))
    assert S < M < L
    # per capability: the implementations present grow with the size and never change primary
    for name, cap in itf["capabilities"].items():
        impl = set(cap["implementations"])
        present = [impl & S, impl & M, impl & L]
        assert present[0] <= present[1] <= present[2], name
        if cap.get("primary"):
            first = next((p for p in present if p), set())
            assert not first or cap["primary"] in first, name
    # the scaling dimensions exist from day one in the core, not added later
    core = {c["component"] for c in sizes["core"]}
    assert {"Envoy Gateway", "CloudNativePG", "Cilium", "OpenBao", "K3s"} <= core
    notes = " ".join(c.get("note", "") for c in sizes["core"])
    assert "embedded etcd from S" in notes and "Raft storage from S" in notes
    assert {"Caddy", "pgBackRest"} <= set(sizes["retired"])
    assert any("no swaps" in r for r in up["rules"]) and "S-to-M" in up["transitions"]


def test_focal_point_denies_cross_tenant_access():
    import yaml as _y
    from authz import decide, load
    root = Path(__file__).resolve().parent.parent
    reg = load()
    pol = _y.safe_load((root / "policies" / "vault-access.yaml").read_text(encoding="utf-8"))
    t = (NOW - timedelta(minutes=5)).isoformat()
    cv = lambda v: {"value": v, "at": t}
    who = lambda tenant: {"type": "person", "id": f"u-{tenant}", "attributes": {"role": cv("consultant"), "acr": cv("phishing-resistant"), "tenant": cv(tenant)}}
    ctx = {"device_posture": cv("compliant"), "evidence_state": cv("GREEN")}
    req = lambda s, tenant: {"subject": s, "action": {"name": "read"}, "resource": {"type": "sensitive-document", "tenant": tenant}, "context": ctx}
    _d, _g = decide, _grants(("u-t-a", "consultant"), ("sum", "consultant"))
    decide = lambda r, p, rg, n: _d(r, p, rg, n, _g)   # roles from grant records
    assert decide(req(who("t-a"), "t-a"), pol, reg, NOW)["decision"]
    r = decide(req(who("t-a"), "t-b"), pol, reg, NOW)
    assert not r["decision"] and any("cross-tenant" in x for x in r["reasons"])
    agent = {"type": "agent", "id": "sum", "attributes": {"role": cv("consultant"), "acr": cv("phishing-resistant"), "tenant": cv("t-a")}}
    assert not decide({**req(agent, "t-b"), "actors": [who("t-a")]}, pol, reg, NOW)["decision"]


def test_reconnect_pipeline_reprofiles_measures_drift_scores_risk_and_gates_the_decision():
    from datetime import timedelta as td
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from federate import aggregate, sign
    from rejoin import decide
    expected = {"components": {"keycloak": "26.8", "opa": "1.9"}, "policy_bundle": "b42",
                "cache_max_hours": {"policy-bundle": 8}, "flows": [["a", "b", 443, "tcp"]], "config": {"tls": "1.3"}}
    seen = lambda h: {"last_seen": (NOW - td(hours=h)).isoformat()}
    clean = {"id": "site-7", "chain_ok": True, "attestation_ok": True, "components": {"keycloak": "26.8", "opa": "1.9"},
             "policy_bundle": "b42", "cache_age_hours": {"policy-bundle": 2}, "observed_flows": [["a", "b", 443, "tcp"]], "config": {"tls": "1.3"}}
    r = decide(clean, seen(3), expected, NOW, 8, 720)
    assert r["risk"] == "low" and r["approval"] == "autonomous" and r["action"] == "reconcile"
    # drift and a stale cache after a long absence: quarantine first, gated or human
    drifted = {**clean, "observed_flows": [["a", "b", 443, "tcp"], ["a", "pastebin", 443, "tcp"]], "config": {"tls": "1.2"},
               "cache_age_hours": {"policy-bundle": 30}}
    r2 = decide(drifted, seen(30), expected, NOW, 8, 720)
    assert r2["risk"] in ("medium", "high") and r2["approval"] in ("gated", "human") and "quarantine" in r2["action"]
    assert any("pastebin" in x for x in r2["drift"]) and "config tls" in r2["drift"]
    # unexpected software or failed attestation: destroy and rebuild, external authority
    implant = {**clean, "components": {**clean["components"], "netcat": "1.0"}, "attestation_ok": False}
    r3 = decide(implant, seen(3), expected, NOW, 8, 720)
    assert r3["risk"] == "critical" and r3["approval"] == "external" and r3["action"].startswith("destroy")
    # the risk owner sees plain language
    assert any("Risk:" in line for line in r2["card"]) and not any("tcp" in line for line in r2["card"])
    # NET-07: a last-seen in the future never shortens the return
    assert decide(clean, {"last_seen": (NOW + td(days=3)).isoformat()}, expected, NOW, 8, 720)["class"] == "stale"
    # NET-06: a malformed child turns RED; the others still count
    k = {"a": Ed25519PrivateKey.generate(), "b": Ed25519PrivateKey.generate()}
    hdr = lambda name: {"child": name, "audience": "region-1", "seq": 1}   # ADR-0126
    st_b = hdr("b") | {"overall": "GREEN", "evaluated_at": (NOW - td(hours=1)).isoformat()}
    bad = hdr("a") | {"overall": "BLUE", "evaluated_at": (NOW - td(hours=1)).isoformat()}
    out = aggregate({"a": {"status": bad, "signature": sign(k["a"], bad)}, "b": {"status": st_b, "signature": sign(k["b"], st_b)}},
                    {n: key.public_key() for n, key in k.items()}, {"a": td(hours=4), "b": td(hours=4)}, "GREEN", NOW,
                    parent="region-1", seen={})
    assert out["children"]["a"]["state"] == "RED" and out["children"]["b"]["state"] == "GREEN"
    broken = {"status": {"overall": "GREEN"}, "signature": "x"}
    assert aggregate({"a": broken}, {"a": k["a"].public_key()}, {"a": td(hours=4)}, "GREEN", NOW, parent="region-1",
                     seen={})["overall"] == "RED"


def test_ztop_shows_the_live_trust_state_per_request_path_and_never_trusts_silence():
    from datetime import timedelta as td
    import yaml as _y
    from ztop import picture
    root = Path(__file__).resolve().parent.parent
    zt = _y.safe_load((root / "platform" / "zero-trust.yaml").read_text(encoding="utf-8"))
    peps = {pep for p in zt["request_paths"] for pep in p["peps"]}
    sigs = {s for p in zt["request_paths"] for s in p["signals"] if s != "signature"}
    fresh = (NOW - td(minutes=5)).isoformat()
    ok = {pep: {"at": fresh, "enforcing": True, "bundle": "b42"} for pep in peps}
    sig = {s: {"at": fresh} for s in sigs}
    pic = picture(zt, ok, sig, "b42", NOW, td(hours=1))
    # everything enforcing on the current bundle with fresh signals: green, except the declared bypass
    assert pic["paths"]["person to application"]["state"] == "GREEN"
    assert pic["paths"]["break-glass to infrastructure"]["state"] == "AMBER" and pic["overall"] == "AMBER"
    # one silent enforcement point makes every path through it UNKNOWN, never green
    silent = {k: v for k, v in ok.items() if k != "Cilium"}
    p2 = picture(zt, silent, sig, "b42", NOW, td(hours=1))
    assert p2["paths"]["person to application"]["state"] == "UNKNOWN" and p2["paths"]["person to application"]["peps"]["Cilium"] == "UNKNOWN"
    # an outdated bundle is AMBER; a point that stopped enforcing is RED; a stale signal is UNKNOWN
    old_bundle = {**ok, "NetBird": {**ok["NetBird"], "bundle": "b41"}}
    assert picture(zt, old_bundle, sig, "b42", NOW, td(hours=1))["paths"]["device to network"]["state"] == "AMBER"
    off = {**ok, "Envoy Gateway": {**ok["Envoy Gateway"], "enforcing": False}}
    assert picture(zt, off, sig, "b42", NOW, td(hours=1))["overall"] == "RED"
    stale_sig = {**sig, "device_posture": {"at": (NOW - td(hours=5)).isoformat()}}
    p3 = picture(zt, ok, stale_sig, "b42", NOW, td(hours=1))
    assert p3["paths"]["person to application"]["state"] == "UNKNOWN" and "device_posture" in p3["paths"]["person to application"]["stale_signals"]


def test_every_component_is_alive_supportable_and_has_an_eu_path_or_an_accepted_gap():
    import copy as _c
    from datetime import date as _d
    from provenance import check, eu_path, flags, load as pload
    prov, iface = pload()
    today = _d.fromisoformat(prov["checked"])
    assert check(prov, iface, today) == []
    # the measured findings stay visible
    assert "stale" in flags("mat2", prov, today) and "bus-factor" in flags("ExifTool", prov, today)
    assert eu_path("Proxmox VE", prov, iface).startswith("steward") and eu_path("Synapse", prov, iface)  # ADR-0114: Synapse runs, its own European path
    bad = _c.deepcopy(prov); bad["components"]["K3s"]["signals"]["archived"] = True
    assert "K3s: archived" in check(bad, iface, today)
    old = _c.deepcopy(prov); old["components"]["NATS"]["signals"].update(release_date="2025-01-01", last_activity="2025-01-01")
    assert any("NATS: stale runtime" in e for e in check(old, iface, today))
    gap = _c.deepcopy(prov); gap["components"]["Proxmox VE"].update(region="non-eu", support=[])
    assert any("Proxmox VE: sovereignty gap not accepted" in e for e in check(gap, iface, today))
    fixed = _c.deepcopy(prov); fixed["components"]["Grafana"]["support"].append("EU partner (NL)")
    assert any("Grafana: listed as a sovereignty gap but has an EU" in e for e in check(fixed, iface, today))
    small = _c.deepcopy(prov); small["bus_factor_accepted"].pop("ExifTool")   # ADR-0114: Tuwunel is no longer a runtime component
    assert any("ExifTool: bus factor" in e for e in check(small, iface, today))


def test_every_component_has_a_resilience_profile_and_every_seam_an_outside_watcher():
    import copy as _c
    from resilience import blast, check, load as rload, spofs
    res, seams, sizes = rload()
    assert check(res, seams, sizes) == []
    # the sizes differ in what is restored versus failed over
    assert "OpenBao" in spofs(res, sizes, "S") and "OpenBao" not in spofs(res, sizes, "M")
    assert spofs(res, sizes, "L") == ["CryptPad", "KeyClerk", "NetBird"]   # Warpgate clusters in L; KeyClerk is one writer by design, its failure leaves grants in place
    # blast radius: PostgreSQL backs identity, the portal and more; K3s failing is static for running pods
    pg = blast("PostgreSQL", res, seams, "M")
    assert {"Keycloak", "Backstage", "NetBird"} <= set(pg["backing_for"])
    assert blast("K3s", res, seams, "S")["mode"] == "fail-static"
    # violations are caught
    bad = _c.deepcopy(res); bad["components"]["OpenBao"]["snapshot"] = "allowed"
    assert any("consensus member" in e for e in check(bad, seams, sizes))
    nobk = _c.deepcopy(res); nobk["components"]["Keycloak"].pop("data")
    assert any("Keycloak: holds data but names no backup" in e for e in check(nobk, seams, sizes))
    selfw = _c.deepcopy(seams); selfw["seams"][0]["watch"] = ["evaluator"]; selfw["seams"][0]["to"] = "evaluator"
    assert any("its own parties" in e for e in check(res, selfw, sizes))
    gone = _c.deepcopy(res); gone["components"].pop("Cilium")
    assert any("Cilium has no resilience profile" in e for e in check(gone, seams, sizes))
    assert "MariaDB" in res["undeclared_backing"]   # a backing store not yet declared


def test_host_os_is_decided_and_updated_through_git():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    host = _y.safe_load((root / "platform" / "host-os.yaml").read_text(encoding="utf-8"))
    sizes = _y.safe_load((root / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    assert host["decision"].startswith("SUSE Micro") and "ADR-0050" in host["decision"]
    core = {c["component"]: c["functions"] for c in sizes["core"]}
    assert core["SUSE Micro"] == ["host-os"] and core["system-upgrade-controller"] == ["host-updates"]
    s = host["scores"]["SUSE Micro"]
    assert s["eu_support"] == 3 and s["stack_fit"] == 3 and set(s) >= set(host["criteria"])


def test_boot_stick_works_before_the_network_and_reveals_nothing_without_the_key():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    bs = _y.safe_load((root / "platform" / "boot-stick.yaml").read_text(encoding="utf-8"))
    names = [s["stage"] for s in bs["stages"]]
    first_online = next(i for i, s in enumerate(bs["stages"]) if not s["offline"])
    # sign-in, identity and policy all happen before the first online stage, and nothing offline comes after it
    assert {"sign-in", "identity", "policy"} <= set(names[:first_online])
    assert all(not s["offline"] for s in bs["stages"][first_online:])
    assert bs["offline_limits"]["Restricted"]["allowed"] is False
    assert bs["offline_limits"]["Sensitive"]["max_offline_hours"] < bs["offline_limits"]["Internal"]["max_offline_hours"]
    items = " ".join(i["item"] for i in bs["image_bom"])
    for driver in ("libfido2", "pcsc-lite", "OpenSC", "linux-firmware", "NetworkManager"):
        assert driver in items, driver
    assert any("reveals nothing personal" in i for i in bs["invariants"])
    eid_items = [i for i in bs["image_bom"] if i.get("required_when") == "eid"]
    assert eid_items and "image (not the home)" in eid_items[0]["why"]
    assert "authentication key, never the signature key" in bs["eid"]["key_used"]


def test_four_eyes_release_needs_a_fresh_bound_single_use_approval_by_another_officer():
    from datetime import timedelta as td
    import yaml as _y
    from stick_release import release, required_mode
    cfg = _y.safe_load((Path(__file__).resolve().parent.parent / "platform" / "boot-stick.yaml").read_text(encoding="utf-8"))
    assert required_mode(cfg, "Sensitive", set()) == "self"
    assert required_mode(cfg, "Sensitive", {"new-hardware"}) == "self"   # per-sign-in release is off by default
    on = {**cfg, "release_modes": {**cfg["release_modes"], "risk_triggers_enabled": True}}
    assert required_mode(on, "Sensitive", {"new-hardware"}) == "four-eyes-online"
    assert required_mode(cfg, "Restricted", set()) == "four-eyes-online"
    req = {"user": "u1", "stick": "st-9", "request_id": "r-1"}
    ok = {"approver": "so1", "user": "u1", "stick": "st-9", "request_id": "r-1", "at": NOW - td(minutes=2), "nonce": "n1", "approver_session_online": True}
    used = set()
    assert release(req, ok, NOW, used, {"so1", "so2"})[0] is True
    assert "approval already used" in release(req, ok, NOW, used, {"so1", "so2"})[1]
    assert not release(req, None, NOW, set(), {"so1"})[0]
    assert "four eyes: the approver cannot be the user" in release({**req, "user": "so1"}, {**ok, "user": "so1", "nonce": "n2"}, NOW, set(), {"so1"})[1]
    assert "approval is bound to another stick" in release({**req, "stick": "st-x"}, {**ok, "nonce": "n3"}, NOW, set(), {"so1"})[1]
    assert "approval is not fresh" in release(req, {**ok, "at": NOW - td(minutes=30), "nonce": "n4"}, NOW, set(), {"so1"})[1]
    assert "the officer's own session is not connected and verified" in release(req, {**ok, "approver_session_online": False, "nonce": "n5"}, NOW, set(), {"so1"})[1]


def test_enrolment_ceremony_takes_a_blank_stick_to_offline_sign_in_with_four_eyes():
    from datetime import timedelta as td
    import yaml as _y
    from stick_enrol import enrol
    cfg = _y.safe_load((Path(__file__).resolve().parent.parent / "platform" / "boot-stick.yaml").read_text(encoding="utf-8"))
    steps = [s["step"] for s in cfg["enrolment"]["steps"]]
    assert steps[:3] == ["code", "account", "ticket"] and steps[-2:] == ["offline-test", "record"]
    assert steps.index("sas") < steps.index("identity") < steps.index("keys")   # bind stick and console before anything is issued
    # ADR-0138 revises the officer's terminal from "any thin client" to their own boot stick; "no station" holds
    assert "own boot stick" in cfg["enrolment"]["officer_needs"] and "no station" in cfg["enrolment"]["officer_needs"]
    ticket = {"id": "t-1", "user": "u1", "stick": "st-9", "image_version_min": 7}
    appr = {"approver": "so1", "user": "u1", "stick": "st-9", "request_id": "t-1", "at": NOW - td(minutes=3), "nonce": "e1", "approver_session_online": True}
    ev = {s: True for s in steps} | {"fido2_keys_enrolled": 2, "image_version": 7}
    assert enrol(cfg, ticket, appr, ev, NOW, set(), {"so1"}) == (True, [])
    bad = {**ev, "offline-test": False, "offline_sign_in_test": False, "fido2_keys_enrolled": 1, "pin_seen_by_officer": True}
    ok, why = enrol(cfg, ticket, {**appr, "nonce": "e2"}, bad, NOW, set(), {"so1"})
    assert not ok and "two FIDO2 keys (primary and backup) must be enrolled" in why
    assert "the officer must never see or set the user's PIN" in why and any("network disconnected" in w for w in why)
    self_approved = enrol(cfg, {**ticket, "user": "so1"}, {**appr, "user": "so1", "nonce": "e3"}, ev, NOW, set(), {"so1"})
    assert "four eyes: the approver cannot be the user" in self_approved[1]


def test_radar_records_platform_stack_prior_art():
    """ADR-0142: the platform-stack prior art is on the radar with its rings; nothing is adopted without its own ADR."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    radar = _y.safe_load((root / "catalog/radar.yaml").read_text(encoding="utf-8"))["radar"]
    for name in ("Zarf", "Lula", "Sylva", "Haven Compliancy Checker"):
        assert radar[name]["ring"] == "assess" and "ADR-0142" in radar[name]["why"], name
    for name in ("UDS Core", "Contrast"):
        assert radar[name]["ring"] == "hold", name
    assert "not open source" in radar["Contrast"]["why"]


def test_no_authenticator_ceremony_depends_on_forwarding_into_vdi():
    import yaml as _y
    ep = _y.safe_load((Path(__file__).resolve().parent.parent / "platform" / "endpoint-access.yaml").read_text(encoding="utf-8"))
    ac = ep["authenticator_ceremonies"]
    assert set(ac["mechanisms"]) >= {"session-sso", "out-of-band-step-up"}
    for name, proc in ac["processes"].items():
        assert proc["where"] in ("endpoint", "out-of-band", "forbidden-in-vdi"), name
        assert "guacamole" not in proc["how"].lower() or "before guacamole" in proc["how"].lower(), name
    for must in ("break-glass", "git-signing-and-merge-approval", "eid-document-signature"):
        assert ac["processes"][must]["where"] == "forbidden-in-vdi", must
    assert ac["processes"]["step-up-inside-vdi"]["where"] == "out-of-band"


def test_recovery_passphrase_needs_the_users_eid_and_an_officer_and_is_single_use():
    from datetime import timedelta as td
    from stick_recovery import release
    req = {"pseudonym": "p-7f3", "stick": "st-9", "nonce": "r1", "at": NOW - td(minutes=4)}
    eid = {"chain_ok": True, "revoked": False, "signed": {"pseudonym": "p-7f3", "stick": "st-9", "nonce": "r1"}, "nrn_hash": "h1"}
    cg = {"approvals": ["so1"], "required": 1, "created": NOW - td(minutes=3)}
    reg, officers, used = {"p-7f3": "h1"}, {"so1", "so2"}, set()
    assert release(req, eid, cg, reg, officers, used, NOW) == (True, [])
    assert "request already used" in release(req, eid, cg, reg, officers, used, NOW)[1]
    fresh = {**req, "nonce": "r2"}
    eid2 = {**eid, "signed": {**eid["signed"], "nonce": "r2"}}
    assert "security officer approval missing (OpenBao control group)" in release(fresh, eid2, {**cg, "approvals": []}, reg, officers, set(), NOW)[1]
    assert "eID holder is not the person behind this pseudonym" in release(fresh, {**eid2, "nrn_hash": "other"}, cg, reg, officers, set(), NOW)[1]
    assert "eID signature does not cover this request" in release(fresh, eid, cg, reg, officers, set(), NOW)[1]
    assert "request or approval expired" in release({**fresh, "at": NOW - td(hours=1)}, eid2, cg, reg, officers, set(), NOW)[1]
    two = release(fresh, eid2, {**cg, "required": 2}, reg, officers, set(), NOW)
    assert not two[0]   # without eID: two officers required, one is not enough


def test_endpoint_decisions_after_research_are_in_the_model():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    sz = _y.safe_load((root / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    ep = _y.safe_load((root / "platform" / "endpoint-access.yaml").read_text(encoding="utf-8"))
    seams = _y.safe_load((root / "platform" / "seams.yaml").read_text(encoding="utf-8"))["seams"]
    assert sz["modules"]["vdi"]["size"] == "optional"
    assert sz["modules"]["privileged-access"]["size"] == "M"
    assert "CIBA through the decision inbox" in ep["authenticator_ceremonies"]["mechanisms"]["out-of-band-step-up-channel"]
    assert any(x["from"] == "Keycloak" and x["to"] == "decision-inbox" for x in seams)
    assert "forceCpPassword" in ep["passwordless"]["cryptpad"]   # ADR-0060 replaced the SSO-secret model
    assert "no osquery manager" in ep["layers"]["posture"]["how"]


def test_gitops_itsm_and_browser_are_placed_per_tier():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    pl = _y.safe_load((root / "platform" / "placement.yaml").read_text(encoding="utf-8"))
    tiers = set(pl["tiers"])
    assert set(pl["gitops"]) == tiers and set(pl["itsm"]) == tiers
    assert set(pl["clients"]) == {"thin-client", "boot-stick", "fat-client"}
    assert "never the source of truth" in pl["tiers"]["edge-site"]
    assert "NATS JetStream queue" in pl["itsm"]["edge-site"]["what"]
    assert "only platform origins" in pl["browser"]["local"]["reaches"]
    assert "Firefox ESR" in pl["browser"]["local"]["what"] and pl["browser"]["pixels"]["when"]
    assert "Zammad tickets" not in (root / "platform" / "gitops.yaml").read_text(encoding="utf-8")


def test_egress_needs_two_approvers_two_pipelines_and_every_perimeter():
    import yaml as _y
    from egress import change_ok, check
    cfg = _y.safe_load((Path(__file__).resolve().parent.parent / "platform" / "egress.yaml").read_text(encoding="utf-8"))
    assert cfg["min_approvers"] >= 2 and cfg["min_pipelines"] >= 2 and len(cfg["perimeters"]) >= 3
    ok = {"requested_by": "u1", "expires": "2027-01-01", "approvals": [
        {"person": "ro1", "role": "risk_owner", "signature_valid": True}, {"person": "so1", "role": "security_officer", "signature_valid": True}]}
    assert change_ok(ok, cfg) == (True, [])
    self_app = {**ok, "requested_by": "ro1"}
    assert not change_ok(self_app, cfg)[0]   # the requester's own approval does not count
    assert not change_ok({**ok, "approvals": ok["approvals"][:1]}, cfg)[0]
    assert not change_ok({**ok, "expires": None}, cfg)[0]
    allow = {"docs.example.org", "vendor.example.com"}
    pipes = {"flux-network": True, "dns-zone": True, "host-firewall": True}
    full = {"l7": set(allow), "dns": set(allow), "l3": set(allow)}
    assert check(cfg, allow, full, pipes) == {"reachable": allow, "findings": []}
    # one perimeter missing a destination makes it unreachable; one extra destination is an incident
    partial = {**full, "dns": {"docs.example.org"}}
    assert check(cfg, allow, partial, pipes)["reachable"] == {"docs.example.org"}
    leak = {**full, "l3": allow | {"evil.example.net"}}
    assert any("incident" in f for f in check(cfg, allow, leak, pipes)["findings"])
    assert any("did not verify" in f for f in check(cfg, allow, full, {**pipes, "dns-zone": False})["findings"])


def test_adaptive_policy_bands_profiles_and_fails_loudly():
    from datetime import timedelta as td
    from adaptive import band, decide, load as aload, notice, workload_profile
    c = aload()
    f = lambda v: {"value": v, "at": NOW - td(minutes=1)}
    base = {"role": f("analyst"), "persona_status": f("normal"), "device_posture": f("ok"), "network": f("enterprise"),
            "location": f("allowed"), "time_of_day": f("inside"), "environment": f("green"), "world_state": f("normal"), "behaviour": f("none")}
    assert band(c, base, NOW)["band"] == "green"
    off = band(c, {**base, "network": f("unknown")}, NOW)
    assert off["band"] == "amber" and "NOT_ENTERPRISE_NETWORK" in off["reasons"]
    assert decide(c, "Sensitive write", off)["allow"] is False and decide(c, "Internal", off)["allow"] is True
    assert decide(c, "Sensitive read", off)["step_up"] is True
    # unknown is never green: a missing or stale signal raises the band
    stale = {**base, "device_posture": {"value": "ok", "at": NOW - td(hours=3)}}
    assert band(c, stale, NOW)["band"] != "green"
    # under review: red, everything closed except status and help, and the person is told (discreetly by default)
    rev = band(c, {**base, "persona_status": f("under-review")}, NOW)
    assert rev["band"] == "red" and not decide(c, "Internal", rev)["allow"] and decide(c, "status and help", rev)["allow"]
    n = notice(c, rev["reasons"], "REF-1", NOW)
    assert n["discreet"] and n["messages"][0]["code"] == "ACCESS_RESTRICTED" and n["logged_reasons"] == ["PERSONA_UNDER_REVIEW"]
    full = notice(c, rev["reasons"], "REF-1", NOW, "full")
    assert full["messages"][0]["text"] == "Your access is under review." and full["reference"] == "REF-1"
    # suspended is black: even status and help is closed online, the stick shows its cached state screen
    assert band(c, {**base, "persona_status": f("suspended")}, NOW)["band"] == "black"
    # world state and time of day combine
    assert band(c, {**base, "world_state": f("severe"), "time_of_day": f("outside")}, NOW)["band"] == "red"
    # every reason has a text and a remedy; every message carries reference and time
    assert all(r["text"] and r["todo"] for r in c["reasons"].values())
    # dynamic workload profile of a remote browser session
    assert workload_profile(c, "green", set(), "normal") == "open"
    assert workload_profile(c, "green", {"perimeter drift detected"}, "normal") == "isolated"
    assert workload_profile(c, "red", set(), "normal") == "isolated"
    assert workload_profile(c, "green", set(), "severe") == "isolated"


def test_every_component_is_placed_with_ddil_buffer_federation_and_reconcile():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    pl = _y.safe_load((root / "platform" / "placement.yaml").read_text(encoding="utf-8"))
    sz = _y.safe_load((root / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    runtime = {c["component"] for c in sz["core"]} | {c["component"] for m in sz["modules"].values() for c in m.get("components", [])}
    assert set(pl["components"]) == runtime
    for name, c in pl["components"].items():
        assert c["tiers"] and set(c["tiers"]) <= set(pl["tiers"]), name
        assert c["isolated"] in pl["ddil_models"] and c["buffer"] in pl["buffer_models"], name
        assert c["federation"] in pl["federation_models"] and c["reconcile"] in pl["reconcile_models"] and c["drp"] in pl["drp_roles"], name
        # something that stops during isolation at the edge must not be placed at the edge without a buffer
        if "edge-site" in c["tiers"] and c["isolated"] == "stops":
            assert c["buffer"] != "none", name
    # the edge keeps its essentials: identity, policy, secrets, network, time of truth
    for essential in ("Keycloak", "OPA", "OpenBao", "Cilium", "WireGuard", "Flux"):
        assert "edge-site" in pl["components"][essential]["tiers"] and pl["components"][essential]["isolated"] == "works", essential


def test_dynamic_trust_and_risk_from_sensors_decide_together():
    from datetime import timedelta as td
    from adaptive import band, decide_tr, load as aload, on_event, trust
    c = aload()
    fresh = NOW - td(minutes=1)
    strong = {"device_posture": {"sensor": "keylime", "at": fresh, "signed": True, "strong_identity": True},
              "network": {"sensor": "nac", "at": fresh, "signed": True, "strong_identity": True}}
    weak = {"device_posture": {"sensor": "osquery", "at": fresh, "signed": True, "strong_identity": True},
            "network": {"sensor": "netbird", "at": fresh, "signed": True, "strong_identity": True}}
    assert trust(c, strong, NOW)["trust"] == "high"
    assert trust(c, weak, NOW)["trust"] == "medium"           # self-reported evidence never reaches high
    stale = {k: {**v, "at": NOW - td(hours=5)} for k, v in strong.items()}
    assert trust(c, stale, NOW)["trust"] == "low"              # stale caps trust whatever the source
    green = {"band": "green", "score": 0, "reasons": []}
    assert decide_tr(c, "Sensitive write", trust(c, strong, NOW), green)["allow"] is True
    assert decide_tr(c, "Sensitive write", trust(c, weak, NOW), green)["allow"] is False   # good situation, weak evidence
    red = {"band": "red", "score": 9, "reasons": ["DEVICE_POSTURE_FAILED"]}
    assert decide_tr(c, "Internal", trust(c, strong, NOW), red)["allow"] is False          # strong evidence of a bad situation
    assert on_event(c, "session_revoked") == ["revoke-session", "notify"]
    assert on_event(c, "something new") == ["raise-anomaly", "notify-security-officer"]


def test_office_suite_is_optional_and_internal_only():
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    sz = _y.safe_load((root / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    mod = sz["modules"]["office-suite"]
    assert mod["size"] == "optional" and mod["labels"] == ["Internal"]
    assert {c["component"] for c in mod["components"]} == {"Nextcloud", "Collabora Online"}
    assert any(c["component"] == "CryptPad" for c in sz["core"])   # the end-to-end encrypted default stays in core


def test_capability_contracts_bind_seams_and_compute_lock_in():
    import copy as _c
    from contracts import check, combined, load as cload, lock_in, needs_compensation, priorities, readiness, seam_contracts
    d = cload()
    assert check(d) == []
    k = d["contracts"]["contracts"]
    # readiness is computed from features; ready needs lab evidence
    assert readiness({"a": "yes", "b": "yes"}, ["a", "b"]) == "candidate"
    assert readiness({"a": "yes", "b": "yes"}, ["a", "b"], "lab") == "ready"
    assert readiness({"a": "yes", "b": "no"}, ["a", "b"]) == "partial"
    # over-claiming is refused
    bad = _c.deepcopy(d)
    bad["contracts"]["contracts"]["identity-broker"]["implementations"]["Keycloak"]["readiness"] = "ready"
    assert any("claims ready" in e for e in check(bad))
    # primaries fulfil together, alternates by set
    assert combined(k["metrics-and-logs"], "primary")["primary"] == "candidate"
    assert combined(k["metrics-and-logs"], "alternate")["prometheus-loki"] == "candidate"
    assert lock_in(k["device-enrolment"]) == "high"            # own code without an alternate
    # interfaces may not claim less lock-in than the contract shows
    opt = _c.deepcopy(d)
    opt["interfaces"]["identity-broker"]["lock_in"] = "none"
    assert any("identity-broker: interfaces claim lock-in none" in e for e in check(opt))
    # every seam binds to a contract, a backlog capability or an external party
    sc = seam_contracts(d)
    assert len(sc["bound"]) + len(sc["backlog"]) + len(sc["external"]) == len(d["seams"]) and len(sc["bound"]) >= 60
    # exposed components with a heavy advisory record carry compensations, each with pinning and the patch SLA
    need = needs_compensation(d)
    assert "Keycloak" in need and set(need) <= set(d["compensations"])
    for c in need:
        text = " ".join(d["compensations"][c])
        assert "pinned" in text or "same pinning" in text, c
    assert priorities(d)[0]["priority"] >= priorities(d)[-1]["priority"]


def test_gateway_contract_covers_labels_and_keeps_dlp_at_the_boundaries():
    import yaml as _y
    from contracts import check, load as cload, lock_in
    root = Path(__file__).resolve().parent.parent
    d = cload()
    assert check(d) == []
    k = d["contracts"]["contracts"]["ingress-and-api"]
    for f in ("label-cells", "authz-obligation-headers", "authz-request-body-limited", "decision-logs-with-label", "per-label-tls-profile"):
        assert f in k["required"], f
    assert k["implementations"]["kgateway"]["role"] == "alternate" and lock_in(k) == "low"
    assert "heavy DLP" in k["not_in_contract"]
    gw = _y.safe_load((root / "platform" / "gateway.yaml").read_text(encoding="utf-8"))
    assert any("heavy DLP" in x for x in gw["labels_and_dcs"]["does_not"])
    assert any("decrypt" in x for x in gw["labels_and_dcs"]["does_not"])
    assert "payload transformation" in gw["gateway_must_not"]


def test_sources_of_truth_have_one_master_and_work_alone():
    import copy as _c
    from sources_of_truth import check, load as sload
    d = sload()
    assert check(d) == []
    f = d["facts"]
    assert f["people"]["reconcile"] == "replicated" and "SCIM" in f["people"]["flows_to"]
    assert f["physical-assets"]["master"] == "site DCIM/IPAM" and f["physical-assets"]["scope"] == "site"
    assert f["observed-state"]["master"] == "none"
    assert {k for k, v in f.items() if "git" in str(v["master"]).lower()} >= {"intent-and-policy", "architecture", "address-plan", "estate-register"}
    bad = _c.deepcopy(d)
    bad["facts"]["devices"]["wan_down"] = "ask the central enrolment service"
    assert any("depends on the centre" in e for e in check(bad))
    bad = _c.deepcopy(d)
    bad["facts"]["physical-assets"]["master"] = "GLPI"
    assert any("view, never a master" in e for e in check(bad))
    bad = _c.deepcopy(d)
    bad["facts"]["people"]["scope"] = "site"
    assert any("replicated fact is mastered above the site" in e for e in check(bad))


def test_every_capability_has_detection_and_a_response_ladder_with_act_or_inform():
    """ADR-0085: drift method, detector and interval; trust and risk impact; coordinates in time and cyberspace; a
    ladder from watch-detail to quarantine whose autonomy comes from governance/autonomy.yaml, never autonomous for
    increase actions or for quarantining Tier 0; clean-source dependencies are Tier 0."""
    import copy as _c
    from detection_response import card, check, load as dload
    d = dload()
    assert check(d) == []
    idb = card(d, "identity-broker")
    assert idb["tier"] == "tier0" and idb["drift"]["method"] == "adapter-verify" and idb["drift"]["interval_min"] <= 15
    modes = {r["rung"]: r["mode"] for r in idb["ladder"]}
    assert modes["watch-detail"] == "act" and modes["quarantine"] == "ask" and modes["revocation"] == "ask"
    assert card(d, "host-os")["tier"] == "tier0"                    # clean source: Tier 0 runs on it
    assert set(card(d, "remote-browser")["coordinates"]) == {"layer", "site", "infra", "logical"}
    bad = _c.deepcopy(d)
    bad["dr"]["drift_methods"]["adapter-verify"]["interval_min"]["tier0"] = 240
    assert any("checked at least hourly" in e for e in check(bad))
    bad = _c.deepcopy(d)
    bad["autonomy"]["context_caps"]["tier0-target"]["reduce"] = "autonomous"
    assert check(bad) == []                                         # a context can only lower autonomy, never raise it
    bad["autonomy"]["max_autonomy"]["medium-appetite"]["quarantine-host"] = "autonomous"
    assert any("never autonomous" in e for e in check(bad))


def test_opa_and_the_python_engine_decide_identically_and_bands_only_tighten(tmp_path):
    """ADR-0092: the OPA bundle compiled from the packs and tools/policy_engine.py give the same rule, effect,
    parameter, mode, conflicts and blocked list for every generated context (differential test); band floors only
    tighten; the Rego unit tests pass."""
    import itertools as _it
    import json as _json
    import shutil as _sh
    import subprocess as _sp
    from datetime import date as _d
    from policy_compile import build
    from policy_engine import band_floor, effective, load as pload, MODES
    opa = _sh.which("opa")
    assert opa, "opa must be installed (CI installs a pinned, checksummed binary)"
    assert _sp.run([opa, "test", str(Path(__file__).resolve().parent.parent / "policy")], capture_output=True).returncode == 0
    model, rules = pload()
    floors = band_floor(model)
    bands = ["green", "amber", "red", "black"]
    assert [MODES.index(floors[b]) for b in bands] == sorted(MODES.index(floors[b]) for b in bands)   # only tighten
    dims: dict = {}
    for r in rules:
        for k, vals in (r.get("scope") or {}).items():
            dims.setdefault(k, set()).update(vals)
    choices = [[None] + sorted(map(str, v)) for k, v in sorted(dims.items())]
    names = sorted(dims)
    contexts = []
    for combo in _it.product(*choices):
        for trust, band, day in _it.product(["none", "low", "medium", "high"], bands, ["2025-06-01", "2026-10-10"]):
            c = {"trust": trust, "band": band, "day": day, **{n: v for n, v in zip(names, combo) if v is not None}}
            contexts.append(c)
    bundle = build(tmp_path / "bundle")
    q = "[x | some c in input.contexts; x := data.vdh.decide.result with input as {\"context\": c}]"
    r = _sp.run([opa, "eval", "-b", str(bundle), "-I", "-f", "json", q], input=_json.dumps({"contexts": contexts}),
                capture_output=True, text=True, check=True)
    opa_results = _json.loads(r.stdout)["result"][0]["expressions"][0]["value"]
    assert len(opa_results) == len(contexts) > 100
    for c, o in zip(contexts, opa_results):
        py = effective(rules, c, _d.fromisoformat(c["day"]), floors)
        for topic, v in py.items():
            ov = o.get(topic)
            assert ov is not None, (c, topic)
            for k in ("rule", "effect", "parameter", "mode", "conflicts", "blocked"):
                assert str(v[k]) == str(ov[k]) or (v[k] in (None, []) and ov[k] in (None, [])), (c, topic, k, v[k], ov[k])


def test_fetch_opa_installs_only_the_pinned_digest(tmp_path, monkeypatch):
    """ADR-0092: the CI OPA binary is a fixed release; a download whose sha256 differs from the pin is refused and
    nothing is written."""
    import io
    import re as _re
    import fetch_opa
    assert _re.fullmatch(r"v\d+\.\d+\.\d+", fetch_opa.VERSION) and _re.fullmatch(r"[0-9a-f]{64}", fetch_opa.SHA256)
    assert fetch_opa.VERSION in fetch_opa.URL and fetch_opa.URL.startswith("https://github.com/open-policy-agent/")
    monkeypatch.setattr(fetch_opa.urllib.request, "urlopen", lambda *a, **k: io.BytesIO(b"not opa"))
    dest = tmp_path / "opa"
    with pytest.raises(SystemExit):
        fetch_opa.fetch(str(dest))
    assert not dest.exists()


def test_data_is_leased_by_its_owner_revocably_without_breaking_custody():
    """ADR-0095: every product's ownership is a lease with a separate steward; every backbone consumer holds a current
    lease from the owner or (renewal only) the steward, for an allowed purpose, within its kind's limit for the label;
    derived leases end with their inputs; aggregates name a group size; suspend is bounded; stale leases must be marked
    ended; offline grace, key custody and plaintext residency are declared; shred is two-person and blocked by legal
    hold; custody sees ciphertext. Recently lapsed leases are reported, not failed."""
    import copy
    from datetime import date as _date
    from data_leases import check, load
    d = load()
    errs, lapsed = check(d, _date(2026, 10, 10))
    assert errs == [] and lapsed == [], (errs, lapsed)
    errs, later = check(d, _date(2027, 4, 15))
    assert not [e for e in errs if "DL-0001" in e] and any("DL-0001" in x for x in later)
    assert any("ownership lapsed" in x for x in later)
    assert any("DL-0001: ended" in e for e in check(d, _date(2027, 6, 1))[0])   # stale beyond 30 days
    bad = copy.deepcopy(d)
    L = bad["dp"]["leases"]
    L[0]["purpose"] = "marketing"
    L[1]["granted_by"] = "some-admin"
    L[2]["until"] = "2028-12-31"
    L[2]["min_group_size"] = 3
    bad["dp"]["products"]["hr-roster"].pop("owner_until")
    bad["dp"]["mesh"]["domains"]["operations"]["owner"] = "site-ops-owner"
    bad["dl"]["ending"]["shred"]["two_person"] = False
    bad["dl"]["ending"]["revoke"]["purge_attestation_s"] = 0
    bad["dl"]["lease_kinds"]["export"]["max_days"]["Restricted"] = 400
    bad["dl"]["key_custody"]["kas_replicas_min"] = 1
    bad["dl"]["plaintext_residency"]["never_in"] = ["screenshots-and-exports"]
    bad["dl"]["offline"]["key_grace"]["Internal"] = "0s"
    bad["cls"]["layers"]["backup-storage"]["sees"] = "plaintext"
    errs, _ = check(bad, _date(2026, 10, 10))
    for frag in ("purpose marketing", "granted by some-admin", "DL-0003: 822 days", "min_group_size", "owner_until",
                 "steward is the owner", "shred needs two persons", "purge attestation", "shrink from Internal",
                 "key custody", "plaintext residency", "no offline key grace", "custody"):
        assert any(frag in e for e in errs), (frag, errs)
    grants = copy.deepcopy(d)
    G = grants["dp"]["leases"]
    G[0]["granted_by"] = "people-domain-lead"                       # steward, but a new grant
    G[1]["from"] = "2027-05-01"                                     # owner grants after the ownership lease ended
    G[1]["until"] = "2027-09-30"
    G.append(dict(G[2], id="DL-0004", derived_from=["DL-0003"], until="2027-06-30"))
    G.append(dict(G[2], id="DL-0005", status="suspended", suspended_on="2026-08-01"))
    errs, _ = check(grants, _date(2026, 10, 10))
    for frag in ("steward may only renew", "after the ownership lease ended", "DL-0004: ends after", "DL-0005: suspended"):
        assert any(frag in e for e in errs), (frag, errs)
    orphan = copy.deepcopy(d)
    orphan["dp"]["leases"] = [l for l in orphan["dp"]["leases"] if l["consumer"] != "scheduling-app"]
    assert any("scheduling-app" in e for e in check(orphan, _date(2026, 10, 10))[0])


def test_data_carries_verified_identities_that_stack_and_only_tighten():
    """ADR-0096: a derived envelope stacks its inputs' identities and steps, takes the highest label (uplifted once
    per lineage by aggregation across purposes), the narrowest ring, the intersection of purposes and the earliest
    end; small aggregates and undeclared reads are refused; verify recomputes everything from the registry and the
    inputs and checks the digest and the Ed25519 step signatures; beyond the tenant the chain is pseudonymised;
    records prove membership of their batch by Merkle inclusion."""
    import copy
    import json as _json
    import pytest as _pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from data_provenance import derive, digest, included, load, merkle_root, prove, source_envelope, verify, view
    d = load()
    hr, te, cf = (source_envelope(d, p) for p in ("hr-roster", "sensor-telemetry", "case-files-index"))
    j = derive(d, [hr, te], "analytics-job-2025", "join", aggregate=True, group_size=50)
    assert (j["label"], j["releasable_to"], j["purposes"]) == ("Restricted", "tenant", [])
    assert j["valid_until"] == te["valid_until"] and j["uplifted_by"] == "analytics-job-2025"
    assert j["originators"] == ["hr-system", "site-sensors"] and j["chain"][-1]["inputs"] == [hr["digest"], te["digest"]]
    j2 = derive(d, [j, cf], "case-linker", "link")
    from data_provenance import Store
    from provenance_log import Log
    log = Log()
    store = Store(log)
    for e in (hr, te, cf, j, j2):
        store.put(e, log.append(e["digest"]))
    assert j2["releasable_to"] == "site" and len(j2["chain"]) == 1
    assert len(store.history(j2["digest"])) == 6        # hr 1 + te 1 + cf 2 originators + join + link: stacked once
    assert derive(d, [j, te], "x", "agg", aggregate=True, group_size=20)["uplifted_by"] == "analytics-job-2025"
    with _pytest.raises(ValueError, match="minimum group size"):
        derive(d, [hr], "x", "count", aggregate=True, group_size=3)
    with _pytest.raises(ValueError, match="undeclared input"):
        derive(d, [te], "y", "filter", read_set=[te["digest"], hr["digest"]])
    known = {e["digest"]: e for e in (hr, te, cf, j)}
    assert verify(d, j, known) == []
    t = copy.deepcopy(j)
    t["label"] = "Internal"
    assert verify(d, t, known) == ["digest does not match the envelope (altered after signing)"]
    t["digest"] = digest(t)
    assert "label differs from what the inputs give" in verify(d, t, known)
    hr_t = dict(hr, releasable_to="public")
    hr_t["digest"] = digest(hr_t)
    laundered = derive(d, [hr_t, te], "launderer", "join")
    assert any("releasable_to differs" in e for e in verify(d, laundered, dict(known, **{hr_t["digest"]: hr_t})))
    keys = {k: Ed25519PrivateKey.generate() for k in ("hr-system", "site-sensors", "analytics-job-2025")}
    pub = {k: v.public_key() for k, v in keys.items()}
    hs, ts = (source_envelope(d, p, keys=keys) for p in ("hr-roster", "sensor-telemetry"))
    js = derive(d, [hs, ts], "analytics-job-2025", "join", aggregate=True, group_size=50, key=keys["analytics-job-2025"])
    ks = {e["digest"]: e for e in (hs, ts)}
    assert verify(d, js, ks, pub) == []
    assert any("unsigned or unknown key" in e for e in verify(d, js, ks, {k: v for k, v in pub.items() if k != "site-sensors"}))
    assert any("bad signature" in e for e in verify(d, js, ks, dict(pub, **{"analytics-job-2025": Ed25519PrivateKey.generate().public_key()})))
    v = view(d, j, "federation")
    shown = _json.dumps(v)
    assert v["redacted"] and not any(p in shown for p in d["dp"]["principals"]) and "workload:" in shown
    assert view(d, j, "tenant") is j
    members = [{"sensor": "site-sensors", "seq": i} for i in range(7)]
    root = merkle_root(members)
    assert all(included(m, i, len(members), prove(members, i), root) for i, m in enumerate(members))
    assert not included({"sensor": "site-sensors", "seq": 99}, 3, len(members), prove(members, 3), root)


def test_requests_reach_living_owners_by_kind_band_and_without_self_approval():
    """ADR-0096 requests: access stays inside the ring and label; each source blocks only on its own rules; a
    declassification needs every source owner, the uplift's author and the security officer; the worst band of
    requester, delegator, site and data caps the ring; nobody approves their own request (agents included); a lapsed
    owner yields to the steward; with no living authority the request is refused, not lost."""
    import copy
    from data_provenance import derive, load, route, source_envelope
    d = load()
    G = {"band": "green", "site_band": "green"}   # ADR-0126: the request states its bands; a missing one decides as black
    hr, te = (source_envelope(d, p) for p in ("hr-roster", "sensor-telemetry"))
    j = derive(d, [hr, te], "analytics-job-2025", "join", aggregate=True, group_size=50)
    A = lambda env, **r: route(d, env, {"kind": "access", "target_ring": "site", "purpose": "operations"} | G | r)
    assert A(te, target_ring="tenant")["decision"] == "allowed-by-policy"
    assert route(d, te, {"kind": "release", "target_ring": "federation", "purpose": "analytics"} | G)["approvers"] == ["release_officer"]
    r = route(d, j, {"kind": "release", "target_ring": "tenant", "purpose": "analytics"} | G)
    assert r["declassification"] and r["no_common_purpose"]
    assert r["approvers"] == ["hr-service-owner", "site-ops-owner", "data-governance-board", "release_officer",
                              "people-domain-lead", "security_officer"]
    assert A(hr, target_ring="federation")["decision"] == "refused"
    assert A(hr, new_label="Internal")["decision"] == "refused"
    low = route(d, hr, {"kind": "release", "target_ring": "tenant", "purpose": "scheduling", "new_label": "Internal"} | G)
    assert low["approvers"] == ["hr-service-owner", "release_officer", "security_officer"]
    assert A(te, purpose="marketing", requester="site-ops-owner")["approvers"] == ["operations-domain-lead"]
    assert A(hr, purpose="analytics", requester="scheduler-agent")["approvers"] == ["people-domain-lead"]
    assert route(d, te, G | {"kind": "release", "target_ring": "tenant", "purpose": "operations", "site_band": "red"})["decision"] == "refused"
    assert A(te, on_behalf_band="amber")["approvers"] == ["security_officer"]
    lapsed = copy.deepcopy(d)
    lapsed["dp"]["products"]["hr-roster"]["owner_until"] = "2026-01-01"
    assert route(lapsed, hr, {"kind": "access", "target_ring": "site", "purpose": "analytics"} | G)["approvers"] == ["people-domain-lead"]
    nobody = copy.deepcopy(d)
    for k in ("hr-service-owner", "people-domain-lead", "data-governance-board"):
        nobody["dp"]["principals"][k]["status"] = "vacant"
    assert route(nobody, hr, {"kind": "access", "target_ring": "site", "purpose": "analytics"} | G)["decision"] == "refused"


def test_platform_and_policy_data_are_products_and_changes_reach_everything_built_on_them():
    """ADR-0096 change and scope: every data class (business, infrastructure, governance, observability, security,
    logging, policy) has a registered product; an update or supersession makes dependents stale, a correction or
    retraction taints them, transitively and worst-wins; artefacts citing them follow unless their relevance lapsed;
    a corrected policy bundle taints every decision made under it; snapshots are never rewritten; the model's
    rings, principals, consumers and identifiers are consistent and an acts_for cycle is caught."""
    import copy
    from data_provenance import check, derive, impact, load, source_envelope
    d = load()
    assert check(d) == [], check(d)
    hr, te, cf = (source_envelope(d, p) for p in ("hr-roster", "sensor-telemetry", "case-files-index"))
    a = derive(d, [te], "telemetry-rollup", "aggregate per hour", aggregate=True)
    b = derive(d, [a, hr], "staffing-model", "join")
    c = derive(d, [cf], "case-index-stats", "count")
    envs = [hr, te, cf, a, b, c]
    notes = [{"id": "note-staffing", "refs": [b["digest"]], "relevant_until": "2026-12-31"},
             {"id": "note-old", "refs": [a["digest"]], "relevant_until": "2026-01-31"},
             {"id": "note-cases", "refs": [c["digest"]], "relevant_until": "2026-12-31"}]
    up = impact(d, envs, notes, te["digest"], "update", "2026-10-10")
    assert up[a["digest"]] == up[b["digest"]] == "stale" and c["digest"] not in up
    assert up["note-staffing"] == "stale" and up["note-old"] == "historical" and "note-cases" not in up
    snap = copy.deepcopy(b)
    bad = impact(d, envs, notes, te["digest"], "correction", "2026-10-10")
    assert bad[b["digest"]] == bad["note-staffing"] == "tainted" and snap == b
    pb = source_envelope(d, "policy-bundles")
    dec = derive(d, [pb], "policy-decision-points", "decide")
    review = [{"id": "access-review-q4", "refs": [dec["digest"]], "relevant_until": "2027-01-31"}]
    assert impact(d, [pb, dec], review, pb["digest"], "correction", "2026-10-10") == {dec["digest"]: "tainted", "access-review-q4": "tainted"}
    assert impact(d, [pb, dec], review, pb["digest"], "supersession", "2026-10-10")[dec["digest"]] == "stale"
    classes = {p["data_class"] for p in d["dp"]["products"].values() if "data_class" in p} | {"business"}
    assert classes == set(d["pv"]["applies_to"]["data_classes"])
    bad = copy.deepcopy(d)
    bad["dp"]["products"] = {k: v for k, v in bad["dp"]["products"].items() if v.get("data_class") != "policy"}
    bad["dp"]["products"]["case-files-index"]["releasable_to"] = "federation"
    bad["dp"]["consumers"]["scheduling-app"]["ring"] = "federation"
    bad["dp"]["principals"]["site-sensors"].pop("acts_for")
    bad["dp"]["principals"]["loop-a"] = {"kind": "workload", "acts_for": "loop-b", "status": "active"}
    bad["dp"]["principals"]["loop-b"] = {"kind": "workload", "acts_for": "loop-a", "status": "active"}
    bad["pv"]["rings"]["band_cap"]["black"] = "public"
    errs = check(bad)
    for frag in ("data class policy", "wider than Restricted allows", "DL-0001: consumer ring federation",
                 "site-sensors: a sensor must name", "acts_for cycle", "band_cap"):
        assert any(frag in e for e in errs), (frag, errs)


def test_provenance_scales_by_reference_and_the_store_is_anchored_to_the_log():
    """ADR-0097 scale: one byte through 1000 workloads keeps every envelope constant in size, verifies at any depth
    without recursion, and a signed checkpoint from a registered verifier bounds the walk; a forged or revoked
    checkpoint does not; the store only accepts logged envelopes with their inputs present and returns history once
    per node, dependents first, over a diamond; a folded pipeline run verifies only against its run log and is
    rejected when it hid a policy-relevant change."""
    import json as _json
    import pytest as _pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from data_provenance import Store, _canon, derive, digest, load, source_envelope, verify
    from provenance_log import Log, checkpoint, mth
    d = load()
    te = source_envelope(d, "sensor-telemetry")
    log = Log()
    store, known, env = Store(log), {te["digest"]: te}, te
    store.put(te, log.append(te["digest"]))
    sizes = []
    for n in range(1000):
        env = derive(d, [env], f"workload-{n % 7}", "transform")
        store.put(env, log.append(env["digest"]))
        known[env["digest"]] = env
        sizes.append(len(_json.dumps(env)))
    assert max(sizes) - min(sizes) < 16 and max(sizes) < 1500
    assert len(store.history(env["digest"])) == 1001 and verify(d, env, known) == []
    cut = list(known)[990]
    assert len(store.history(env["digest"], stop={cut})) == 11
    vk = Ed25519PrivateKey.generate()
    cp = checkpoint(vk, "site-verifier", cut, len(log.leaves))
    signers = {"site-verifier": vk.public_key()}
    partial = {k: v for i, (k, v) in enumerate(known.items()) if i >= 990}
    assert verify(d, env, partial, checkpoints=[cp], checkpoint_signers=signers) == []
    assert verify(d, env, partial) != []                                               # no checkpoint: walk needed
    forged = dict(cp, verifier="site-verifier", sig=Ed25519PrivateKey.generate().sign(b"x").hex())
    assert verify(d, env, partial, checkpoints=[forged], checkpoint_signers=signers) != []
    assert verify(d, env, partial, checkpoints=[cp], checkpoint_signers=signers, revoked={cut}) != []
    with _pytest.raises(ValueError, match="not at log index"):
        Store(Log()).put(te, 0)
    other = Log()
    with _pytest.raises(ValueError, match="inputs not in the store"):
        Store(other).put(env, other.append(env["digest"]))
    hr = source_envelope(d, "hr-roster")
    left, right = derive(d, [te], "l", "split"), derive(d, [te], "r", "split")
    top = derive(d, [left, right, hr], "m", "merge")
    dl_ = Log()
    ds = Store(dl_)
    for e in (te, hr, left, right, top):
        ds.put(e, dl_.append(e["digest"]))
        ds.put(e, len(dl_.leaves) - 1)                                                 # idempotent, no duplicates
    acts = [s["actor"] for s in ds.history(top["digest"])]
    assert acts[0] == "m" and sorted(acts) == sorted(["m", "l", "r", "site-sensors", "hr-system"]) and len(ds.children[te["digest"]]) == 2
    steps = [{"step": i, "changes": []} for i in range(5)]
    root = mth([_canon(x) for x in steps]).hex()
    run = derive(d, [te], "orchestrator", "pipeline run", run={"internal_steps": 5, "log_root": root})
    k1 = {te["digest"]: te}
    assert verify(d, run, k1, runs={root: steps}) == []
    assert "missing" in verify(d, run, k1)[0]
    hidden = [dict(x, changes=["label"]) if x["step"] == 2 else x for x in steps]
    sneaky = derive(d, [te], "orchestrator", "pipeline run",
                    run={"internal_steps": 5, "log_root": mth([_canon(x) for x in hidden]).hex()})
    assert "must be their own steps" in verify(d, sneaky, k1, runs={sneaky["chain"][-1]["params"]["run"]["log_root"]: hidden})[0]


def test_the_transparency_log_proves_inclusion_and_that_nothing_was_rewritten():
    """ADR-0097 log: RFC 9162 inclusion and consistency proofs hold for every tree size; a rewritten entry breaks
    consistency with an earlier signed tree head; a tree head signed by the wrong key is rejected."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from provenance_log import (Log, consistency_proof, inclusion_proof, mth, verify_consistency, verify_inclusion,
                                verify_sth)
    leaves = [f"sha256:{i:064x}".encode() for i in range(33)]
    for n in range(1, 34):
        L, r = leaves[:n], mth(leaves[:n])
        assert all(verify_inclusion(i, n, L[i], inclusion_proof(i, L), r) for i in range(n))
        assert all(verify_consistency(m, n, mth(L[:m]), r, consistency_proof(m, L)) for m in range(1, n + 1))
    log, key = Log("site-a"), Ed25519PrivateKey.generate()
    for x in leaves[:8]:
        log.append(x.decode())
    head = log.sth(key, "2026-10-10T06:00:00Z")
    assert verify_sth(head, key.public_key()) and not verify_sth(head, Ed25519PrivateKey.generate().public_key())
    for x in leaves[8:20]:
        log.append(x.decode())
    assert verify_consistency(8, 20, bytes.fromhex(head["root"]), log.root(), log.consistency(8))
    log.leaves[3] = b"rewritten"
    assert not verify_consistency(8, 20, bytes.fromhex(head["root"]), log.root(), log.consistency(8))


def test_oversight_sees_shape_and_verdicts_never_content_or_fingerprints():
    """ADR-0097 oversight: the view is an allowlist with suppressed small counts, month dates and per-case
    pseudonyms; DLP validates what it finds and reports counts, a label finding and hits per owner-registered list,
    never text or fingerprints; small lists are refused, list queries have a budget, totals below the floor are
    suppressed; the investigation lease is two distinct persons, capped and reported."""
    import json as _json
    import pytest as _pytest
    from data_provenance import check, derive, load, source_envelope
    from oversight import aggregate, dlp_scan, find, oversight_view, register_list
    d = load()
    hr, cf = source_envelope(d, "hr-roster"), source_envelope(d, "case-files-index")
    v = oversight_view(d, derive(d, [hr, cf], "case-linker", "link"), b"case-17")
    shown = _json.dumps(v)
    assert set(v) == {"label", "releasable_to", "purposes", "sources", "ref", "valid_until_month", "originator_kinds",
                      "originator_count", "steps", "uplifted"}
    assert v["originator_count"] == "<10" and len(v["valid_until_month"]) == 7 and hr["digest"] not in shown
    assert not any(f'"{p}"' in shown for p in d["dp"]["principals"])
    assert oversight_view(d, hr, b"case-18")["ref"] != oversight_view(d, hr, b"case-17")["ref"]
    corpus = {"Jan.Peeters@example.org": "email", "BE71 0961 2345 6769": "iban", "be71096123456769": "iban",
              "+32 470 12 34 56": "phone", "0470 12 34 56": "phone", "02/123.45.67": "phone",
              "BE71 0961 2345 6769 approved": "iban", "GB82 WEST 1234 5698 7654 32 sent": "iban"}
    for text, kind in corpus.items():
        assert [k for k, _ in find(f"x {text} y")] == [kind], text
    for clean in ("BE00 0000 0000 0000", "ref 12345678901234", "order 2026-10-10", "v1.30.1"):
        assert find(clean) == [], clean
    key = b"tenant-dlp-key-stays-in-the-ring"
    vip = [("email", f"person{i}@example.org") for i in range(60)]
    lst = register_list("vip", "people-domain-lead", vip, key, salt="s1", budget=2)
    with _pytest.raises(ValueError, match="membership probe"):
        register_list("one", "x", vip[:1], key, salt="s2")
    text = "Shift for person7@example.org and jan@example.org, refund BE71 0961 2345 6769, call 0470 12 34 56."
    out = dlp_scan(text, "Internal", key, [lst])
    assert out["counts"] == {"iban": 1, "email": 2, "phone": 1} and out["finding"] == "under-labelled"
    assert out["list_hits"] == {"vip": 1} and "fingerprints" not in out
    dumped = _json.dumps(out)
    assert "person7" not in dumped and "0961" not in dumped and "0470" not in dumped
    dlp_scan(text, "Sensitive", key, [lst])
    assert dlp_scan(text, "Sensitive", key, [lst])["list_hits"] == {"vip": "budget-exhausted"}
    assert aggregate([out] * 3) == {"iban": "<10", "email": "<10", "phone": "<10"}
    assert aggregate([out] * 12)["email"] == 24
    bad = load()
    bad["dl"]["lease_kinds"]["investigation"]["max_renewals"] = 5
    bad["pv"]["oversight"]["roles"]["dpo"]["sees"].append("content")
    errs = check(bad)
    assert any("investigation lease" in e for e in errs) and any("dpo: must never see content" in e for e in errs)


def test_provenance_survives_ddil_and_dead_ephemeral_identities():
    """ADR-0097 ddil: a step signed by an identity whose key has since expired (a spun-down ephemeral PoP) verifies
    when signed inside its validity window, and fails when signed after expiry or after revocation; a site's log
    grown while cut off is consistent with the head the parent saw before the partition, and a rewrite is caught;
    data whose inputs died undrained is unverifiable and treated fail-closed; the model declares the ddil rules."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from data_provenance import check, derive, fail_closed, load, source_envelope, verify
    from provenance_log import Log, verify_consistency
    d = load()
    keys = {k: Ed25519PrivateKey.generate() for k in ("site-sensors", "pop-17-transcoder")}
    te = source_envelope(d, "sensor-telemetry", keys={"site-sensors": keys["site-sensors"]})
    made = derive(d, [te], "pop-17-transcoder", "transcode", at="2026-10-10T05:00:00Z", key=keys["pop-17-transcoder"])
    late = derive(d, [te], "pop-17-transcoder", "transcode", at="2026-10-10T09:00:00Z", key=keys["pop-17-transcoder"])
    register = {"site-sensors": keys["site-sensors"].public_key(),
                "pop-17-transcoder": {"key": keys["pop-17-transcoder"].public_key(), "not_before": "2026-10-10T04:50:00Z",
                                      "not_after": "2026-10-10T05:10:00Z"}}
    known = {te["digest"]: te}
    assert verify(d, made, known, keys=register) == []                    # the PoP is gone; its work still verifies
    assert any("not valid at" in e for e in verify(d, late, known, keys=register))
    revoked = dict(register, **{"pop-17-transcoder": dict(register["pop-17-transcoder"], revoked_at="2026-10-10T04:55:00Z")})
    assert any("not valid at" in e for e in verify(d, made, known, keys=revoked))
    site, parent_key = Log("site-b"), Ed25519PrivateKey.generate()
    for i in range(5):
        site.append(f"sha256:{i:064x}")
    seen_by_parent = site.sth(parent_key, "2026-10-10T05:00:00Z")
    for i in range(5, 12):
        site.append(f"sha256:{i:064x}")                                   # logged while cut off
    assert verify_consistency(5, 12, bytes.fromhex(seen_by_parent["root"]), site.root(), site.consistency(5))
    site.leaves[1] = b"rewritten-while-cut-off"
    assert not verify_consistency(5, 12, bytes.fromhex(seen_by_parent["root"]), site.root(), site.consistency(5))
    orphan = derive(d, [made], "downstream", "use")
    errs = verify(d, orphan, {te["digest"]: te})                          # the PoP died before draining `made`
    assert errs and "unverifiable" in errs[0]
    fc = fail_closed(d, orphan)
    assert (fc["label"], fc["releasable_to"], fc["state"]) == ("Restricted", "site", "unverifiable")
    bad = load()
    del bad["pv"]["ddil"]["drain_before_spin_down"]
    assert any("drain_before_spin_down" in e for e in check(bad))


def test_proof_bundles_verify_offline_across_isolated_pops_and_nesting():
    """ADR-0098: data from PoP B reaches an isolated PoP A with a proof bundle (the envelope, its ancestors back to a
    checkpoint signed by a verifier A trusts, log inclusion proofs and a signed tree head); A verifies it offline with
    only the replicated key register; tampering, an untrusted checkpoint signer or an unregistered log key fail; a
    site verifies and vouches, so the bundle it forwards up the nesting is one envelope long; a bad bundle is never
    vouched for."""
    import copy
    import pytest as _pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from data_provenance import Store, derive, load, source_envelope
    from provenance_bundle import make_bundle, rebundle, verify_bundle
    from provenance_log import Log, checkpoint
    d = load()
    k = {n: Ed25519PrivateKey.generate() for n in ("sensor", "work", "vb", "lb", "vs", "ls")}
    te = source_envelope(d, "sensor-telemetry", keys={"site-sensors": k["sensor"]})
    log_b = Log("pop-b")
    store_b = Store(log_b)
    store_b.put(te, log_b.append(te["digest"]))
    env, chain = te, [te]
    for n in range(50):
        env = derive(d, [env], "pop-b-transform", "transform", at=f"2026-10-10T06:{n:02d}:00Z", key=k["work"])
        store_b.put(env, log_b.append(env["digest"]))
        chain.append(env)
    cp = checkpoint(k["vb"], "pop-b-verifier", chain[40]["digest"], len(log_b.leaves))
    b = make_bundle(store_b, env["digest"], [cp], log_b, log_b.sth(k["lb"], "2026-10-10T07:00:00Z"))
    assert len(b["envelopes"]) == 11
    register = {"site-sensors": k["sensor"].public_key(),
                "pop-b-transform": {"key": k["work"].public_key(), "not_before": "2026-10-10T05:00:00Z",
                                    "not_after": "2026-10-10T07:00:00Z"}}       # PoP B may be long gone
    signers, log_keys = {"pop-b-verifier": k["vb"].public_key()}, {"pop-b": k["lb"].public_key()}
    assert verify_bundle(d, b, register, signers, log_keys) == []
    bad = copy.deepcopy(b)
    bad["envelopes"][3]["label"] = "Restricted"
    assert "does not match its digest" in verify_bundle(d, bad, register, signers, log_keys)[0]
    assert verify_bundle(d, b, register, {}, log_keys) != []                     # untrusted signer: ancestors missing
    assert "not signed by a registered log key" in verify_bundle(d, b, register, signers, {})[0]
    moved = copy.deepcopy(b)
    first = next(iter(moved["proofs"]))
    moved["proofs"][first]["index"] = (moved["proofs"][first]["index"] + 1) % moved["sth"]["size"]
    assert "not proven to be in log" in verify_bundle(d, moved, register, signers, log_keys)[0]
    log_s = Log("site-s")
    clock = {"revoked": frozenset(), "tombstones": frozenset(), "now": "2026-10-10T07:05:00Z"}
    fwd = rebundle(d, b, register, signers, log_keys, k["vs"], "site-s-verifier", log_s, k["ls"], "2026-10-10T07:05:00Z", **clock)
    assert len(fwd["envelopes"]) == 1
    assert verify_bundle(d, fwd, register, {"site-s-verifier": k["vs"].public_key()}, {"site-s": k["ls"].public_key()}) == []
    with _pytest.raises(ValueError, match="cannot vouch"):
        rebundle(d, bad, register, signers, log_keys, k["vs"], "site-s-verifier", log_s, k["ls"], "2026-10-10T07:06:00Z", **clock)
    scoped = {"pop-b-verifier": {"key": k["vb"].public_key(), "scope": {"products": ["hr-roster"], "max_label": "Sensitive"}}}
    assert "outside its scope" in verify_bundle(d, b, register, scoped, log_keys)[0]
    assert verify_bundle(d, b, register, signers, log_keys, revoked={chain[40]["digest"]}) != []
    assert "tombstone" in verify_bundle(d, b, register, signers, log_keys, tombstones={chain[45]["digest"]})[0]
    assert "stale" in verify_bundle(d, b, register, signers, log_keys, now="2026-10-20T07:00:00Z")[0]
    assert "key register is older" in verify_bundle(d, b, register, signers, log_keys, now="2026-10-11T07:00:00Z",
                                                    register_issued="2026-09-01T00:00:00Z")[0]
    newer = {"log": "pop-b", "size": b["sth"]["size"] + 5, "root": "00" * 32}
    assert "split view" in verify_bundle(d, b, register, signers, log_keys, last_seen=newer)[0]
    older_head = {"log": "pop-b", "size": 20, "root": log_b.root(20).hex()}
    assert "split view" in verify_bundle(d, b, register, signers, log_keys, last_seen=older_head)[0]
    b2 = dict(b, consistency_from={"20": [h.hex() for h in log_b.consistency(20, b["sth"]["size"])]})
    assert verify_bundle(d, b2, register, signers, log_keys, last_seen=older_head) == []
    with _pytest.raises(ValueError, match="within the tenant"):
        make_bundle(store_b, env["digest"], [cp], log_b, b["sth"], ring="federation")


def test_a_sensor_record_an_unsourced_chat_claim_and_a_paper_map_combine_with_honest_provenance():
    """ADR-0099: an analyst's three sources. A JSON record from a sensor stream is attested; a colleague's chat
    claim is attributable but rests on a source he did not identify, so it is unidentified and incomplete and asks
    him to name it; a paper map on the wall enters as a transcribed surrogate of a registered item. The analysis cites
    each by digest (the chat by span selector, no text), takes the weakest assurance and is incomplete; releasing it
    to the tenant needs the provenance reviewer. When the colleague names his source, the restated claim supersedes
    the old one, the analysis turns stale, and the recomputed analysis is complete."""
    import hashlib
    import json as _json
    import pytest as _pytest
    from data_provenance import derive, impact, load, route, source_envelope, source_request, verify
    d = load()
    G = {"band": "green", "site_band": "green"}   # ADR-0126: the request states its bands; a missing one decides as black
    import hmac
    quote = "sha256:" + "0f" * 32
    sensor = source_envelope(d, "sensor-telemetry", subject={"event": "cloudevents:site-sensors/0001842", "seq": 1842},
                             measurements={"site-sensors": quote})
    assert source_envelope(d, "sensor-telemetry")["assurance"] == "signed"            # no measurement, not attested
    span = hmac.new(b"owner-span-key", "the road north of the depot floods first".encode(), hashlib.sha256).hexdigest()
    chat = source_envelope(d, "analyst-chat", unidentified=1, subject={"message": "urn:vdh:tenant:chat:msg:0192f3"})
    mapp = source_envelope(d, "physical-references", subject={
        "physical_item": "urn:vdh:tenant:asset:map-0042", "surrogate": "photo", "surrogate_digest": "sha256:" + "ab" * 32,
        "capture_signer": "reference-desk"})
    with _pytest.raises(ValueError, match="capture signer"):
        source_envelope(d, "physical-references", subject={"physical_item": "urn:vdh:tenant:asset:map-0042"})
    assert (sensor["assurance"], chat["assurance"], mapp["assurance"]) == ("attested", "unidentified", "transcribed")
    assert "floods" not in _json.dumps(chat)
    req = source_request(d, chat)
    assert req and req[0]["to"] == "analysts" and source_request(d, sensor) == []
    sel = {chat["digest"]: {"type": "TextPositionSelector", "unit": chat["digest"], "start": 40, "end": 81, "keyed_digest": span}}
    with _pytest.raises(ValueError, match="keyed span digest"):
        derive(d, [chat], "x", "y", selectors={chat["digest"]: {"start": 5, "end": 1}})
    assert "floods" not in _json.dumps(sel)                                        # cited by position and keyed digest
    analysis = derive(d, [sensor, chat, mapp], "me-analysis", "assess flooding risk on the north road", selectors=sel)
    assert (analysis["assurance"], analysis["complete"]) == ("unidentified", False)
    known = {e["digest"]: e for e in (sensor, chat, mapp)}
    assert verify(d, analysis, known) == []
    with _pytest.raises(ValueError, match="selector points at an input"):
        derive(d, [sensor], "x", "y", selectors={chat["digest"]: {}})
    assert route(d, analysis, {"kind": "release", "target_ring": "tenant", "purpose": "operations"} | G)["decision"] == "refused"
    r = route(d, analysis, {"kind": "access", "target_ring": "site", "purpose": "operations"} | G)
    assert r["provenance_complete"] is False and r["assurance"] == "unidentified"   # usable at the site, flagged
    named = source_envelope(d, "analyst-chat", subject={"message": "urn:vdh:tenant:chat:msg:0192f9"})
    cited = source_envelope(d, "sensor-telemetry", subject={"event": "cloudevents:site-sensors/0001790"})
    claim2 = derive(d, [named, cited], "analysts", "restate the claim with its source")
    states = impact(d, [sensor, chat, mapp, analysis], [{"id": "my-note", "refs": [analysis["digest"]],
                                                       "relevant_until": "2026-12-31"}], chat["digest"], "supersession", "2026-10-10")
    assert states == {analysis["digest"]: "stale", "my-note": "stale"}
    analysis2 = derive(d, [sensor, claim2, mapp], "me-analysis", "assess flooding risk on the north road")
    assert (analysis2["assurance"], analysis2["complete"]) == ("transcribed", True)
    r2 = route(d, analysis2, {"kind": "release", "target_ring": "tenant", "purpose": "operations"} | G)
    assert "provenance-reviewer" in r2["approvers"]                                # a transcribed map is still weak
    r3 = route(d, derive(d, [sensor, claim2], "me-analysis", "without the map"), {"kind": "release", "target_ring": "tenant", "purpose": "operations"} | G)
    assert "provenance-reviewer" not in r3["approvers"] and r3["assurance"] == "asserted"


def test_data_limits_are_policy_packs_that_tenants_tighten_or_except_with_accepted_risk(tmp_path, monkeypatch):
    """ADR-0100: rings per label, weak-provenance caps, the minimum group size and subscription limits are rules in
    policy packs naming their standards; a tenant pack tightens them (vdh-demo: group 25, Restricted leases 30 days)
    and loosens one only with raises_risk, a minimum trust and an acceptance (Sensitive to partners for high-trust
    requesters); derivation and routing follow the tenant's limits; OPA resolves the same rules; a loosening without
    accepted risk, or a standard missing from the register, is caught."""
    import pytest as _pytest
    import policy_engine
    from data_policy import check, limits
    from data_provenance import derive, load, route, source_envelope
    from policy_compile import build, evaluate
    assert check() == [], check()
    base, demo, demo_hi = limits(), limits({"tenant": "vdh-demo"}), limits({"tenant": "vdh-demo", "trust": "high"})
    assert (base["min_group_size"], demo["min_group_size"]) == (10, 25)
    assert (base["subscription_max_days"]["Restricted"], demo["subscription_max_days"]["Restricted"]) == (90, 30)
    assert demo["label_max_ring"]["Sensitive"] == "tenant" and demo_hi["label_max_ring"]["Sensitive"] == "federation"
    d = load()
    G = {"band": "green", "site_band": "green"}   # ADR-0126: the request states its bands; a missing one decides as black
    hr = source_envelope(d, "hr-roster")
    derive(d, [hr], "x", "count", aggregate=True, group_size=12)
    with _pytest.raises(ValueError, match="minimum group size 25"):
        derive(d, [hr], "x", "count", aggregate=True, group_size=12, tenant="vdh-demo")
    req = {"kind": "release", "target_ring": "federation", "purpose": "scheduling", "tenant": "vdh-demo"} | G
    low, high = route(d, hr, req), route(d, hr, req | {"trust": "high"})
    assert low["declassification"] and not high["declassification"]
    assert high["approvers"] == ["hr-service-owner", "release_officer"]
    b = build(tmp_path / "bundle")
    ctx = {"day": "2026-10-10", "label": "Sensitive", "tenant": "vdh-demo", "band": "green"}
    hi = evaluate(b, ctx | {"trust": "high"})["data-max-ring"]
    lo = evaluate(b, ctx | {"trust": "medium"})["data-max-ring"]
    assert (hi["rule"], hi["parameter"]) == ("DEMO-SENSITIVE-TO-PARTNERS", "federation")
    assert (lo["rule"], lo["parameter"]) == ("DATA-RING-SENSITIVE", "tenant")
    real = policy_engine.load

    def with_extra(*a, **k):
        model, rules = real(*a, **k)
        extra = [{"id": "SNEAKY", "topic": "data-min-group-size", "effect": "require", "parameter": 3, "scope": {"tenant": ["vdh-demo"]},
                  "valid_from": "2026-10-01", "mitigates": [], "anchor": "configuration", "standards": ["iso-27001:A.8.11"]},
                 {"id": "UNREGISTERED", "topic": "data-min-group-size", "effect": "require", "parameter": 50, "scope": {"tenant": ["other"]},
                  "valid_from": "2026-10-01", "mitigates": [], "anchor": "configuration", "standards": ["made-up-standard"]}]
        return model, rules + extra
    monkeypatch.setattr(policy_engine, "load", with_extra)
    errs = check()
    assert any("SNEAKY: loosens data-min-group-size" in e for e in errs) and any("made-up-standard" in e for e in errs)


def test_one_security_label_renders_into_every_standard_form():
    """ADR-0103: one canonical label per unit, rendered as SPIF policy, STANAG 4774 label, ESS label (RFC 2634),
    RFC 7444 SIO-Label header, XEP-0258 element, Matrix field and STANAG 4778 binding. Conformance anchors are the
    standards' own published examples (RFC 7444 and XEP-0258 ESS labels); every form round-trips to the same label."""
    import base64
    import copy
    import xml.etree.ElementTree as _ET
    import security_labels as sl
    from data_provenance import load, source_envelope
    assert sl.check() == []
    assert sl.ess_decode("MQYGASkCAQM=") == {"policy": "1.1", "classification": 3, "privacy_mark": None, "categories": None}
    assert sl.ess_decode("MQYCAQQGASk=")["classification"] == 4 and sl.ess_encode("1.1", 4) == "MQYCAQQGASk="
    assert sl.ess_decode("MRUCAgD9DA9BcXVhIChvYnNvbGV0ZSk=")["privacy_mark"] == "Aqua (obsolete)"
    d = load()
    env = source_envelope(d, "case-files-index")
    lab = sl.canonical(env)
    x = sl.parse_4774(sl.xml(sl.stanag4774(lab)))
    assert (x["policy"], x["classification"]) == ("VDHOME", "RESTRICTED") and x["policy_uri"].startswith("urn:oid:2.25.")
    assert ("PERMISSIVE", "Releasable Within", ["host", "site"]) in x["categories"]
    assert ("PERMISSIVE", "Purpose", ["case-handling"]) in x["categories"] and x["created"]
    info = list(_ET.fromstring(sl.xml(sl.stanag4774(lab)))[0])
    assert [c.tag.split("}")[1] for c in info][:2] == ["PolicyIdentifier", "Classification"]
    h = sl.sio_label(lab)
    assert h.startswith("SIO-Label: ") and max(len(line) for line in h.split("\r\n")) <= 78
    p = sl.parse_sio_label(h)
    assert (p["marking"], p["fgcolor"], p["bgcolor"], p["type"]) == ("VDHOME RESTRICTED", "white", "red", ":xml")
    assert sl.parse_4774(base64.b64decode(p["label"]).decode()) == x
    e = sl.ess_decode(sl.parse_sio_label(sl.sio_label(lab, ":ess"))["label"])
    assert e["classification"] == 3 and e["policy"] == sl.policy()["policy"]["oid"] and "WITHIN SITE" in e["privacy_mark"]
    xr = _ET.fromstring(sl.xep0258(lab))
    assert xr.tag == "{urn:xmpp:sec-label:0}securitylabel" and len(xr.findall("{urn:xmpp:sec-label:0}label")) == 1
    assert xr.find("{urn:xmpp:sec-label:0}displaymarking").get("bgcolor") == "red"
    ess = xr.find("{urn:xmpp:sec-label:0}equivalentlabel/{urn:xmpp:sec-label:ess:0}esssecuritylabel").text
    assert sl.ess_decode(ess)["classification"] == 3
    m = sl.matrix(lab)["org.vdhome.security_label"]
    assert sl.parse_4774(m["stanag4774"]) == x and sl.ess_decode(m["ess"])["classification"] == 3
    b = _ET.fromstring(sl.stanag4778(lab, env))
    assert b.tag == "{urn:nato:stanag:4778:bindinginformation:1:0}MetadataBindingContainer"
    assert env["digest"] in b.find(".//{urn:nato:stanag:4778:bindinginformation:1:0}DataReference").get("URI")
    assert b.find(".//{urn:nato:stanag:4774:confidentialitymetadatalabel:1:0}originatorConfidentialityLabel") is not None
    s = _ET.fromstring(sl.spif())
    ns = "{http://www.xmlspif.org/spif}"
    assert s.get("schemaVersion") == "3.0" and s.find(ns + "securityPolicyId").get("id") == sl.policy()["policy"]["oid"]
    assert [c.get("lacv") for c in s.iter(ns + "securityClassification")] == ["1", "2", "3"]
    assert {t.get("tagType") for t in s.iter(ns + "securityCategoryTag")} == {"permissive", "restrictive", "tagType7"}
    purposes = {t.get("name") for ts in s.iter(ns + "securityCategoryTagSet") if ts.get("name") == "Purpose" for t in ts.iter(ns + "tagCategory")}
    assert purposes >= {p for q in d["dp"]["products"].values() for p in q["purposes"]}
    assert set(sl.policy()["classifications"]) == {"Internal", "Sensitive", "Restricted"}
    real = sl.policy

    def bad():
        p2 = copy.deepcopy(real())
        p2["classifications"]["Restricted"]["marking"] = "RESTRICTED"
        p2["classifications"]["Internal"]["bgcolor"] = "chartreuse"
        return p2
    sl.policy = bad
    try:
        errs = sl.check()
    finally:
        sl.policy = real
    assert any("must name the policy" in e for e in errs) and any("named colours" in e for e in errs)


def test_a_message_citing_restricted_data_reaches_exactly_the_people_policy_allows():
    """ADR-0104, the mail walkthrough as a regression: a message citing a Restricted case record takes the record's
    purpose (the chat product never narrows it); the colleague holding a case-handling lease is allowed; one without a
    lease needs the case owner and the cases steward; another site needs a declassification by the case owner, the
    release officer, the cases steward and the security officer, never the chat product's owner; an outsider is refused
    by the ceiling (Restricted never leaves the tenant); a correction taints the message."""
    from data_provenance import derive, impact, load, route, source_envelope
    d = load()
    G = {"band": "green", "site_band": "green"}   # ADR-0126: the request states its bands; a missing one decides as black
    case = source_envelope(d, "case-files-index", subject={"record": "urn:vdh:tenant:case:2026-0412"})
    body = source_envelope(d, "analyst-chat", subject={"message": "urn:vdh:tenant:mail:draft-1"})
    msg = derive(d, [case, body], "you", "two sentences of analysis citing the record")
    assert (msg["label"], msg["releasable_to"], msg["purposes"]) == ("Restricted", "site", ["case-handling"])
    A = {"kind": "access", "target_ring": "site", "purpose": "case-handling"} | G
    ok = route(d, msg, A | {"reader": "case-officers"})
    assert ok["decision"] == "allowed-by-policy" and ok["entitled"] == ["DL-0008"]
    no = route(d, msg, A | {"reader": "analysts"})
    assert no["decision"] == "needs-approval" and no["approvers"] == ["case-owner", "cases-domain-lead"]
    other = route(d, msg, {"kind": "release", "target_ring": "tenant", "purpose": "case-handling"} | G)
    assert other["approvers"] == ["case-owner", "release_officer", "cases-domain-lead", "security_officer"]
    out = route(d, msg, {"kind": "release", "target_ring": "federation", "purpose": "case-handling"} | G)
    assert out["decision"] == "refused" and "never leaves the tenant" in out["reason"]
    assert impact(d, [case, body, msg], [{"id": "mail", "refs": [msg["digest"]]}], case["digest"], "correction", "2026-10-10")["mail"] == "tainted"
    chat_only = derive(d, [body], "you", "a message citing nothing")
    assert chat_only["purposes"] == ["analysis", "operations"]


def test_a_transcript_outlives_its_audio_only_as_a_registered_minimisation_with_machine_fidelity():
    """ADR-0104, the Matrix call as a regression: a transcript derived from one-day call audio ends with the audio
    unless it is a registered minimisation, which may keep it up to the label's maximum; machine interpretation caps
    assurance at transcribed and carries its method and confidence, and a derivation keeps the lowest confidence; all
    of it survives verification."""
    import copy
    import pytest as _pytest
    from data_provenance import derive, load, source_envelope, verify
    d = copy.deepcopy(load())
    d["dp"]["products"]["case-call-media"] = dict(d["dp"]["products"]["case-files-index"], retention_days=1,
                                                  originators=["case-officers"], schema="webrtc-media-v1")
    media = source_envelope(d, "case-call-media", subject={"call": "rtc:case-0412:1"})
    plain = derive(d, [media], "transcriber", "speech to text")
    assert plain["valid_until"] == "2026-10-11"
    asr = {"method": "speech-to-text", "confidence": 0.87, "speaker_attribution": "call identity per track"}
    t = derive(d, [media], "transcriber", "speech to text", minimisation={"kind": "transcribe", "retain_days": 365},
               interpretation=asr)
    assert t["valid_until"] == "2027-10-10" and t["assurance"] == "transcribed" and t["fidelity"]["confidence"] == 0.87
    s = derive(d, [t], "summariser", "summary", interpretation={"method": "llm-summary", "confidence": 0.95},
               minimisation={"kind": "summarise", "retain_days": 730})
    assert s["fidelity"]["confidence"] == 0.87                    # the weakest interpretation along the way
    assert verify(d, s, {media["digest"]: media, t["digest"]: t}) == []
    with _pytest.raises(ValueError, match="not registered"):
        derive(d, [media], "x", "y", minimisation={"kind": "keep-forever", "retain_days": 10})
    with _pytest.raises(ValueError, match="kept at most"):
        derive(d, [media], "x", "y", minimisation={"kind": "transcribe", "retain_days": 99999})
    with _pytest.raises(ValueError, match="confidence between 0 and 1"):
        derive(d, [media], "x", "y", interpretation={"method": "ocr", "confidence": 3})


def test_the_mail_gate_decides_per_recipient_and_fails_closed():
    """ADR-0105: the gated mail walkthrough with its fixes. A Restricted message citing a case record is
    delivered to the leased colleague, held for the unleased one and for another site, refused for an outsider, a
    nested list and a lookalike domain; the subject is neutral, the SIO-Label names the label, bounces carry no content;
    a link the sender may not open is refused with the same answer whether or not it exists; unscannable or non-unit
    attachments, uncited personal data, a stale directory and any error stop the message before anyone receives it."""
    import base64
    import json as _json
    from data_provenance import load, source_envelope
    from mail_gate import gate
    from security_labels import parse_4774, parse_sio_label
    d = load()
    case = source_envelope(d, "case-files-index", subject={"record": "urn:vdh:tenant:case:2026-0412"})
    directory = {"_meta": {"synced": "2026-10-10T06:00:00"},
                 "lieve@vdhome.example": {"kind": "person-role", "principal": "case-officers", "ring": "site"},
                 "an@vdhome.example": {"kind": "person-role", "principal": "analysts", "ring": "site"},
                 "jef@vdhome.example": {"kind": "person-role", "principal": "analysts", "ring": "tenant"},
                 "team@vdhome.example": {"kind": "list", "members": ["lieve@vdhome.example", "an@vdhome.example"]},
                 "outer@vdhome.example": {"kind": "list", "members": ["team@vdhome.example"]}}
    sub = {"sender": "case-officers", "sender_ring": "site", "band": "green", "site_band": "green",   # ADR-0126
           "subject": "Case 2026-0412: flooding on the north road",
           "body": "The depot report understates the risk. I would not wait for the next survey.", "links": [case],
           "purpose": "case-handling",
           "addresses": ["team@vdhome.example", "lieve@vdhome.example", "jef@vdhome.example", "partner@other.org",
                         "outer@vdhome.example", "x@vdh0me.example"]}
    r = gate(d, sub, directory)
    got = {x["to"]: x["decision"] for x in r["deliveries"]}
    assert got == {"lieve@vdhome.example": "deliver", "an@vdhome.example": "hold", "jef@vdhome.example": "hold",
                   "partner@other.org": "refused", "outer@vdhome.example": "refused", "x@vdh0me.example": "refused"}
    assert sum(1 for x in r["deliveries"] if x["to"] == "lieve@vdhome.example") == 1          # list and direct: once
    held = {x["to"]: x["approvers"] for x in r["deliveries"] if x["decision"] == "hold"}
    assert held["an@vdhome.example"] == ["case-owner", "cases-domain-lead"]
    assert held["jef@vdhome.example"] == ["case-owner", "release_officer", "cases-domain-lead", "security_officer"]
    assert r["subject"].startswith("Restricted message") and "2026-0412" not in r["subject"]
    h = parse_sio_label("SIO-Label: " + r["headers"]["SIO-Label"])
    assert h["marking"] == "VDHOME RESTRICTED" and parse_4774(base64.b64decode(h["label"]).decode())["classification"] == "RESTRICTED"
    bounced = _json.dumps(r["bounces"])
    assert len(r["bounces"]) == 3 and "flooding" not in bounced and "depot" not in bounced and "2026-0412" not in bounced
    stranger = dict(sub, sender="analysts")
    fake = dict(case, sources=["no-such-product"])
    a, b = gate(d, stranger, directory), gate(d, dict(stranger, links=[fake]), directory)
    assert a == b and a["code"] == "link-not-available" and not a["deliveries"]
    assert gate(d, dict(sub, attachments=[{"name": "x.zip", "encrypted": True}]), directory)["code"] == "attachment-unscannable"
    assert gate(d, dict(sub, attachments=[{"name": "y.zip", "depth": 5, "unit": "u"}]), directory)["code"] == "attachment-unscannable"
    assert gate(d, dict(sub, attachments=[{"name": "notes.docx"}]), directory)["code"] == "attachment-not-a-unit"
    leak = dict(sub, links=[], purpose="operations", body="Refund to BE71 0961 2345 6769 for the depot lead.")
    assert gate(d, leak, directory)["code"] == "uncited-personal-data"
    stale = dict(directory, _meta={"synced": "2026-10-08T06:00:00"})
    assert gate(d, sub, stale)["result"] == "tempfail"
    broken = {k: v for k, v in sub.items() if k != "purpose"}
    t = gate(d, broken, directory)
    assert t["result"] == "tempfail" and t["deliveries"] == []


def test_data_logistics_places_seeds_drains_and_backs_up_by_policy():
    """ADR-0106: a new PoP pulls mission-critical data first; each product is placed only with a demand, a lease and a
    ring that allows the site; a seed that the link cannot carry in time goes by carrier (ciphertext, two-person custody)
    and the site then pulls only the deltas, with a warning when the link cannot keep up; site-bound data reaches a PoP
    only when the PoP is a declared member of the parent's site ring. Spin-down drains originated data within its ring,
    holds back site-bound data, crypto-shreds caches and keys, and power-off waits for every drain to be acknowledged.
    Backups are ciphertext, keys apart, shred ledger first, and site-bound offline copies stay at their site."""
    import copy
    from data_logistics import backup, check, policy, spin_down, spin_up, transport

    def check_logistics(d_, pl_):
        import data_logistics as _dl
        real = _dl.policy
        _dl.policy = lambda: pl_
        try:
            return _dl.check(d_)
        finally:
            _dl.policy = real
    from data_provenance import load
    d, pl = load(), policy()
    assert check(d) == []
    dem = [{"product": "sensor-telemetry", "home": "edge-1", "reader": "analytics-lakehouse", "purpose": "analytics"},
           {"product": "policy-bundles", "home": "core-1", "reader": "site-pdps", "purpose": "enforcement"},
           {"product": "case-files-index", "home": "edge-1", "reader": "case-officers", "purpose": "case-handling"},
           {"product": "hr-roster", "home": "core-1", "reader": "analysts", "purpose": "scheduling"}]
    plan = {s["product"]: s for s in spin_up(d, pl, "pop-17", dem, 48)}
    assert [s["product"] for s in spin_up(d, pl, "pop-17", dem, 48)][:2] == ["policy-bundles", "case-files-index"]
    assert plan["policy-bundles"]["move"]["mode"] == "network"
    seed = plan["sensor-telemetry"]["move"]
    assert seed["mode"] == "carrier" and seed["carriers"] == 1 and seed["delta_gb"] == 180 and seed["sustain"]["advice"]
    assert plan["case-files-index"]["allowed"]          # pop-17 is an evidenced member of edge-1's site ring
    assert not plan["hr-roster"]["allowed"] and "request one first" in plan["hr-roster"]["reason"]
    alone = copy.deepcopy(pl)
    alone["memberships"]["pop-17"]["conditions"]["overlay_only"] = None
    refused = {s["product"]: s for s in spin_up(d, alone, "pop-17", dem, 48)}["case-files-index"]
    assert not refused["allowed"] and "site ring" in refused["reason"]
    assert any("conditions without evidence" in e for e in check_logistics(d, alone))
    lapsed = copy.deepcopy(pl)
    lapsed["memberships"]["pop-17"]["member_until"] = "2026-10-01"
    assert not {s["product"]: s for s in spin_up(d, lapsed, "pop-17", dem, 48)}["case-files-index"]["allowed"]
    wrong = copy.deepcopy(pl)
    wrong["memberships"]["pop-17"]["ring_site"] = "core-1"
    assert any("own parent" in e for e in check_logistics(d, wrong))
    assert transport(pl, "hr-roster", "edge-1", 4)["mode"] == "network"
    held = [{"unit": "u1", "product": "sensor-telemetry", "origin": "originated", "home": "edge-1"},
            {"unit": "u2", "product": "case-files-index", "origin": "originated", "home": "edge-1"},
            {"unit": "u3", "product": "hr-roster", "origin": "cached", "home": "core-1"},
            {"unit": "a1", "product": "audit-log", "origin": "audit", "home": "core-1"},
            {"unit": "k1", "product": "-", "origin": "key", "home": "-"}]
    down = spin_down(d, pl, "pop-17", held)
    act = {s["unit"]: s["action"] for s in down["steps"]}
    assert act["u1"] == "drain" and act["u2"] == "drain" and act["u3"] == "crypto-shred and wipe"
    assert act["k1"].startswith("destroy") and not down["power_off_allowed"] and set(down["pending"]) == {"u1", "u2", "a1"}
    assert spin_down(d, pl, "pop-17", held, acks={"u1", "u2", "a1"})["power_off_allowed"]
    assert {s["unit"]: s["action"] for s in spin_down(d, alone, "pop-17", held)["steps"]}["u2"].startswith("carrier-return")
    b = backup(d, pl, "case-files-index")
    assert b["contents"] == "ciphertext only" and "offline-carrier" in b["copies"] and "own site" in b["offline_location"]
    assert backup(d, pl, "platform-health")["copies"] == ["second-provider"]


def test_an_attested_device_on_the_site_overlay_counts_as_inside_the_site():
    """ADR-0107: a colleague based at another site, on an attested, enrolled, managed device on edge-1's overlay with
    no other route, is inside edge-1's site ring: with her lease she reads Restricted case data there (the Matrix
    remote participant joins through the site's own homeserver). A stale attestation, a split tunnel, an unmanaged or
    unenrolled device, or another site's overlay puts her outside again, and access to Restricted data is refused."""
    import copy
    from data_provenance import load, reader_ring, route, source_envelope
    d = load()
    G = {"band": "green", "site_band": "green"}   # ADR-0126: the request states its bands; a missing one decides as black
    case = source_envelope(d, "case-files-index")
    good = {"site": "core-1", "tenant_member": True,
            "device": {"attested_at": "2026-10-10T09:40:00", "enrolled": "active", "overlay_site": "edge-1",
                       "overlay_only": True, "managed": True}}
    at = "2026-10-10T10:00:00"
    assert reader_ring(d, "edge-1", {"site": "edge-1"}, at) == "federation"   # ADR-0126: a bare claim is no evidence
    assert reader_ring(d, "edge-1", good, at) == "site"
    A = {"kind": "access", "purpose": "case-handling", "reader": "case-officers"} | G
    assert route(d, case, A | {"target_ring": reader_ring(d, "edge-1", good, at)})["decision"] == "allowed-by-policy"
    for change in ({"attested_at": "2026-10-10T08:30:00"}, {"overlay_only": False}, {"managed": False},
                   {"enrolled": "quarantined"}, {"overlay_site": "core-1"}):
        bad = copy.deepcopy(good)
        bad["device"].update(change)
        ring = reader_ring(d, "edge-1", bad, at)
        assert ring == "tenant", change
        assert route(d, case, A | {"target_ring": ring})["decision"] == "refused", change
    assert reader_ring(d, "edge-1", {"site": "partner-hq"}, at) == "federation"
    rules = d["pv"]["rings"]["inside_site"]["devices"]
    assert set(rules["conditions"]) == {"attested_within_lease", "enrolled_active", "site_overlay_only", "managed_client"}
    assert "never through federation" in rules["matrix"]


def test_the_enforcement_path_guards_a_route_with_the_same_rules():
    """ADR-0109: a route through Envoy Gateway is guarded by ext_authz to the PDP, fail-closed; the PDP serves the
    compiled bundle including vdh.authz (Rego unit tests pass); the proxies listen on IPv6 behind a ClusterIP service; the
    cross-namespace reference is granted explicitly; the backend is digest-pinned and hardened."""
    import subprocess as _sp
    import yaml
    root = Path(__file__).resolve().parent.parent
    g = lambda rel: yaml.safe_load((root / "gitops" / "lab" / rel).read_text(encoding="utf-8"))
    sp = g("edge-demo/securitypolicy-data.yaml")
    assert sp["spec"]["extAuth"]["failOpen"] is False
    assert sp["spec"]["extAuth"]["grpc"]["backendRefs"] == [{"name": "pdp", "namespace": "vdh-pdp", "port": 9191}]
    assert sp["spec"]["targetRefs"][0]["name"] == g("edge-demo/httproute-data.yaml")["metadata"]["name"]
    ep = g("layer1-config/envoyproxy-vdh-proxy.yaml")
    assert ep["spec"]["ipFamily"] == "IPv6" and ep["spec"]["provider"]["kubernetes"]["envoyService"]["type"] == "ClusterIP"
    assert g("layer1-config/gateway.yaml")["spec"]["parametersRef"]["name"] == "vdh-proxy"
    rg = g("pdp/referencegrant-authz.yaml")
    assert rg["spec"]["from"][0]["kind"] == "SecurityPolicy" and rg["spec"]["to"][0]["name"] == "pdp"
    cfg = g("pdp/opa-config.yaml")
    assert cfg["plugins"]["envoy_ext_authz_grpc"]["path"] == "vdh/authz/allow" and cfg["decision_logs"]["console"] is True
    dep = g("pdp/deployment-pdp.yaml")["spec"]["template"]["spec"]["containers"][0]
    assert "-envoy-static@sha256:" in dep["image"] and "/policy/authz.rego" in dep["args"]
    who = g("edge-demo/deployment-whoami.yaml")["spec"]["template"]["spec"]["containers"][0]
    assert "@sha256:" in who["image"] and who["securityContext"]["readOnlyRootFilesystem"] is True
    assert (root / "gitops/lab/pdp/bundle/authz.rego").exists()
    r = _sp.run(["opa", "test", str(root / "policy")], capture_output=True, text=True)
    assert r.returncode == 0 and "PASS" in r.stdout


def test_pops_mesh_and_elect_a_temporary_isle_by_priority_and_uid():
    """ADR-0116: like OSPF's designated router. Highest priority, then highest UID; priority 0 never; only current
    members of the same ring; non-preemptive while the holder's lease lives; an Isle in reach ends the role; when two
    partitions meet the lower-ranked stand-in yields."""
    from datetime import datetime as _dt
    from standin import Pop, elect, merge
    now = _dt(2026, 10, 10, 14)
    later = _dt(2026, 11, 9)
    a = Pop("pop-0a1", "edge-1", later)
    b = Pop("pop-0f7", "edge-1", later)
    c = Pop("pop-0c3", "edge-1", later, priority=0)
    d = Pop("pop-0ff", "edge-2", later)                       # another ring: never joins
    e = Pop("pop-0fe", "edge-1", _dt(2026, 10, 1))            # membership lapsed: never joins
    r = elect([a, b, c, d, e], "edge-1", now, isle_reachable=False)
    assert r["stand_in"] == "pop-0f7" and r["backup"] == "pop-0a1"          # same priority: highest UID
    assert elect([a, b], "edge-1", now, isle_reachable=True)["stand_in"] is None
    assert elect([c], "edge-1", now, isle_reachable=False)["stand_in"] is None   # priority 0 never stands in
    boss = Pop("pop-001", "edge-1", later, priority=5)        # a sysadmin's real order beats the UID
    assert elect([a, b, boss], "edge-1", now, isle_reachable=False)["stand_in"] == "pop-001"
    # non-preemptive: the holder keeps a live lease when a better-ranked PoP arrives; it yields when the lease lapses
    assert elect([a, b, boss], "edge-1", now, False, holder="pop-0f7", holder_lease_live=True)["stand_in"] == "pop-0f7"
    assert elect([a, b, boss], "edge-1", now, False, holder="pop-0f7", holder_lease_live=False)["stand_in"] == "pop-001"
    pops = {p.uid: p for p in (a, b, boss)}
    assert merge({"stand_in": "pop-0a1"}, {"stand_in": "pop-001"}, pops) == "pop-001"


def test_skiffs_reach_the_overlay_through_any_relay_of_their_ring_under_their_own_lease():
    """ADR-0118: a NetBird relay on every Isle and Islet; a Skiff whose Islet is down roams to another site of its ring
    through any relay, keeping its own lease (no new grant, never outside the ring), bounded by SKIFF-ROAMING (RI-21)."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    layers = _y.safe_load((root / "platform/layers.yaml").read_text(encoding="utf-8"))
    assert "a NetBird relay on every Isle and Islet" in layers["topology"]["overlay-access"]["ha"]
    peer = layers["topology"]["overlay-access"]["peer"]
    assert "only for federation" in peer and "terminating at the site's Harbor" in peer   # strongSwan, optional
    voc = {t["term"]: t for t in _y.safe_load((root / "platform/vocabulary.yaml").read_text(encoding="utf-8"))["terms"]}
    assert "any Isle's or Islet's relay" in voc["Skiff"]["meaning"] and "own lease" in voc["Skiff"]["meaning"]
    rules = {r["id"]: r for r in _y.safe_load((root / "policies/packs/baseline.yaml").read_text(encoding="utf-8"))["rules"]}
    roam = rules["SKIFF-ROAMING"]
    assert roam["mitigates"] == ["RI-21"] and "never a site outside its ring" in roam["parameter"]
    secs = {"1h": 3600, "15m": 900, "0": 0}
    assert secs[roam["by_band"]["amber"]] >= secs[roam["by_band"]["red"]] >= secs[roam["by_band"]["black"]]


def test_every_lab_image_is_pinned_by_digest():
    """ADR-0120: every image the lab GitOps tree runs is pinned by digest: plain manifests by @sha256, Helm charts
    through a Flux post-renderer that sets a digest for each of their images, the Envoy data plane through the EnvoyProxy
    resource, PostgreSQL through the Cluster's imageName."""
    import re as _re
    import yaml as _y
    base = Path(__file__).resolve().parent.parent / "gitops" / "lab"
    dig = _re.compile(r"^sha256:[0-9a-f]{64}$")
    seen = 0
    for f in base.rglob("*.yaml"):
        if f.name.endswith("-lock.yaml"):
            continue   # locks are not manifests; tools/pins.py checks them
        for doc in _y.safe_load_all(f.read_text(encoding="utf-8")):
            if not doc:
                continue
            kind = doc.get("kind")
            if kind == "HelmRelease":
                imgs = [i for pr in doc["spec"].get("postRenderers", []) for i in pr.get("kustomize", {}).get("images", [])]
                assert imgs and all(dig.match(i["digest"]) for i in imgs), f.name
                seen += 1
            elif kind == "EnvoyProxy":
                assert "@sha256:" in doc["spec"]["provider"]["kubernetes"]["envoyDeployment"]["container"]["image"], f.name
            elif kind == "Cluster" and doc.get("apiVersion", "").startswith("postgresql.cnpg.io"):
                assert "@sha256:" in doc["spec"]["imageName"], f.name
            for img in _re.findall(r"image: *\"?([^\s\"]+)", f.read_text(encoding="utf-8")):
                assert "@sha256:" in img, (f.name, img)
    assert seen == 6   # ADR-0172: approver-policy joins the five HelmReleases

def test_a_temporary_isle_may_stand_in_for_netbird_signal_never_management():
    """ADR-0124: one active NetBird management and signal per ring with a warm standby on another Isle; during a
    partition a temporary Isle may run only a signal stand-in (it forwards end-to-end encrypted offers between known
    peers and grants nothing), never management; the gap stays listed for overlay-access."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    layers = _y.safe_load((root / "platform/layers.yaml").read_text(encoding="utf-8"))
    topo = layers["topology"]["overlay-access"]
    assert "warm standby" in topo["ha"] and "ADR-0124" in topo["gap"]
    role = layers["temporary_isle"]["roles"]["overlay-access"]
    assert role["may"] == ["relay"]
    assert "signal stand-in" in role["note"] and "never NetBird management" in role["note"] and "admits no new peer" in role["note"]

def test_a_site_never_vouches_for_what_a_direct_receiver_would_refuse_and_later_taint_reaches_the_forwarded_copy():
    """ADR-0126: rebundle() verifies with the same revocations, tombstones and clock as any receiver,
    and they are required; its checkpoint signs the lineage it verified, so a tombstone or a revoked upstream
    checkpoint that arrives later still refuses the forwarded one-envelope bundle; stripping the lineage breaks the
    vouching signature."""
    import copy
    import pytest as _pytest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from data_provenance import Store, derive, load, source_envelope
    from provenance_bundle import make_bundle, rebundle, verify_bundle
    from provenance_log import Log, checkpoint
    d = load()
    k = {n: Ed25519PrivateKey.generate() for n in ("sensor", "work", "vb", "lb", "vs", "ls", "vp", "lp")}
    te = source_envelope(d, "sensor-telemetry", keys={"site-sensors": k["sensor"]})
    log_b = Log("pop-b")
    store_b = Store(log_b)
    store_b.put(te, log_b.append(te["digest"]))
    env, chain = te, [te]
    for n in range(50):
        env = derive(d, [env], "pop-b-transform", "transform", at=f"2026-10-10T06:{n:02d}:00Z", key=k["work"])
        store_b.put(env, log_b.append(env["digest"]))
        chain.append(env)
    cp = checkpoint(k["vb"], "pop-b-verifier", chain[40]["digest"], len(log_b.leaves))
    register = {"site-sensors": k["sensor"].public_key(),
                "pop-b-transform": {"key": k["work"].public_key(), "not_before": "2026-10-10T05:00:00Z",
                                    "not_after": "2026-10-10T07:00:00Z"}}
    signers, log_keys = {"pop-b-verifier": k["vb"].public_key()}, {"pop-b": k["lb"].public_key()}
    now = "2026-10-10T08:00:00Z"
    fresh = make_bundle(store_b, env["digest"], [cp], log_b, log_b.sth(k["lb"], "2026-10-10T07:00:00Z"))
    stale = make_bundle(store_b, env["digest"], [cp], log_b, log_b.sth(k["lb"], "2026-10-01T07:00:00Z"))
    log_s = Log("site-s")

    def vouch(bundle, **kw):
        return rebundle(d, bundle, register, signers, log_keys, k["vs"], "site-s-verifier", log_s, k["ls"],
                        "2026-10-10T07:59:00Z", **kw)
    nothing = {"revoked": frozenset(), "tombstones": frozenset()}
    # stale, tainted or revoked input is refused at the site as at a direct receiver
    for bundle, kw in ((stale, nothing), (fresh, {"revoked": frozenset(), "tombstones": {chain[45]["digest"]}}),
                       (fresh, {"revoked": {chain[40]["digest"]}, "tombstones": frozenset()})):
        assert verify_bundle(d, bundle, register, signers, log_keys, now=now, **kw) != []
        with _pytest.raises(ValueError, match="cannot vouch"):
            vouch(bundle, now=now, **kw)
    with _pytest.raises(TypeError):
        rebundle(d, fresh, register, signers, log_keys, k["vs"], "site-s-verifier", log_s, k["ls"], "2026-10-10T07:59:00Z")
    with _pytest.raises(ValueError, match="without a clock"):
        vouch(fresh, now="", **nothing)
    fwd = vouch(fresh, now=now, **nothing)
    parent = ({"site-s-verifier": k["vs"].public_key()}, {"site-s": k["ls"].public_key()})
    assert len(fwd["envelopes"]) == 1 and verify_bundle(d, fwd, register, *parent, now=now) == []
    # taint or revocation that arrives after the vouching still reaches the forwarded copy
    assert "tombstone" in verify_bundle(d, fwd, register, *parent, tombstones={chain[45]["digest"]})[0]
    assert "now revoked" in verify_bundle(d, fwd, register, *parent, revoked={chain[40]["digest"]})[0]
    # stripping the lineage breaks the vouching signature: the root is no longer vouched for
    stripped = copy.deepcopy(fwd)
    del stripped["checkpoints"][0]["lineage"]
    assert verify_bundle(d, stripped, register, *parent, tombstones={chain[45]["digest"]}) != []
    # a second hop carries the lineage on
    log_p = Log("parent-p")
    fwd2 = rebundle(d, fwd, register, parent[0], parent[1], k["vp"], "parent-verifier", log_p, k["lp"],
                    "2026-10-10T08:00:00Z", now=now, **nothing)
    top = ({"parent-verifier": k["vp"].public_key()}, {"parent-p": k["lp"].public_key()})
    assert verify_bundle(d, fwd2, register, *top, now=now) == []
    assert "tombstone" in verify_bundle(d, fwd2, register, *top, tombstones={chain[45]["digest"]})[0]

def test_charts_enter_only_from_the_in_site_mirror_locked_and_signed():
    """ADR-0126: no chart reaches the lab from the internet. The only HelmRepository is the in-site
    mirror over verified TLS; every HelmRelease takes its chart from it, pins the version and verifies the cosign
    signature; every installed chart is in gitops/lab/chart-lock.yaml with the sha256 of its archive, and the lock
    names nothing that is not installed. Charts come through one OCIRepository each, referenced by chartRef: the
    cosign verifier of a HelmRepository chart ignores the mirror CA."""
    import re
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    docs = [x for p in sorted((root / "gitops" / "lab").rglob("*.yaml")) if p.name != "chart-lock.yaml"
            for x in _y.safe_load_all(p.read_text(encoding="utf-8")) if isinstance(x, dict)]
    assert not [x for x in docs if x.get("kind") == "HelmRepository"], "no HelmRepository: charts come by chartRef"
    sources = {x["metadata"]["name"]: x["spec"] for x in docs if x.get("kind") == "OCIRepository" and x["metadata"]["name"].startswith("chart-")}
    for name, spec in sources.items():
        assert spec["url"] == f"oci://registry.vdh-mirror.svc.cluster.local:5000/charts/{name[len('chart-'):]}", name
        assert spec["certSecretRef"]["name"] == "mirror-ca", name
        assert spec["verify"] == {"provider": "cosign", "secretRef": {"name": "cosign-pub"}}, name
        assert spec["layerSelector"]["mediaType"] == "application/vnd.cncf.helm.chart.content.v1.tar+gzip", name
    lock = {(c["name"], c["version"]): c for c in _y.safe_load((root / "gitops/lab/chart-lock.yaml").read_text(encoding="utf-8"))["charts"]}
    assert all(re.fullmatch(r"[0-9a-f]{64}", c["sha256"]) for c in lock.values())
    assert all(c["source"].startswith(("https://", "oci://")) for c in lock.values())
    installed = set()
    for r in (x for x in docs if x.get("kind") == "HelmRelease"):
        assert "chart" not in r["spec"], r["metadata"]["name"]
        ref = r["spec"]["chartRef"]
        assert ref["kind"] == "OCIRepository" and ref["namespace"] == "flux-system" and ref["name"] in sources, r["metadata"]["name"]
        tag = str(sources[ref["name"]]["ref"]["tag"])
        assert re.fullmatch(r"v?\d+\.\d+\.\d+", tag), r["metadata"]["name"]
        installed.add((ref["name"][len("chart-"):], tag))
    assert installed == set(lock), (installed ^ set(lock))
    # no other source kind pulls charts or manifests from outside the mirror
    for x in docs:
        if x.get("kind") in ("GitRepository", "Bucket", "OCIRepository", "HelmChart"):
            url = str(x.get("spec", {}).get("url", ""))
            assert not url or url.startswith("oci://registry.vdh-mirror.svc.cluster.local:5000/"), (x["kind"], url)


def test_every_lab_manifest_passes_the_schema_its_ring_applies(monkeypatch):
    """Every document in the lab tree validates against the schema a ring's API server applies (captured
    from a ring into frameworks/k8s-api/schemas.json), strictly as Flux's dry run does: unknown fields, missing required
    fields and wrong types fail. A kind without a captured schema fails, and so does a chart or Flux version that differs
    from the capture. The mutations are the kinds of error a ring's API server refuses."""
    import copy
    import api_schemas
    assert api_schemas.check() == []
    real = list(api_schemas.docs())

    def errs(mutate):
        ds = copy.deepcopy(real)
        mutate(ds)
        monkeypatch.setattr(api_schemas, "docs", lambda root=None: iter(ds))
        return " | ".join(api_schemas.check())

    def doc(ds, kind, name):
        return next(d for _, d in ds if d["kind"] == kind and d["metadata"]["name"] == name)

    def common_name_as_list(ds):   # a list where the policy takes one value
        doc(ds, "CertificateRequestPolicy", "barman-cloud")["spec"]["allowed"]["commonName"] = {"values": ["barman-cloud"], "required": True}
    assert "commonName" in errs(common_name_as_list)
    assert "replica" in errs(lambda ds: doc(ds, "Deployment", "harbor-pdp")["spec"].update(replica=1))
    assert "is not of type" in errs(lambda ds: doc(ds, "Deployment", "harbor-pdp")["spec"].update(replicas="one"))
    assert "selector" in errs(lambda ds: doc(ds, "Deployment", "harbor-pdp")["spec"].pop("selector"))
    assert "loadBalancerClas" in errs(lambda ds: doc(ds, "Service", "harbor-pdp")["spec"].update(loadBalancerClas="x"))
    assert "no captured schema" in errs(lambda ds: ds.append(("x.yaml", {"apiVersion": "example.com/v1", "kind": "Widget", "metadata": {"name": "w"}})))
    monkeypatch.setattr(api_schemas, "docs", lambda root=None: iter(real))
    lock = api_schemas.versions()
    monkeypatch.setattr(api_schemas, "versions", lambda root=None: {"charts": {**lock["charts"], "openbao": "9.9.9"}, "flux": lock["flux"]})
    assert "capture again" in " | ".join(api_schemas.check())


def test_no_image_in_the_lab_tree_escapes_its_digest_pin(tmp_path):
    """ADR-0126: tools/pins.py passes the real tree and catches four bypasses: a
    multi-line Helm values override, a .yml manifest, a kustomize images retarget, and a post-renderer newName."""
    import shutil
    from pins import check
    root = Path(__file__).resolve().parent.parent / "gitops" / "lab"
    assert check(root) == []

    def mutated(fn):
        d = tmp_path / fn.__name__
        shutil.copytree(root, d)
        fn(d)
        return check(d)

    def values_override(d):
        f = d / "layer1" / "cert-manager.yaml"
        f.write_text(f.read_text(encoding="utf-8").replace(
            "    crds: {enabled: true}\n", "    crds: {enabled: true}\n    image:\n      repository: ghcr.io/evil/cert-manager-controller\n      tag: latest\n"), encoding="utf-8")

    def yml_manifest(d):
        (d / "layer1" / "evil.yml").write_text("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec:\n  containers:\n    - name: x\n      image: docker.io/evil/x:latest\n", encoding="utf-8")

    def kustomize_retarget(d):
        f = d / "layer1" / "kustomization.yaml"
        f.write_text(f.read_text(encoding="utf-8") + "images:\n  - {name: docker.io/traefik/whoami, newName: docker.io/evil/whoami, digest: \"sha256:" + "0" * 64 + "\"}\n", encoding="utf-8")

    def renderer_newname(d):
        f = d / "layer1" / "cnpg.yaml"
        f.write_text(f.read_text(encoding="utf-8").replace(
            "{name: ghcr.io/cloudnative-pg/cloudnative-pg, digest:", "{name: ghcr.io/cloudnative-pg/cloudnative-pg, newName: ghcr.io/evil/cnpg, digest:"), encoding="utf-8")

    for fn, word in ((values_override, "values override"), (yml_manifest, ".yml"), (kustomize_retarget, "retargets"),
                     (renderer_newname, "retargets")):
        errs = mutated(fn)
        assert any(word in e for e in errs), (fn.__name__, errs)


def test_flux_and_injected_sidecars_run_by_a_verified_digest(tmp_path):
    """ADR-0126: Flux's controllers come from gitops/lab/flux-lock.yaml with digests
    verified against Flux's own signatures; an image a component injects at runtime (the Barman plugin's
    SIDECAR_IMAGE) is pinned by a post-renderer patch; and the list the lab digest check compares against carries both."""
    import shutil
    from pins import check, expected
    root = Path(__file__).resolve().parent.parent / "gitops" / "lab"
    names = {n for n, _ in expected(root)}
    assert {"ghcr.io/fluxcd/source-controller", "ghcr.io/fluxcd/kustomize-controller", "ghcr.io/fluxcd/helm-controller",
            "ghcr.io/fluxcd/notification-controller", "ghcr.io/cloudnative-pg/plugin-barman-cloud-sidecar",
            # Cilium is locked too (gitops/lab/cilium-lock.yaml), its digests verified upstream
            "quay.io/cilium/cilium", "quay.io/cilium/operator-generic", "quay.io/cilium/cilium-envoy"} <= names

    def mutated(name, fn):
        d = tmp_path / name
        shutil.copytree(root, d)
        fn(d)
        return check(d)

    lock = lambda d: d / "flux-lock.yaml"
    cases = {
        "no lock": (lambda d: lock(d).unlink(), "flux-lock.yaml missing"),
        "unverified": (lambda d: lock(d).write_text(lock(d).read_text(encoding="utf-8").replace(
            "upstream_signature: verified}", "upstream_signature: tofu}", 1), encoding="utf-8"), "not verified"),
        "no digest": (lambda d: lock(d).write_text(lock(d).read_text(encoding="utf-8").replace(
            'digest: "sha256:6a66', 'digest: "latest6a66', 1), encoding="utf-8"), "no sha256 digest"),
        "sidecar tag": (lambda d: (d / "backup-plugin" / "helmrelease-barman-cloud.yaml").write_text(
            (d / "backup-plugin" / "helmrelease-barman-cloud.yaml").read_text(encoding="utf-8").replace(
                "plugin-barman-cloud-sidecar@sha256:", "plugin-barman-cloud-sidecar:v0.15.1#"), encoding="utf-8"),
            "SIDECAR_IMAGE without a digest"),
    }
    for name, (fn, word) in cases.items():
        errs = mutated(name.replace(" ", "-"), fn)
        assert any(word in e for e in errs), (name, errs)


FLIP_MODULE = '''
import gc
import pytest
from _pytest.config import Config

cfg = next(o for o in gc.get_objects() if isinstance(o, Config))


class Flip:
    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item, call):
        out = yield
        rep = out.get_result()
        if rep.failed:
            rep.outcome = "passed"


cfg.pluginmanager.register(Flip(), "flip")
'''


def test_the_gate_cannot_be_turned_green_by_the_change_itself(tmp_path):
    """A test module that registers a hook at import time
    flips a failing test to passed in the JUnit file (asserted, so this fixture can fail); the gate's plugin
    (tools/gate_guard.py) still records the raw failure and the injected plugin; the static scan rejects the module;
    a weakened assert ('and' to 'or', 'or True') is caught by the assert guard."""
    import json as _j
    import os as _os
    import subprocess as _sp
    import sys as _sys
    import xml.etree.ElementTree as _ET
    from gate_guard import changed_asserts, scan
    tools = Path(__file__).resolve().parent.parent / "tools"
    t = tmp_path / "tests"
    t.mkdir()
    (t / "test_model.py").write_text("def test_must_fail():\n    assert 1 == 2\n", encoding="utf-8")
    (t / "test_aaa_flip.py").write_text(FLIP_MODULE, encoding="utf-8")
    junit, report = tmp_path / "junit.xml", tmp_path / "guard.json"
    env = dict(_os.environ, GATE_GUARD_REPORT=str(report), PYTHONPATH=str(tools))
    _sp.run([_sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "gate_guard", "-o", "addopts=",
             "-o", "python_files=test_*.py", f"--junitxml={junit}", "tests"], cwd=tmp_path, env=env,
            capture_output=True, text=True)
    case = next(c for c in _ET.parse(junit).getroot().iter("testcase") if c.get("name") == "test_must_fail")
    assert case.find("failure") is None, "the attack no longer fools JUnit: the fixture proves nothing"
    g = _j.loads(report.read_text(encoding="utf-8"))
    assert g["raw"]["tests/test_model.py::test_must_fail"] == "failed"
    assert any("flip" in p for p in g["late_plugins"]), g["late_plugins"]
    found = " ".join(scan([t / "test_aaa_flip.py"]))
    assert "gc" in found and "_pytest" in found and ".pluginmanager" in found
    base = "def test_pins():\n    assert imgs and all(x for x in imgs)\n    assert '@sha256:' in img\n"
    weak = "def test_pins():\n    assert imgs or all(x for x in imgs)\n    assert '@sha256:' in img or True\n"
    assert changed_asserts(base, weak) == ["test_pins: 2 assert(s) changed or removed"]
    assert changed_asserts(base, base + "    assert extra\n") == []


def test_every_deployed_workload_is_a_wired_component():
    """Every workload in
    the lab tree carries a vdh.component annotation, and every annotated component is a sized component (core or
    module), a declared part of one, or a lab fixture with a reason and an end date that has not passed; so nothing runs
    outside the coupling that ties components to risk, interfaces, placement, provenance, lock, lifecycle, resilience and
    observability."""
    import datetime as _dt
    import yaml as _y
    base = Path(__file__).resolve().parent.parent
    sz = _y.safe_load((base / "platform" / "sizes.yaml").read_text(encoding="utf-8"))
    sized = {c["component"] for c in sz["core"] + sz["ci_only"]} | {c["component"] for m in sz["modules"].values() for c in m.get("components", [])}
    parts = {p["name"] for c in sz["core"] for p in c.get("parts", [])}
    fixtures = sz["lab_fixtures"]
    # a published copy is judged at the day it was exported; the private side at today
    stamp = base / "ci" / "exported-on.txt"
    on = _dt.date.fromisoformat(stamp.read_text(encoding="utf-8").strip()) if stamp.exists() else _dt.date.today()
    for name, f in fixtures.items():
        assert f["why"] and _dt.date.fromisoformat(str(f["until"])) > on, (name, "lab fixture expired")
    kinds = {"Deployment", "StatefulSet", "DaemonSet", "HelmRelease", "Job", "CronJob"}
    unannotated, unwired = [], []
    for p in (base / "gitops" / "lab").rglob("*.yaml"):
        for d in _y.safe_load_all(p.read_text(encoding="utf-8")):
            if not isinstance(d, dict) or d.get("kind") not in kinds:
                continue
            comp = ((d.get("metadata") or {}).get("annotations") or {}).get("vdh.component")
            if not comp:
                unannotated.append(f'{p.name}: {d["kind"]} {d["metadata"]["name"]}')
            elif comp not in sized | parts | set(fixtures):
                unwired.append(f"{p.name}: {comp}")
    assert unannotated == [], unannotated
    assert unwired == [], unwired


def test_size_s_renders_the_whole_ring_on_one_node():
    """platform/sizes.yaml names the component that renders size S; in it every patch
    targets a resource that exists in the lab tree, every resource with more than one replica or instance, or with a
    required anti-affinity, is patched to one (so nothing stays Pending on one node), the disruption budget allows the
    drain, and the component is carried to every child Kustomization layer1-config applies."""
    import re as _re
    import yaml as _y
    base = Path(__file__).resolve().parent.parent
    lab = base / "gitops" / "lab"
    comp_path = _y.safe_load((base / "platform" / "sizes.yaml").read_text(encoding="utf-8"))["rendering"]["S"]
    comp = _y.safe_load((base / comp_path / "kustomization.yaml").read_text(encoding="utf-8"))
    assert comp["kind"] == "Component"
    docs = []
    for p in lab.rglob("*.yaml"):
        if "components" in p.parts:
            continue
        for d in _y.safe_load_all(p.read_text(encoding="utf-8")):
            if isinstance(d, dict) and "kind" in d and "metadata" in d:
                docs.append(d)
    def hits(t):
        return [d for d in docs if d["kind"] == t["kind"] and d.get("apiVersion", "").split("/")[0] == t["group"]
                and _re.fullmatch(t.get("name", ".*"), d["metadata"]["name"])]
    patched = set()
    for pt in comp["patches"]:
        found = hits(pt["target"])
        assert found, pt["target"]
        patched |= {(d["kind"], d["metadata"]["name"]) for d in found}
    text = lambda d: _y.safe_dump(d)
    for d in docs:
        spec = d.get("spec") or {}
        many = (spec.get("replicas") or 1) > 1 or (spec.get("instances") or 1) > 1 \
            or ((spec.get("values") or {}).get("server") or {}).get("ha", {}).get("replicas", 1) > 1
        # a required ANTI-affinity blocks on one node; a required co-location (podAffinity, the state backups) cannot
        def anti(o):
            if isinstance(o, dict):
                return any((k == "podAntiAffinity" and "requiredDuringSchedulingIgnoredDuringExecution" in text(v)) or anti(v)
                           for k, v in o.items())
            return isinstance(o, list) and any(anti(x) for x in o)
        hard = anti(d) or "podAntiAffinityType: required" in text(d)
        if many or hard or (d["kind"] == "PodDisruptionBudget" and "minAvailable" in spec):
            assert (d["kind"], d["metadata"]["name"]) in patched, (d["kind"], d["metadata"]["name"], "not reduced at size S")
    # a JSON-patch replace needs its path: every PostgreSQL cluster declares the anti-affinity the S overlay relaxes
    for d in docs:
        if d["kind"] == "Cluster" and d.get("apiVersion", "").startswith("postgresql.cnpg.io"):
            assert "podAntiAffinityType" in ((d["spec"].get("affinity") or {})), (d["metadata"]["name"], "the S patch cannot apply")
    children = {d["metadata"]["name"] for d in docs if d["kind"] == "Kustomization" and d.get("apiVersion", "").startswith("kustomize.toolkit")}
    carry = [pt for pt in comp["patches"] if pt["target"]["kind"] == "Kustomization"][0]
    assert children and all(_re.fullmatch(carry["target"]["name"], c) for c in children), children


def test_the_harbor_releases_only_what_the_label_lets_leave():
    """ADR-0153: the Harbor's label table is the data-max-ring rules of the data-centric pack (one source), an Open
    Cloud Mesh fetch is allowed only for a released share, and the policy's tests prove the refusals."""
    import json as _j
    import shutil
    import subprocess
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    h = root / "gitops/lab/harbor"
    labels = _j.loads((h / "data.json").read_text(encoding="utf-8"))["vdh"]["harbor"]["labels"]
    pack = _y.safe_load((root / "policies/packs/data-centric.yaml").read_text(encoding="utf-8"))["rules"]
    max_ring = {lab: r["parameter"] for r in pack if r["topic"] == "data-max-ring" for lab in r["scope"].get("label", [])}
    assert labels == max_ring and labels["Sensitive"] == "tenant"
    rego = (h / "harbor.rego").read_text(encoding="utf-8")
    assert "content_ok" in rego and "/dav/ocm/" in rego
    opa = shutil.which("opa")
    assert opa, "opa must be installed (CI installs a pinned, checksummed binary)"
    if opa:
        r = subprocess.run([opa, "test", str(h / "harbor.rego"), str(h / "harbor_test.rego"),
                            str(h / "harbor_test_certs.rego"), str(h / "data.json")], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout[-400:]
        assert "test_a_sensitive_share_never_leaves_even_released" in (h / "harbor_test.rego").read_text(encoding="utf-8")


def test_a_harbor_partner_is_bound_to_its_own_ca():
    """The gateway trusts every admitted partner's CA in one bundle, so the PDP binds each
    principal to the CA pinned for it at admission. The gateway hands the PDP the leaf it verified (XFCC Cert, and
    SanitizeSet so a client cannot set the header), the PDP loads harbor-partners, every allow needs the binding, and
    the policy's tests fail if the binding is taken out of either allow rule (mutation check)."""
    import shutil
    import subprocess
    import tempfile
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    h = root / "gitops/lab/harbor"
    ctp = _y.safe_load((h / "clienttrafficpolicy-harbor-mtls.yaml").read_text(encoding="utf-8"))["spec"]
    xfcc = ctp["headers"]["xForwardedClientCert"]
    assert xfcc["mode"] == "SanitizeSet" and "Cert" in xfcc["certDetailsToAdd"]
    auth = _y.safe_load((h / "securitypolicy-harbor-authz.yaml").read_text(encoding="utf-8"))["spec"]["extAuth"]
    assert auth["failOpen"] is False
    assert "x-forwarded-client-cert" in [x.lower() for x in auth.get("headersToExtAuth", ["x-forwarded-client-cert"])]
    pdp = _y.safe_load((h / "deployment-harbor-pdp.yaml").read_text(encoding="utf-8"))["spec"]["template"]["spec"]
    assert "/partners/partners.json" in pdp["containers"][0]["args"]
    assert {"name": "partners", "configMap": {"name": "harbor-partners"}} in pdp["volumes"]
    flux = _y.safe_load((root / "gitops/lab/layer1-config/flux-kustomization-harbor.yaml").read_text(encoding="utf-8"))
    assert flux["spec"]["wait"] is False                     # the PDP waits for the first admission, as Matrix waits
    rego = (h / "harbor.rego").read_text(encoding="utf-8").replace("\r\n", "\n")   # a Windows clone may check out CRLF
    blocks = [b for b in rego.split("\n\n") if b.startswith("allow if {")]
    assert len(blocks) == 1 and all("\tbound\n" in b for b in blocks)   # allow is bound and trusted
    assert "allow" not in "".join(b for b in rego.split("\n\n") if b.startswith("trusted if {"))
    opa = shutil.which("opa")
    assert opa, "opa must be installed (CI installs a pinned, checksummed binary)"
    files = ["harbor_test.rego", "harbor_test_certs.rego", "data.json"]
    with tempfile.TemporaryDirectory() as tmp:
        for b in blocks:
            d = Path(tmp) / f"m{blocks.index(b)}"
            d.mkdir()
            for f in files:
                shutil.copy(h / f, d / f)
            (d / "harbor.rego").write_text(rego.replace(b, b.replace("\tbound\n", "", 1)), encoding="utf-8")
            r = subprocess.run([opa, "test", *[str(d / f) for f in ["harbor.rego", *files]]], capture_output=True, text=True)
            assert r.returncode != 0, f"the rego tests survive an allow rule without the binding:\n{b}"


def test_regenerated_harbor_test_certificates_still_pass_the_policy_tests(tmp_path, monkeypatch):
    """tools/harbor_test_certs.py makes fresh keys every run; certificates it makes now must pass the same rego
    tests (the right CA binds, a forged, expired or unpinned leaf is refused), so a regeneration cannot quietly weaken
    them, and the committed file is not edited by hand."""
    import shutil
    import subprocess
    import harbor_test_certs
    h = Path(__file__).resolve().parent.parent / "gitops/lab/harbor"
    out = tmp_path / "harbor_test_certs.rego"
    monkeypatch.setattr(harbor_test_certs, "OUT", out)
    harbor_test_certs.main()
    text = out.read_text(encoding="utf-8")
    assert text.startswith("# Generated by tools/harbor_test_certs.py") and "PRIVATE KEY" not in text
    committed = (h / "harbor_test_certs.rego").read_text(encoding="utf-8")
    assert committed.startswith("# Generated by tools/harbor_test_certs.py") and "PRIVATE KEY" not in committed
    opa = shutil.which("opa")
    assert opa, "opa must be installed (CI installs a pinned, checksummed binary)"
    r = subprocess.run([opa, "test", str(h / "harbor.rego"), str(h / "harbor_test.rego"), str(out), str(h / "data.json")],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-800:]


def test_the_harbor_intake_shows_a_partner_only_its_own_records_and_bounds_its_writes(tmp_path, monkeypatch):
    """The management intake shows a partner only its own records and bounds its writes: a GET returns only the caller's own records, a request without a verified identity is
    refused, a POST must be a JSON object, and each partner has a rate and a stored-bytes quota per kind that survive a
    restart. The real server class runs on ::1, as on an Isle; each refusal says why and what to do next."""
    import http.client
    import importlib.util
    import json as _j
    import threading
    import yaml as _y
    h = Path(__file__).resolve().parent.parent / "gitops/lab/harbor"
    monkeypatch.setenv("INTAKE_DIR", str(tmp_path))
    monkeypatch.setenv("INTAKE_RATE_PER_MIN", "5")
    monkeypatch.setenv("INTAKE_QUOTA_BYTES", "2000")

    def start():
        spec = importlib.util.spec_from_file_location("intake", h / "intake.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.load()
        srv = mod.Server(("::1", 0), mod.Intake)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return mod, srv

    S, X = "spiffe://s.vdh.test/harbor", "spiffe://x.vdh.test/harbor"

    def call(srv, method, path, who=None, body=None):
        c = http.client.HTTPConnection(f"[::1]:{srv.server_address[1]}", timeout=5)
        hdr = {"content-type": "application/json"}
        if who:
            hdr["x-forwarded-client-cert"] = f'By=spiffe://m.vdh.test/harbor;Hash=ab;Cert="x";URI={who}'
        c.request(method, path, body=body if body is None or isinstance(body, bytes) else _j.dumps(body).encode(), headers=hdr)
        r = c.getresponse()
        return r.status, _j.loads(r.read() or b"{}")

    mod, srv = start()
    try:
        assert call(srv, "POST", "/mgmt/state", S, {"event": "finding"})[0] == 202
        assert call(srv, "POST", "/mgmt/state", X, {"event": "incident", "secret": "x only"})[0] == 202
        st, got = call(srv, "GET", "/mgmt/state", S)
        assert st == 200 and got["partner"] == S and [r["partner"] for r in got["records"]] == [S]
        assert "x only" not in _j.dumps(got)                                   # S never sees X's report
        st, got = call(srv, "GET", "/mgmt/state", X)
        assert [r["body"]["event"] for r in got["records"]] == ["incident"]
        for method in ("GET", "POST"):                                         # no verified identity: refused, with a next step
            st, got = call(srv, method, "/mgmt/state", None, {"event": "x"} if method == "POST" else None)
            assert st == 403 and got.get("next")
        assert call(srv, "POST", "/mgmt/state", S, [1, 2])[0] == 400           # a JSON object only
        assert call(srv, "POST", "/mgmt/nope", S, {"a": 1})[0] == 400
        codes = [call(srv, "POST", "/mgmt/logs", S, {"n": i})[0] for i in range(6)]
        assert codes[:4] == [202] * 4 and codes[4] == 429                      # 5 a minute, the finding counted
        st, got = call(srv, "POST", "/mgmt/logs", X, {"n": 0})
        assert st == 202                                                       # S's flood does not throttle X
        mod.RECENT.clear()
        big = {"pad": "y" * 600}
        codes = [call(srv, "POST", "/mgmt/evidence", X, big)[0] for _ in range(4)]
        assert codes[:2] == [202, 202] and codes[-1] == 507                    # 2000 bytes for X's evidence
        st, got = call(srv, "POST", "/mgmt/evidence", X, big)
        assert st == 507 and "quota" in got["error"] and got["next"]
        assert call(srv, "POST", "/mgmt/evidence", S, big)[0] == 202           # S's quota is its own
    finally:
        srv.shutdown()
        srv.server_close()
    mod, srv = start()                                                         # a restart keeps the quota
    try:
        assert call(srv, "POST", "/mgmt/evidence", X, {"pad": "y" * 600})[0] == 507
        assert call(srv, "POST", "/mgmt/state", X, {"event": "resolved"})[0] == 202
    finally:
        srv.shutdown()
        srv.server_close()
    dep = _y.safe_load((h / "deployment-harbor-intake.yaml").read_text(encoding="utf-8"))["spec"]["template"]["spec"]
    env = {e["name"]: e["value"] for e in dep["containers"][0].get("env", [])}
    assert int(env["INTAKE_RATE_PER_MIN"]) > 0 and int(env["INTAKE_QUOTA_BYTES"]) > 0   # the bounds are stated in the tree


def test_the_harbor_pdp_api_needs_the_evaluators_token_and_allows_only_its_calls(tmp_path):
    """The Harbor PDP's OPA REST API is not open: OPA runs with token authentication and basic
    authorization (authz.rego): the evaluator's token, whose SHA-256 alone is in the PDP, may make the evaluator's six
    calls and nothing else. The rego tests run, then the PDP starts here with the Deployment's own arguments and files
    and is called over HTTP, so the flags are proven to take effect, not only the policy."""
    import hashlib
    import json as _j
    import shutil
    import socket
    import subprocess
    import time
    import urllib.error
    import urllib.request
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    h = root / "gitops/lab/harbor"
    opa = shutil.which("opa")
    assert opa, "opa must be installed (CI installs a pinned, checksummed binary)"
    r = subprocess.run([opa, "test", str(h / "authz.rego"), str(h / "authz_test.rego")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-800:]
    pdp = _y.safe_load((h / "deployment-harbor-pdp.yaml").read_text(encoding="utf-8"))["spec"]["template"]["spec"]
    args = pdp["containers"][0]["args"]
    assert "--authentication=token" in args and "--authorization=basic" in args and "/policy/authz.rego" in args
    assert {"name": "api", "secret": {"secretName": "harbor-pdp-api"}} in pdp["volumes"]
    kz = _y.safe_load((h / "kustomization.yaml").read_text(encoding="utf-8"))
    assert "authz.rego" in [g for g in kz["configMapGenerator"] if g["name"] == "harbor-policy"][0]["files"]
    token = "lab-" + hashlib.sha256(str(tmp_path).encode()).hexdigest()[:24]
    (tmp_path / "partners.json").write_text(_j.dumps({"vdh": {"harbor": {"partner_cas": {}}}}), encoding="utf-8")
    (tmp_path / "api.json").write_text(_j.dumps({"vdh": {"harbor_api": {"token_sha256": hashlib.sha256(token.encode()).hexdigest()}}}), encoding="utf-8")

    held = [socket.socket(), socket.socket()]                 # both reserved at once, so they differ
    for s in held:
        s.bind(("127.0.0.1", 0))
    port, diag = (s.getsockname()[1] for s in held)
    for s in held:
        s.close()
    local = {"/partners/partners.json": tmp_path / "partners.json", "/api/api.json": tmp_path / "api.json"}
    run = []
    for a in args:
        if a.startswith("--addr="):
            a = f"--addr=127.0.0.1:{port}"
        elif a.startswith("--diagnostic-addr="):
            a = f"--diagnostic-addr=127.0.0.1:{diag}"
        elif a.startswith("--config-file="):
            continue                                           # the Envoy plugin's config: not this API
        elif a.startswith("/policy/"):
            a = str(h / a.split("/")[-1])
        elif a in local:
            a = str(local[a])
        run.append(a)
    log = open(tmp_path / "opa.log", "w", encoding="utf-8")       # a pipe nobody reads would fill and stall OPA
    proc = subprocess.Popen([opa, *run], stdout=log, stderr=subprocess.STDOUT)

    def call(method, path, who=None, body=None, p=port):
        hdr = {"content-type": "application/json"}
        if who:
            hdr["authorization"] = f"Bearer {who}"
        req = urllib.request.Request(f"http://127.0.0.1:{p}{path}", method=method, headers=hdr,
                                     data=None if body is None else _j.dumps(body).encode())
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code
        except ConnectionResetError:          # OPA refuses before reading the body and closes; Windows may reset
            return "dropped"                  # the client before it reads the 401 (checked against OPA's log below)

    try:
        for _ in range(150):                                    # both listeners up before anything is judged
            try:
                if call("GET", "/health", p=diag) == 200 and call("GET", "/health") == 200:
                    break
            except OSError:
                pass
            assert proc.poll() is None, (tmp_path / "opa.log").read_text(encoding="utf-8")[-800:]
            time.sleep(0.1)
        assert call("GET", "/health", p=diag) == 200                   # the readiness probe needs no token
        now = {"spiffe://s.vdh.test/harbor": {"state": "member", "band": "medium", "valid_until": "2200-01-01T00:00:00Z"}}
        for who in (None, "guess", hashlib.sha256(token.encode()).hexdigest()):   # no token, a wrong one, the hash itself
            assert call("PUT", "/v1/data/vdh/harbor/partners", who, now) in (401, "dropped"), who
        assert call("PUT", "/v1/data/vdh/harbor/partners", token, now) == 204
        assert call("PUT", "/v1/data/vdh/harbor/releases", token, {}) == 204
        assert call("POST", "/v1/data/vdh/harbor/allow", token, {"input": {}}) == 200
        refused = [("GET", "/v1/data/vdh/harbor/partners", token, None),     # the token cannot read data back
                   ("GET", "/v1/data/vdh/harbor_api", token, None),
                   ("PUT", "/v1/policies/x", token, {}),                     # nor change a policy
                   ("PUT", "/v1/data/vdh/harbor/partner_cas", token, {}),    # nor re-pin a partner's CA
                   ("GET", "/v1/policies", None, None)]
        for m, path, who, body in refused:
            assert call(m, path, who, body) in (401, "dropped"), (m, path)
        assert call("POST", "/v1/data/vdh/harbor/allow", token, {"input": {}}) == 200   # and the server still answers
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        log.close()
    sent = {}
    for line in (tmp_path / "opa.log").read_text(encoding="utf-8").splitlines():
        if '"Sent response."' in line:
            e = _j.loads(line)
            sent.setdefault((e["req_method"], e["req_path"]), set()).add(e["resp_status"])
    for m, path, _, _ in refused:
        assert sent.get((m, path)) == {401}, (m, path, sent.get((m, path)))     # what OPA itself answered
    assert sent.get(("PUT", "/v1/data/vdh/harbor/partners")) == {401, 204}     # three refused, the evaluator's accepted


def test_every_helm_release_retries_a_failed_install_and_upgrade():
    """A HelmRelease without remediation stays Stalled after one failed install or upgrade (a failed hook, say), and the
    layers behind it stay not ready until a person resets it. Every
    HelmRelease retries a failed install and upgrade."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    seen = 0
    for f in (root / "gitops/lab").rglob("*.yaml"):
        if "components" in f.parts:
            continue
        for d in _y.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(d, dict) and d.get("kind") == "HelmRelease":
                seen += 1
                for k in ("install", "upgrade"):
                    assert ((d["spec"].get(k) or {}).get("remediation") or {}).get("retries", 0) >= 1, (f.name, k)
    assert seen


def test_every_database_that_holds_data_is_backed_up_on_a_schedule():
    """Every CloudNativePG cluster outside vdh-test archives WAL through the Barman Cloud plugin
    to an ObjectStore in its own namespace and has a ScheduledBackup; Garage admits each such namespace's database
    instances on its S3 port only."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent / "gitops/lab"
    docs = [(f, d) for f in root.rglob("*.yaml") for d in _y.safe_load_all(f.read_text(encoding="utf-8")) if isinstance(d, dict)]
    clusters = [d for _, d in docs if d.get("kind") == "Cluster" and d.get("apiVersion", "").startswith("postgresql.cnpg.io")
                and d["metadata"].get("namespace") not in ("vdh-test", None)]
    assert len(clusters) >= 3
    stores = {(d["metadata"]["namespace"], d["metadata"]["name"]) for _, d in docs if d.get("kind") == "ObjectStore"}
    sched = {(d["metadata"]["namespace"], d["spec"]["cluster"]["name"]) for _, d in docs if d.get("kind") == "ScheduledBackup"}
    seg = (root / "segmentation/cnp-vdh-backup.yaml").read_text(encoding="utf-8")
    for c in clusters:
        ns, name = c["metadata"]["namespace"], c["metadata"]["name"]
        plug = [p for p in c["spec"].get("plugins", []) if p["name"] == "barman-cloud.cloudnative-pg.io"]
        assert plug and plug[0].get("isWALArchiver"), name
        assert (ns, plug[0]["parameters"]["barmanObjectName"]) in stores, name
        assert (ns, name) in sched, name
        assert f"k8s:io.kubernetes.pod.namespace: {ns}}}, matchExpressions: [{{key: cnpg.io/cluster" in seg, ns
    # the backups leave the node by a job that reads its targets only from the site's Secret (layers are data)
    job = _y.safe_load((root / "backup/cronjob-offsite-backup.yaml").read_text(encoding="utf-8"))
    pod = job["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    assert job["spec"]["concurrencyPolicy"] == "Forbid" and pod["automountServiceAccountToken"] is False
    assert {"name": "targets", "secret": {"secretName": "offsite-targets", "defaultMode": 0o440, "optional": False}} in pod["volumes"]
    script = pod["containers"][0]["args"][0]
    assert "--password-file /targets/restic.password" in script and "RESTIC_PASSWORD" not in script   # never in argv or env
    assert "StrictHostKeyChecking=yes" in script


def test_the_forge_reaches_only_the_ring_and_mirrors_nothing():
    """The forge has a platform-owned egress floor in its own unit (resolver, the ring's gateway,
    the event store's webhook receiver, its own namespace; no CIDR, entity or FQDN), its database instances alone reach
    the API, and Forgejo's mirrors and migrations are off. Pharos may scrape the Harbor gateway's metrics."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    forge = root / "gitops/lab/forge"
    assert "cnp-egress-floor.yaml" in (forge / "kustomization.yaml").read_text(encoding="utf-8")
    floor = _y.safe_load((forge / "cnp-egress-floor.yaml").read_text(encoding="utf-8"))
    db = _y.safe_load((forge / "cnp-database-to-api.yaml").read_text(encoding="utf-8"))
    assert "cnp-database-to-api.yaml" in (forge / "kustomization.yaml").read_text(encoding="utf-8")
    assert floor["metadata"] == {"name": "egress-floor", "namespace": "vdh-forge"} and floor["spec"]["endpointSelector"] == {}
    for rule in floor["spec"]["egress"]:
        assert set(rule) <= {"toEndpoints", "toPorts"}, rule
        ns = {e["matchLabels"]["k8s:io.kubernetes.pod.namespace"] for e in rule["toEndpoints"]}
        assert ns <= {"kube-system", "envoy-gateway-system", "vdh-telemetry", "vdh-backup", "vdh-forge"}, ns
        if "vdh-backup" in ns:   # only Garage's S3 port, for the database's backups
            assert rule["toPorts"] == [{"ports": [{"port": "3900", "protocol": "TCP"}]}]
    assert db["spec"]["egress"] == [{"toEntities": ["kube-apiserver"]}]
    env = {e["name"]: e.get("value") for e in _y.safe_load((forge / "deployment-forgejo.yaml").read_text(encoding="utf-8"))["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["GITEA__mirror__ENABLED"] == "false" and env["GITEA__repository__DISABLE_MIGRATIONS"] == "true"
    # the Harbor's proxy runs in envoy-gateway-system behind its own Cilium policy
    cnp = _y.safe_load((root / "gitops/lab/harbor/ciliumnetworkpolicy-harbor-from-ring-front.yaml").read_text(encoding="utf-8"))
    assert {"fromEndpoints": [{"matchLabels": {"k8s:io.kubernetes.pod.namespace": "vdh-pharos", "app": "prometheus"}}],
            "toPorts": [{"ports": [{"port": "19001", "protocol": "TCP"}]}]} in cnp["spec"]["ingress"]


def test_future_dated_or_rolled_back_time_never_keeps_an_input_fresh():
    """ADR-0126: a signal or a federated light dated beyond the allowed clock skew
    (policies/time-gating.yaml clock_skew_s) is refused instead of staying fresh forever; naive and aware timestamps mix
    without crashing (both read as UTC); with a watermark a clock set back does not make old signals young again."""
    from datetime import timedelta as td
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from adaptive import _fresh, band, load as aload
    from clock import skew
    from federate import aggregate, sign
    from data_provenance import load, reader_ring
    c = aload()
    f = lambda v, at=NOW - td(minutes=1): {"value": v, "at": at}
    base = {"role": f("analyst"), "persona_status": f("normal"), "device_posture": f("ok"), "network": f("enterprise"),
            "location": f("allowed"), "time_of_day": f("inside"), "environment": f("green"), "world_state": f("normal"), "behaviour": f("none")}
    assert band(c, base, NOW)["band"] == "green"
    ahead = f("normal", NOW + td(days=365))
    assert not _fresh(ahead, 15, NOW + td(days=300))                      # it never ages, so it is never fresh
    assert band(c, {**base, "persona_status": ahead}, NOW)["band"] != "green"
    assert _fresh(f("normal", NOW + td(seconds=30)), 15, NOW)            # within the skew
    naive = {**base, "persona_status": f("normal", NOW.replace(tzinfo=None) - td(minutes=1))}
    assert band(c, naive, NOW)["band"] == "green"                         # naive and aware mix without TypeError
    # a clock set back 30 minutes below the evaluator's watermark: signals from before the watermark stay stale
    old = {k: {**v, "at": NOW - td(minutes=30, seconds=30)} for k, v in base.items()}
    assert band(c, old, NOW - td(minutes=30))["band"] == "green"         # no watermark given: the band trusts the clock
    assert band(c, old, NOW - td(minutes=30), watermark=NOW)["band"] != "green"
    # a federated light 90 s ahead (beyond the 60 s skew) is RED
    assert skew() == td(seconds=60)
    k = Ed25519PrivateKey.generate()
    st = {"child": "site-a", "audience": "region-1", "seq": 1, "overall": "GREEN", "evaluated_at": (NOW + td(seconds=90)).isoformat()}
    r = aggregate({"site-a": {"status": st, "signature": sign(k, st)}}, {"site-a": k.public_key()}, {"site-a": td(hours=4)},
                  "GREEN", NOW, parent="region-1", seen={})
    assert r["overall"] == "RED" and "future" in r["children"]["site-a"]["flags"][0]
    # a device attestation dated ahead of the clock does not put a reader inside the site; mixed time zones do not crash
    d = load()
    dev = {"enrolled": "active", "overlay_site": "edge-1", "overlay_only": True, "managed": True}
    assert reader_ring(d, "edge-1", {"device": dev | {"attested_at": "2026-10-10T10:30:00Z"}}, "2026-10-10T10:00:00") != "site"
    assert reader_ring(d, "edge-1", {"device": dev | {"attested_at": "2026-10-10T09:30:00Z"}}, "2026-10-10T10:00:00") == "site"


def test_stale_suspension_stays_black_until_a_fresh_reinstatement():
    """ADR-0126: a suspension that goes stale (signal bus cut) no longer decays from black to amber and
    lets Internal through; sticky deny rules keep their band until a fresh contrary value replaces the signal."""
    from datetime import timedelta as td
    from adaptive import band, decide, load as aload
    c = aload()
    f = lambda v, age=td(minutes=1): {"value": v, "at": NOW - age}
    base = {"role": f("analyst"), "device_posture": f("ok"), "network": f("enterprise"), "location": f("allowed"),
            "time_of_day": f("inside"), "environment": f("green"), "world_state": f("normal"), "behaviour": f("none")}
    for age in (td(minutes=16), td(hours=24)):
        b = band(c, {**base, "persona_status": f("suspended", age)}, NOW)
        assert b["band"] == "black" and "PERSONA_SUSPENDED" in b["reasons"], (age, b)
        assert decide(c, "Internal", b)["allow"] is False
    stale_fail = band(c, {**base, "persona_status": f("normal"), "device_posture": f("failed", td(hours=2))}, NOW)
    assert stale_fail["band"] == "red" and not decide(c, "Internal", stale_fail)["allow"]
    assert band(c, {**base, "persona_status": f("normal")}, NOW)["band"] == "green"      # a fresh reinstatement
    assert all(r.get("sticky") for r in c["hard_rules"])


def test_federated_light_refuses_replayed_or_misaddressed_reports():
    """ADR-0126: a signed light carries child, audience and a monotonic sequence; the parent keeps the
    last accepted sequence per child, so a captured GREEN replayed over a current RED, a report addressed to another
    parent or claiming another child, or one without a sequence is RED. The same latest report again is re-evaluated."""
    from datetime import timedelta as td
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from federate import aggregate, sign
    k = Ed25519PrivateKey.generate()

    def rep(overall, hours_ago, seq, audience="region-1", child="site-a"):
        st = {"child": child, "audience": audience, "seq": seq, "overall": overall,
              "evaluated_at": (NOW - td(hours=hours_ago)).isoformat()}
        return {"status": st, "signature": sign(k, st)}
    seen: dict = {}
    agg = lambda r: aggregate({"site-a": r}, {"site-a": k.public_key()}, {"site-a": td(hours=4)}, "GREEN", NOW,
                              parent="region-1", seen=seen)
    old_green, new_red = rep("GREEN", 3.5, 4), rep("RED", 0.1, 5)
    assert agg(old_green)["overall"] == "GREEN"
    assert agg(new_red)["overall"] == "RED" and seen["site-a"]["seq"] == 5
    replay = agg(old_green)
    assert replay["overall"] == "RED" and "replay" in replay["children"]["site-a"]["flags"][0]
    assert agg(new_red)["overall"] == "RED" and seen["site-a"]["seq"] == 5             # same report: re-evaluated
    assert agg(rep("GREEN", 0.05, 5))["overall"] == "RED"                               # a different report, same seq
    assert agg(rep("GREEN", 0.05, 6, audience="region-2"))["overall"] == "RED"          # addressed to another parent
    assert agg(rep("GREEN", 0.05, 6, child="site-b"))["overall"] == "RED"               # claims another child
    no_seq = {kk: v for kk, v in rep("GREEN", 0.05, 6)["status"].items() if kk != "seq"}
    assert agg({"status": no_seq, "signature": sign(k, no_seq)})["overall"] == "RED"
    assert agg(rep("GREEN", 0.05, 6))["overall"] == "GREEN" and seen["site-a"]["seq"] == 6


def test_site_relation_honours_the_callers_date():
    """ADR-0126: an expired site-ring membership puts the PoP outside its parent's site ring on the
    caller's date; site_relation() takes that date instead of the frozen default, and place() and spin_down() pass it."""
    from data_logistics import place, policy, site_relation, spin_down
    from data_provenance import load
    d, pl = load(), policy()
    args = ("case-files-index", "edge-1", "pop-17", "case-officers", "case-handling")
    assert place(d, pl, *args, today="2026-10-10")["allowed"]
    late = place(d, pl, *args, today="2026-12-01")                                    # membership lapsed 2026-11-09
    assert not late["allowed"] and "outside" in late["reason"]
    assert site_relation(pl, "edge-1", "pop-17", "2026-10-10") == "site"
    assert site_relation(pl, "edge-1", "pop-17", "2026-12-01") == "tenant"
    held = [{"unit": "u1", "product": "case-files-index", "origin": "originated", "home": "edge-1"}]
    assert spin_down(d, pl, "pop-17", held, today="2026-10-10")["steps"][0]["action"] == "drain"
    assert spin_down(d, pl, "pop-17", held, today="2026-12-01")["steps"][0]["action"].startswith("carrier-return")


def test_reader_ring_needs_device_evidence_and_an_explicit_clock():
    """ADR-0126: a bare `site` claim no longer grants the site ring (where Restricted data lives);
    only the attested, enrolled, managed device on the site overlay does, judged at an explicit `now`: there is no
    frozen default clock under which an old attestation stays fresh."""
    import pytest as _pytest
    from data_provenance import load, reader_ring
    d = load()
    assert reader_ring(d, "edge-1", {"site": "edge-1"}, "2026-10-10T10:00:00") == "federation"
    assert reader_ring(d, "edge-1", {"site": "edge-1", "tenant_member": True}, "2026-10-10T10:00:00") == "tenant"
    dev = {"attested_at": "2026-10-10T09:30:00", "enrolled": "active", "overlay_site": "edge-1", "overlay_only": True, "managed": True}
    assert reader_ring(d, "edge-1", {"device": dev}, "2026-10-10T10:00:00") == "site"
    assert reader_ring(d, "edge-1", {"device": dev}, "2027-01-01T00:00:00") == "federation"
    with _pytest.raises(TypeError):
        reader_ring(d, "edge-1", {"device": dev})


def test_absent_band_is_never_green(tmp_path):
    """ADR-0126: a request or policy context without a band decides as the strictest band (black),
    in route(), in the Python engine and in the Rego evaluator alike; dropping a field never loosens. A request made
    on someone's behalf needs that principal's band too."""
    from datetime import date as _d
    from data_provenance import load, route, source_envelope
    from policy_compile import build, evaluate
    from policy_engine import effective, load as pload
    d = load()
    te = source_envelope(d, "sensor-telemetry")
    rel = {"kind": "release", "target_ring": "tenant", "purpose": "operations"}
    calm = {"band": "green", "site_band": "green"}
    assert route(d, te, rel | calm)["decision"] == "needs-approval"
    assert route(d, te, rel)["decision"] == "refused"
    assert route(d, te, rel | {"band": "green"})["decision"] == "refused"                 # site band dropped
    assert route(d, te, rel | {"site_band": "green"})["decision"] == "refused"            # requester band dropped
    assert route(d, te, rel | calm | {"site_band": "purple"})["decision"] == "refused"    # an unknown band is black
    assert route(d, te, rel | calm | {"on_behalf_of": "site-ops-owner"})["decision"] == "refused"
    assert route(d, te, rel | calm | {"on_behalf_of": "site-ops-owner", "on_behalf_band": "green"})["decision"] == "needs-approval"
    _, rules = pload()
    day = _d(2026, 10, 10)
    none = effective(rules, {"trust": "low"}, day)["session-lifetime"]
    assert (none["parameter"], none["mode"]) == ("0", "enforce")
    assert effective(rules, {"trust": "low", "band": "green"}, day)["session-lifetime"]["parameter"] == "15m"
    b = build(tmp_path / "bundle")
    opa = evaluate(b, {"day": "2026-10-10", "trust": "low"})["session-lifetime"]
    assert (opa["parameter"], opa["mode"]) == ("0", "enforce")

def test_proof_bundles_refuse_future_dated_heads_and_registers_and_never_crash_on_time():
    """ADR-0126, proof-bundle half: a tree head or key register dated beyond the allowed skew is
    refused (it never ages), a clock behind the last head seen is refused, and naive or malformed times fail closed
    instead of raising."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from data_provenance import Store, derive, load, source_envelope
    from provenance_bundle import make_bundle, verify_bundle
    from provenance_log import Log, checkpoint
    d = load()
    k = {n: Ed25519PrivateKey.generate() for n in ("sensor", "work", "vb", "lb")}
    te = source_envelope(d, "sensor-telemetry", keys={"site-sensors": k["sensor"]})
    log_b = Log("pop-b")
    store_b = Store(log_b)
    store_b.put(te, log_b.append(te["digest"]))
    env = derive(d, [te], "pop-b-transform", "transform", at="2026-10-10T06:00:00Z", key=k["work"])
    store_b.put(env, log_b.append(env["digest"]))
    cp = checkpoint(k["vb"], "pop-b-verifier", env["digest"], len(log_b.leaves))
    register = {"site-sensors": k["sensor"].public_key(),
                "pop-b-transform": {"key": k["work"].public_key(), "not_before": "2026-10-10T05:00:00Z", "not_after": "2026-10-10T07:00:00Z"}}
    signers, log_keys = {"pop-b-verifier": k["vb"].public_key()}, {"pop-b": k["lb"].public_key()}
    now = "2026-10-10T08:00:00Z"
    ok = make_bundle(store_b, env["digest"], [cp], log_b, log_b.sth(k["lb"], "2026-10-10T07:30:00Z"))
    assert verify_bundle(d, ok, register, signers, log_keys, now=now) == []
    ahead = make_bundle(store_b, env["digest"], [cp], log_b, log_b.sth(k["lb"], "2030-01-01T00:00:00Z"))
    assert "future" in verify_bundle(d, ahead, register, signers, log_keys, now=now)[0]
    assert "future" in verify_bundle(d, ok, register, signers, log_keys, now=now, register_issued="2099-01-01T00:00:00Z")[0]
    assert "rollback" in verify_bundle(d, ok, register, signers, log_keys, now=now,
                                       last_seen={"log": "other", "size": 1, "root": "00" * 32, "ts": "2026-10-11T00:00:00Z"})[0]
    assert verify_bundle(d, ok, register, signers, log_keys, now="2026-10-10T08:00:00", register_issued="2026-10-10T07:00:00Z") == []
    assert "cannot be read" in verify_bundle(d, ok, register, signers, log_keys, now="yesterday")[0]


def test_the_harbor_keeps_coordination_open_and_closes_data_when_trust_falls():
    """ADR-0151: telephony and management stay open while a partner is restricted or suspended (coordination and the
    evidence that re-evaluates it); the data plane needs member or watch at band medium; withdrawn closes everything;
    an unreported partner gets management only. Every state is an FTEF 0.1 ladder state."""
    import json as _json
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    h = _y.safe_load((root / "policies/federation.yaml").read_text(encoding="utf-8"))["harbor"]
    ladder = _json.loads((root / "frameworks/ftef/0.1/policy-defaults.json").read_text(encoding="utf-8"))["states"]
    bands = ["none", "low", "medium", "high"]
    c = h["classes"]
    assert set(c) == {"management", "telephony", "data-plane"}
    for name, rule in c.items():
        assert set(rule["states"]) <= set(ladder) and "withdrawn" not in rule["states"], name
        assert rule["min_band"] in bands, name

    def open_(cls, state, band):
        return state in c[cls]["states"] and bands.index(band) >= bands.index(c[cls]["min_band"])
    for state in ("restricted", "suspended"):
        assert open_("telephony", state, "none") and open_("management", state, "none") and not open_("data-plane", state, ladder[state]["cap"])
    assert open_("data-plane", "member", "medium") and not open_("data-plane", "member", "low") and open_("data-plane", "watch", "medium")
    assert [k for k, v in c.items() if v["unreported"]] == ["management"]
    assert h["report_valid_minutes"] <= 5


def test_recovery_needs_two_people_and_follows_nist_methods():
    """ADR-0156 amendment 1: recovery uses only NIST SP 800-63B-4 methods, in order; two people besides the subject;
    the helpdesk never handles a credential; administrators only by repeated proofing; every recovery is visible."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent
    op = _y.safe_load((root / "platform" / "identity.yaml").read_text(encoding="utf-8"))["accounts"]["operations"]
    rec = op["recovery"]
    assert rec["order"][0] == "second passkey" and rec["order"][-1] == "repeated identity proofing"
    assert "64 random bits" in rec["saved_code"] and "used once" in rec["saved_code"]
    assert "OPA refuses one person in both roles" in rec["two_people"]
    assert "never sets, resets or reads a credential" in rec["helpdesk"]
    assert "10 minutes" in rec["enrolment_link"] and "ADR-0055" in rec["enrolment_link"]
    assert {"revoke every session and refresh token", "notify every address on file"} <= set(rec["after"])
    assert "repeated proofing" in rec["high_privilege"]
    assert "recover an administrator" in op["delegated_admin"]["may_not"]
    assert any("without a second person" in x for x in op["pharos"])


def test_the_ring_front_rolls_when_its_configuration_changes():
    """The ring front (Envoy, static configuration) reads its ConfigMap only at start; a new name in it does
    nothing until the DaemonSet restarts. The pod template carries the configuration's hash, so a change
    to the ConfigMap without the new hash fails here, and with it Flux rolls the front."""
    import hashlib
    import yaml as _y
    root = Path(__file__).resolve().parent.parent / "gitops/lab/netbird"
    cm = _y.safe_load((root / "configmap-ring-front.yaml").read_text(encoding="utf-8"))
    ds = _y.safe_load((root / "daemonset-ring-front.yaml").read_text(encoding="utf-8"))
    want = hashlib.sha256(cm["data"]["envoy.yaml"].encode()).hexdigest()[:16]
    assert ds["spec"]["template"]["metadata"]["annotations"]["vdh.config-sha256"] == want, "update the hash in daemonset-ring-front.yaml"


def test_a_deployment_with_a_single_writer_volume_is_replaced_not_rolled():
    """A persistent queue on a ReadWriteOnce volume (one file lock) deadlocks during a rolling update: the new pod
    waits for the lock while the old one has lost write access. Any Deployment that mounts a ReadWriteOnce claim is replaced (Recreate), never rolled."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent / "gitops/lab"
    rwo = set()
    for f in root.rglob("*.yaml"):
        for d in _y.safe_load_all(f.read_text(encoding="utf-8")):
            if d and d.get("kind") == "PersistentVolumeClaim" and "ReadWriteOnce" in d["spec"].get("accessModes", []):
                rwo.add((d["metadata"]["namespace"], d["metadata"]["name"]))
    for f in root.rglob("*.yaml"):
        for d in _y.safe_load_all(f.read_text(encoding="utf-8")):
            if not d or d.get("kind") != "Deployment":
                continue
            ns = d["metadata"].get("namespace")
            claims = {v["persistentVolumeClaim"]["claimName"] for v in d["spec"]["template"]["spec"].get("volumes", []) if "persistentVolumeClaim" in v}
            if any((ns, c) in rwo for c in claims):
                assert (d["spec"].get("strategy") or {}).get("type") == "Recreate", (f.name, d["metadata"]["name"])


def test_ai_egress_fails_closed_without_a_provider():
    """ADR-0164 point 3: at design time an external AI route is refused unless a registered provider of the
    ai-egress-gate contract has readiness candidate or better AND scores external forward yes, whatever the caller
    claims about consent and pseudonymisation. No registered provider qualifies by default."""
    import copy as _c
    import yaml
    from datalife import external_ai_egress_providers, route_inference
    ROOT = Path(__file__).resolve().parent.parent
    contracts = yaml.safe_load((ROOT / "catalog" / "contracts.yaml").read_text(encoding="utf-8"))
    external, local = {"kind": "external"}, {"kind": "local", "max_label": "Sensitive"}
    # the registered catalogue: no provider forwards externally, so every external route is refused
    assert external_ai_egress_providers() == [] and external_ai_egress_providers(contracts) == []
    for label in ("Internal", "Sensitive", "Restricted"):
        for consent in (True, False):
            for pseud in (True, False):
                r = route_inference(label, external, consent, pseud)
                assert r["allowed"] is False, (label, consent, pseud)
    assert "ai-egress-gate" in route_inference("Internal", external, True, True)["why"]
    # local routes keep their behaviour
    assert route_inference("Sensitive", local, False, False)["allowed"]
    assert not route_inference("Restricted", local, True, True)["allowed"]

    def with_egress_gate(readiness: str, forward) -> dict:
        c = _c.deepcopy(contracts)
        impl = c["contracts"]["ai-egress-gate"]["implementations"]["ai-egress-gate"]
        impl["readiness"], impl["features"]["external-forward"] = readiness, forward
        return c
    # readiness alone or the feature alone is not enough; a missing contract or feature is no
    assert not route_inference("Internal", external, True, True, with_egress_gate("partial", "yes"))["allowed"]
    assert not route_inference("Internal", external, True, True, with_egress_gate("candidate", "no"))["allowed"]
    assert not route_inference("Internal", external, True, True, with_egress_gate("ready", "partial"))["allowed"]
    assert not route_inference("Internal", external, True, True, {"contracts": {}})["allowed"]
    gone = _c.deepcopy(contracts)
    del gone["contracts"]["ai-egress-gate"]["implementations"]["ai-egress-gate"]["features"]["external-forward"]
    assert not route_inference("Internal", external, True, True, gone)["allowed"]
    # with a provider that forwards externally the earlier rules still hold: consent, pseudonymisation, never Restricted
    for forward in ("yes", True):   # a bare YAML yes reads as True
        ok = with_egress_gate("candidate", forward)
        assert external_ai_egress_providers(ok) == ["ai-egress-gate"]
        assert route_inference("Internal", external, True, True, ok)["allowed"]
        assert not route_inference("Internal", external, False, True, ok)["allowed"]
        assert not route_inference("Internal", external, True, False, ok)["allowed"]
        assert not route_inference("Restricted", external, True, True, ok)["allowed"]


def test_no_control_bytes_in_the_model_sources():
    """A stray backspace byte where a regular expression meant a word boundary (a shell can turn the two characters
    into one) makes a check assert nothing. No source file of the
    model holds a control byte other than tab, newline and carriage return."""
    ROOT = Path(__file__).resolve().parent.parent
    bad = []
    dirs = [d for d in ("tools", "tests", "platform", "governance", "policies", "catalog", "intent", "gitops", "frameworks",
                        "risks") if (ROOT / d).is_dir()]   # a published copy holds fewer folders
    assert {"tools", "tests", "platform", "gitops"} <= set(dirs), dirs   # never vacuous
    for d in dirs:
        for f in (ROOT / d).rglob("*"):
            if f.is_file() and f.suffix in (".py", ".yaml", ".yml", ".md", ".json", ".rego", ".conf", ".sh", ".txt"):
                data = f.read_bytes()
                if any(b < 32 and b not in (9, 10, 13) for b in data):
                    bad.append(str(f.relative_to(ROOT)))
    assert bad == [], bad


def test_the_pdp_loads_every_policy_in_its_bundle():
    """The ring's OPA is started with its policy files by name; a policy in the bundle but not in the ConfigMap or
    the arguments leaves its questions without a decision. Every .rego in the bundle is
    in the ConfigMap and on the command line."""
    import yaml as _y
    root = Path(__file__).resolve().parent.parent / "gitops" / "lab" / "pdp"
    regos = {p.name for p in (root / "bundle").glob("*.rego")}
    kust = (root / "kustomization.yaml").read_text(encoding="utf-8")
    args = " ".join(_y.safe_load((root / "deployment-pdp.yaml").read_text(encoding="utf-8"))["spec"]["template"]["spec"]["containers"][0]["args"])
    assert regos and all(f"bundle/{r}" in kust for r in regos), regos
    assert all(f"/policy/{r}" in args for r in regos), regos


def test_forgejo_is_the_forge_and_a_project_we_contribute_to():
    """ADR-0186: Forgejo, not Gitea, for client instances and edge sites, and a project we contribute to actively."""
    import yaml
    forges = yaml.safe_load((Path(__file__).resolve().parent.parent / "platform" / "gitops.yaml").read_text(encoding="utf-8"))["forges"]
    for tier in ("client-instance", "edge-site"):
        f = forges[tier]
        assert "Forgejo" in f["tool"] and f["upstream"] == "contribute" and f["decided_by"] == "ADR-0186", tier
    assert not any(f["tool"].startswith("Gitea") for f in forges.values()), "Gitea is not a forge of the platform"
    assert "Forgejo" in forges["central"]["tool"]   # the later central forge


