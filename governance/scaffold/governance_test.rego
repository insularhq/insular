package vdh.governance_test

# Tests for vdh.governance. The keys below are THROWAWAY TEST KEYS generated for these tests
# only; they sign nothing outside this file.

import rego.v1

import data.vdh.governance

T0 := 1791763200000000000 # 2026-10-12

T2028 := 1859241600000000000 # 2028-12-01

iat := 1791676800 # 2026-10-11

exp := 1791850000

priv := {
	"ana": {"kty": "EC", "crv": "P-256", "x": "76oQNxhkRx1Gnkw25p9rCknWWiUs_Q72Ot62kD1mtLs", "y": "gRbqe117E6jQOnaf8Ct8W3A6FkguonI9_L2pzXKCzEg", "d": "KVEhDm-quqBHRvkk3q3llA5oDKESIfZermwZeGC4lNc"},
	"bo": {"kty": "EC", "crv": "P-256", "x": "0eRr7Dp_RylNzZXxfA--KXDhUErhQhk8KY1vecgEHKg", "y": "3q6NSXd3qI76e5LB1FnQrMg4w1MKCk8wzVTG9IEP89w", "d": "fxzSuyeLUoyvFVYJH54QWoG6faUHT38PVhtaITVNHm4"},
	"cy": {"kty": "EC", "crv": "P-256", "x": "j1trLK_a4USgxqmGDS57cInAFccyZFKtGnACO3B8wlA", "y": "mk7_mXuUCsGYa1e2Kr581sOPXE_QdJNm97gCb0mP2Bg", "d": "yfqtb0rGEkwqHH5cUmxYUYXKHsDSQn5UumU_zswWWxw"},
	"dee": {"kty": "EC", "crv": "P-256", "x": "jxUyVIrwe_MQC70bBn9O7lBGuQWmJTL68YOCgnRcvkU", "y": "BO2ktEUeGPbJ1LtC2NycQbBlRUzC4ofQm3zcAFyQB8A", "d": "0kj5wr7Io5hhVXuDw8jfeytyEJrnYTXeiLeABKRrRHY"},
	"eve": {"kty": "EC", "crv": "P-256", "x": "JROQAnWkmNbIk6cZAuz8-TZVHg0G6UdIx6ynRigpSsw", "y": "iaoTXwVVvhJXf1j5lPbtdidsShXN33SuSVWhlxwjGso", "d": "aAlaGpxKrgC5_Vf7Xm42t7crtRiAeniGPeD3i-_jfh4"},
	"fay": {"kty": "EC", "crv": "P-256", "x": "LYSgnSu7o_K4Q0r4_ztpghaQo5kO7qaGNLG0arjQ1gM", "y": "_TZU9K41lVZ9eDAktqcNyW5qRxZUk2JWFbu6cm63cEA", "d": "B9dmNJI2WazZf06RSTDO4LsHG6LtGRcX6HyADcNTCP0"},
}

pub(who) := object.remove(priv[who], ["d"])

tok(who, kind, b, i) := io.jwt.encode_sign(
	{"alg": "ES256", "typ": "JWT"},
	{"sub": who, "kind": kind, "req": crypto.sha256(json.marshal(b)), "iat": i, "exp": exp},
	priv[who],
)

drill(since) := {"evidence": "drill", "since": since, "verifier": "chartroom-grader"}

people := {
	"ana": {"roles": ["pki_custodian"], "key": pub("ana"), "competencies": {"key-custody": drill("2026-06-01")}},
	"bo": {"roles": ["pki_custodian"], "key": pub("bo"), "competencies": {"key-custody": {"evidence": "ceremony-rehearsal", "since": "2026-05-01", "verifier": "ana"}}},
	"cy": {"roles": ["owner"], "key": pub("cy"), "competencies": {"risk-acceptance": {"evidence": "peer-review", "since": "2026-04-01", "verifier": "eve"}}},
	"dee": {"roles": ["platform_operator"], "key": pub("dee"), "competencies": {"database-recovery": drill("2026-07-01"), "platform-security": drill("2026-07-01")}},
	"eve": {"roles": ["security_officer"], "key": pub("eve"), "competencies": {"policy-authoring": {"evidence": "peer-review", "since": "2026-03-01", "verifier": "cy"}}},
	"fay": {"roles": ["owner"], "key": pub("fay"), "competencies": {}},
}

tier3 := {
	"Q01": "five-to-ten", "Q02": "gdpr", "Q03": "personal", "Q04": "harm-to-people-or-legal-breach", "Q05": "a-day",
	"Q06": "a-day", "Q07": "connected-ddil-survivable", "Q08": "separate-organisations", "Q09": "extended-with-on-call",
	"Q10": "partners", "Q11": "none", "Q12": "experienced",
}

tier1 := object.union(tier3, {"Q02": "none", "Q03": "internal", "Q04": "inconvenience", "Q10": "internal-only"})

inst(answers, ps) := {"org": "test", "confirmed": true, "answers": answers, "persons": ps}

org := inst(tier3, people)

chain := {"action": "register-signing-chain", "chain": "lab-nonprod"}

rq(b, who, approvers) := {"body": b, "token": tok(who, "request", b, iat), "approvals": [tok(a, "approve", b, iat) | some a in approvers]}

decide(i, r, band) := d if {
	d := governance.decision with data.instance as i with data.signals as {"band": band} with input as {"request": r} with time.now_ns as T0
}

# ---- intake, tiers and errors ----------------------------------------------------------------------------------

test_the_highest_answer_sets_the_tier if {
	governance.tier == {"security": 3, "availability": 2} with data.instance as org with time.now_ns as T0
	governance.tier.security == 1 with data.instance as inst(tier1, people) with time.now_ns as T0
	governance.tier.security == 4 with data.instance as inst(object.union(tier3, {"Q03": "classified"}), people) with time.now_ns as T0
}

test_an_incomplete_or_unconfirmed_instance_is_an_error_and_denies if {
	e := governance.errors with data.instance as inst(object.remove(tier3, ["Q12"]), people) with time.now_ns as T0
	"question Q12 is unanswered or not one of its options" in e
	u := governance.errors with data.instance as object.union(org, {"confirmed": false}) with time.now_ns as T0
	"the instance is not confirmed by its owner" in u
	d := decide(object.union(org, {"confirmed": false}), rq(chain, "ana", ["bo"]), "green")
	not d.allow
}

test_malformed_mandates_fail_closed if {
	bad := [
		{"knob": "security.root_quorum", "lock": "true"},
		{"knob": "security.action_signers", "limit": "3"},
		{"knob": "security.no_such", "limit": 3},
		{"knob": "security.tier", "limit": 5},
		{"knob": "availability.rto_hours"},
	]
	e := governance.errors with data.instance as org with data.mandate as {"rules": bad} with time.now_ns as T0
	count({x | some x in e; startswith(x, "mandate")}) == 5
	d := decide(org, rq(chain, "ana", ["bo"]), "green") with data.mandate as {"rules": bad}
	not d.allow
}

# ---- mandates and tailoring are applied, not only judged -------------------------------------------------------

test_a_mandate_raises_a_tier_and_a_quorum_at_the_pdp if {
	m := {"rules": [{"knob": "availability.tier", "limit": 3}, {"knob": "security.root_quorum", "limit": 3}]}
	governance.tier.availability == 3 with data.instance as org with data.mandate as m with time.now_ns as T0
	d := decide(org, rq(chain, "ana", ["bo"]), "green") with data.mandate as m
	d.quorum == 3
	not d.allow
	"security.root_quorum" in governance.raised_by_mandate with data.instance as org with data.mandate as m with time.now_ns as T0
}

test_tweaks_are_recorded_deviations_or_refused_and_only_accepted_ones_apply if {
	t := [
		{"knob": "availability.restore_test_days", "value": 30},
		{"knob": "availability.rpo_hours", "value": 4},
		{"knob": "security.action_signers", "value": "0"},
		{"knob": "security.root_quorum", "value": 1},
		{"knob": "security.no_such", "value": 1},
		{"knob": "availability.tier", "value": 2.5},
	]
	i := object.union(org, {"tailoring": t})
	v := governance.verdicts with data.instance as i with time.now_ns as T0
	{[x.knob, x.verdict] | some x in v} == {
		["availability.restore_test_days", "record"],
		["availability.rpo_hours", "deviation"],
		["security.action_signers", "refuse"],
		["security.root_quorum", "refuse"],
		["security.no_such", "refuse"],
		["availability.tier", "refuse"],
	}
	s := governance.settings with data.instance as i with time.now_ns as T0
	s.availability.restore_test_days == 30 # the recorded tightening applies
	s.availability.rpo_hours == 1 # the deviation does not, until it is approved
	ok := object.union(i, {"deviations": [{"knob": "availability.rpo_hours", "value": 4, "approved": true, "expires": "2027-01-01"}]})
	s2 := governance.settings with data.instance as ok with time.now_ns as T0
	s2.availability.rpo_hours == 4
	old := object.union(i, {"deviations": [{"knob": "availability.rpo_hours", "value": 4, "approved": true, "expires": "2026-01-01"}]})
	s3 := governance.settings with data.instance as old with time.now_ns as T0
	s3.availability.rpo_hours == 1 # an expired deviation is a lease that ran out
}

test_a_locked_knob_refuses_even_a_tightening_and_an_equal_value_is_recorded if {
	i := object.union(org, {"tailoring": [{"knob": "security.root_quorum", "value": 3}, {"knob": "security.action_signers", "value": 2}]})
	m := {"rules": [{"knob": "security.root_quorum", "lock": true}]}
	v := governance.verdicts with data.instance as i with data.mandate as m with time.now_ns as T0
	{[x.knob, x.verdict] | some x in v} == {["security.root_quorum", "refuse"], ["security.action_signers", "record"]}
}

test_a_tighter_tier_tweak_changes_the_reference_for_other_knobs if {
	i := object.union(org, {"tailoring": [{"knob": "availability.tier", "value": 3}, {"knob": "availability.restore_test_days", "value": 60}]})
	v := governance.verdicts with data.instance as i with time.now_ns as T0
	{[x.knob, x.verdict] | some x in v} == {["availability.tier", "record"], ["availability.restore_test_days", "deviation"]}
}

# ---- capacity, separation and education come from the persons --------------------------------------------------

test_recorded_persons_override_the_answers if {
	one := {"solo": {"roles": ["owner", "release_manager", "pki_custodian", "platform_operator"], "key": pub("ana"), "competencies": {}}}
	i := inst(object.union(tier3, {"Q01": "more-than-ten"}), one)
	governance.path == "solo" with data.instance as i with time.now_ns as T0
	g := governance.gaps with data.instance as i with time.now_ns as T0
	some x in g
	x.for == "intake"
	x.need == "persons"
	some y in g
	y.need == "separation"
	y.roles == ["owner", "release_manager"]
}

test_conflicts_are_compensated_below_the_separation_tier if {
	one := {"solo": {"roles": ["owner", "release_manager"], "key": pub("ana"), "competencies": {}}}
	c := governance.compensations with data.instance as inst(tier1, one) with time.now_ns as T0
	count(c) == 1
	g := governance.gaps with data.instance as inst(tier1, one) with time.now_ns as T0
	not "separation" in {x.need | some x in g}
}

test_education_gaps_are_only_for_the_roles_competencies if {
	g := governance.gaps with data.instance as org with time.now_ns as T0
	{x.need | some x in g; x.axis == "education"; x.person == "dee"} == {"platform-operations", "secrets-management"}
}

test_competency_evidence_is_checked_for_kind_verifier_date_and_revocation if {
	bad := {
		"self": {"roles": ["pki_custodian"], "competencies": {"key-custody": {"evidence": "ceremony-rehearsal", "since": "2026-05-01", "verifier": "self"}}},
		"fake": {"roles": ["pki_custodian"], "competencies": {"key-custody": {"evidence": "drill", "since": "2026-05-01", "verifier": "bo"}}},
		"kind": {"roles": ["pki_custodian"], "competencies": {"key-custody": {"evidence": "certification", "since": "2026-05-01", "verifier": "lf"}}},
		"soon": {"roles": ["pki_custodian"], "competencies": {"key-custody": drill("2027-01-01")}},
		"gone": {"roles": ["pki_custodian"], "competencies": {"key-custody": object.union(drill("2026-05-01"), {"revoked": true})}},
		"good": {"roles": ["pki_custodian"], "competencies": {"key-custody": drill("2026-05-01")}},
	}
	g := governance.gaps with data.instance as inst(tier3, bad) with time.now_ns as T0
	{x.person | some x in g; x.need == "key-custody"} == {"self", "fake", "kind", "soon", "gone"}
}

# ---- governed actions ------------------------------------------------------------------------------------------

test_registering_a_chain_needs_signed_distinct_competent_signers if {
	decide(org, rq(chain, "ana", ["bo"]), "green").allow
	not decide(org, rq(chain, "ana", ["ana"]), "green").allow # the requester counts once
	not decide(org, rq(chain, "ana", ["fay"]), "green").allow # an owner without a valid competency does not count
	not decide(org, rq(chain, "ana", ["dee"]), "green").allow # an operator holds no approving role for a chain
	other := {"action": "register-signing-chain", "chain": "production-root"}
	r := {"body": chain, "token": tok("ana", "request", chain, iat), "approvals": [tok("bo", "approve", other, iat)]}
	not decide(org, r, "green").allow # an approval of another body does not count
}

test_forged_ghost_and_stale_tokens_are_refused if {
	ghost := object.union(people, {"x1": {"roles": ["pki_custodian"], "key": pub("fay"), "competencies": {}}})
	forged := {"body": chain, "token": io.jwt.encode_sign({"alg": "ES256"}, {"sub": "ana", "kind": "request", "req": crypto.sha256(json.marshal(chain)), "iat": iat, "exp": exp}, priv.bo), "approvals": [tok("bo", "approve", chain, iat)]}
	d := decide(org, forged, "green")
	"the request is not signed by an enrolled person, or is stale or for another body" in d.deny
	stale := {"body": chain, "token": tok("ana", "request", chain, iat), "approvals": [tok("bo", "approve", chain, iat)]}
	late := governance.decision with data.instance as org with data.signals as {"band": "green"} with input as {"request": stale} with time.now_ns as T2028
	not late.allow
	unknown := {"body": chain, "token": tok("fay", "request", chain, iat), "approvals": []}
	not decide(ghost, unknown, "green").allow
}

test_the_requester_needs_the_role_and_its_competency if {
	d := decide(org, rq(chain, "cy", ["ana", "bo"]), "green")
	"requester does not hold pki_custodian" in d.deny
	nocomp := object.union(object.remove(people, ["ana"]), {"ana": {"roles": ["pki_custodian"], "key": pub("ana"), "competencies": {}}})
	d2 := decide(inst(tier3, nocomp), rq(chain, "ana", ["bo"]), "green")
	"requester has no valid key-custody competency" in d2.deny
}

test_red_and_black_add_a_signer_unknown_bands_are_black_and_black_blocks_increases if {
	r := decide(org, rq(chain, "ana", ["bo"]), "red")
	r.quorum == 3
	not r.allow
	decide(org, rq(chain, "ana", ["bo", "cy"]), "red").allow
	u := decide(org, rq(chain, "ana", ["bo", "cy"]), "purple")
	u.band == "black"
	"black band: only restore and reduce actions pass" in u.deny
	none := governance.decision with data.instance as org with input as {"request": rq(chain, "ana", ["bo", "cy"])} with time.now_ns as T0
	none.band == "black"
	rot := {"action": "revoke-or-rotate-key", "chain": "lab-nonprod"}
	decide(org, rq(rot, "ana", ["bo", "eve"]), "black").allow
}

test_root_and_action_quorums_differ_where_the_tier_says_so if {
	low := inst(tier1, people)
	rel := {"action": "release-sign", "release": "r1"}
	rm := object.union(people, {"cy": object.union(people.cy, {"roles": ["release_manager"], "competencies": {"release-officer": drill("2026-06-01")}})})
	decide(inst(tier1, rm), rq(rel, "cy", []), "green").allow # tier 1: one signer for an action
	d := decide(low, rq(chain, "ana", []), "green")
	d.quorum == 2 # but two for a root action
	not d.allow
}

test_compensated_mode_needs_an_old_enough_announcement_and_an_open_path if {
	op := {"dee": people.dee}
	res := {"action": "break-glass", "site": "s1"} # min_signers 2: one person needs compensated mode
	early := 1791417600 # 2026-10-08, four days before
	fresh := 1791760000 # less than 24 hours before
	r := object.union(rq(res, "dee", []), {"announcement": tok("dee", "announce", res, early)})
	a := decide(inst(tier1, op), r, "green")
	a.allow
	a.mode == "compensated"
	f := object.union(rq(res, "dee", []), {"announcement": tok("dee", "announce", res, fresh)})
	not decide(inst(tier1, op), f, "green").allow
	not decide(inst(tier3, op), r, "green").allow # separation required: no compensated mode without an exception
}

test_an_exception_opens_compensated_mode_until_it_expires_never_for_increases_in_black if {
	solo := {"ana": people.ana}
	early := 1791417600
	r := object.union(rq(chain, "ana", []), {"announcement": tok("ana", "announce", chain, early)})
	ex := object.union(inst(tier3, solo), {"exceptions": [{"id": "EX-2", "actions": ["register-signing-chain"], "expires": "2027-04-12"}]})
	decide(ex, r, "green").allow
	old := object.union(inst(tier3, solo), {"exceptions": [{"id": "EX-2", "actions": ["register-signing-chain"], "expires": "2026-01-01"}]})
	not decide(old, r, "green").allow
	not decide(ex, r, "black").allow
}

test_a_tweak_that_breaches_a_mandate_is_refused_even_when_it_matches_the_golden_value if {
	i := object.union(org, {"tailoring": [{"knob": "security.action_signers", "value": 2}]})
	m := {"rules": [{"knob": "security.action_signers", "limit": 3}]}
	v := governance.verdicts with data.instance as i with data.mandate as m with time.now_ns as T0
	{x.verdict | some x in v} == {"refuse"}
}

test_a_competency_expires_after_the_tiers_validity_while_its_tokens_are_still_fresh if {
	g := governance.gaps with data.instance as org with time.now_ns as T2028
	"ana" in {x.person | some x in g; x.need == "key-custody"} # drill of 2026-06-01, valid 24 months
	g0 := governance.gaps with data.instance as org with time.now_ns as T0
	not "ana" in {x.person | some x in g0; x.need == "key-custody"}
}

test_an_expired_token_is_refused_at_the_present_time if {
	b := chain
	old := io.jwt.encode_sign({"alg": "ES256"}, {"sub": "ana", "kind": "request", "req": crypto.sha256(json.marshal(b)), "iat": 1791417600, "exp": 1791500000}, priv.ana)
	d := decide(org, {"body": b, "token": old, "approvals": [tok("bo", "approve", b, iat)]}, "green")
	"the request is not signed by an enrolled person, or is stale or for another body" in d.deny
}
