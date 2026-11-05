# vdh.governance: the governance scaffold evaluated by OPA.
#
# DATA (each from its own signed bundle, never from the caller):
#   the scaffold (this directory): intake, tiers, knobs, overlays, golden_paths, competencies, governed_actions
#   data.instance  {org, confirmed, answers, persons, tailoring, deviations, exceptions}   the organisation's bundle
#                  persons: {id: {roles, external?, org?, key (public JWK, ES256), competencies: {id: {evidence, since,
#                  verifier, ref, revoked?}}}}
#   data.mandate   {by, rules: [{knob, limit? | lock?}]}        the parent's bundle, its own root
#   data.signals   {band}                                      the risk engine's signal; missing or unknown is black
# INPUT (per request): request {body: {action, ...}, token, approvals: [...], announcement?}, each a JWT (ES256) signed
#   by a person's enrolled key over the digest of the body, with kind request|approve|announce, iat and exp.
# TIME: time.now_ns(), never the caller's.
#
# profile, gaps, verdicts (record | deviation | refuse) and decision (allow or deny with reasons). Anything malformed is
# an error, and any error denies every decision (fail closed).
package vdh.governance

import rego.v1

default inst := {}

inst := data.instance

answers := object.get(inst, "answers", {})

persons := object.get(inst, "persons", {})

tailoring := object.get(inst, "tailoring", [])

deviations := object.get(inst, "deviations", [])

exceptions := object.get(inst, "exceptions", [])

default mandates := []

mandates := data.mandate.rules

now := time.now_ns()

questions := data.intake.questions

tiers_valid := {1, 2, 3, 4}

# ---- intake ----------------------------------------------------------------------------------------------------

chosen[q] := o if {
	some q, qq in questions
	some o in qq.options
	o.value == object.get(answers, q, null)
}

errors contains sprintf("question %s is unanswered or not one of its options", [q]) if {
	some q, _ in questions
	not chosen[q]
}

errors contains sprintf("answer to an unknown question %s", [q]) if {
	some q, _ in answers
	not questions[q]
}

errors contains "the instance is not confirmed by its owner" if object.get(inst, "confirmed", false) != true

errors contains sprintf("mandate names an unknown knob %v", [m.knob]) if {
	some m in mandates
	not data.knobs[m.knob]
}

errors contains sprintf("mandate on %v has a limit that is not a number", [m.knob]) if {
	some m in mandates
	"limit" in object.keys(m)
	not is_number(m.limit)
}

errors contains sprintf("mandate on %v has a lock that is not true or false", [m.knob]) if {
	some m in mandates
	"lock" in object.keys(m)
	not is_boolean(m.lock)
}

errors contains sprintf("mandate on %v has neither a limit nor a lock", [m.knob]) if {
	some m in mandates
	not "limit" in object.keys(m)
	not "lock" in object.keys(m)
}

errors contains sprintf("mandate tier limit on %v must be one of 1, 2, 3, 4", [m.knob]) if {
	some m in mandates
	data.knobs[m.knob].field == "tier"
	"limit" in object.keys(m)
	not m.limit in tiers_valid
}

errors contains sprintf("knob %v is tailored more than once", [k]) if {
	some t in tailoring
	k := t.knob
	count([x | some x in tailoring; x.knob == k]) > 1
}

overlays contains ov if {
	some _, o in chosen
	some ov in object.get(o, "overlays", [])
}

# high-water mark: the highest answer sets the golden tier
golden_tier[axis] := t if {
	some axis in ["security", "availability"]
	raised := [n | some _, o in chosen; n := object.get(object.get(o, "raises", {}), axis, 0)]
	t := max(array.concat([1], raised))
}

# ---- knobs, tailoring and mandates -----------------------------------------------------------------------------

weaker(dir, v, ref) if {
	dir == "higher"
	v < ref
}

weaker(dir, v, ref) if {
	dir == "lower"
	v > ref
}

locked(k) if {
	some m in mandates
	m.knob == k
	m.lock == true
}

breaches_mandate(k, v) if {
	some m in mandates
	m.knob == k
	is_number(m.limit)
	weaker(data.knobs[k].stricter, v, m.limit)
}

approved_deviation(t) if {
	some d in deviations
	d.knob == t.knob
	d.value == t.value
	d.approved == true
	time.parse_ns("2006-01-02", d.expires) > now
}

judge(t, ref) := "refuse" if {
	not data.knobs[t.knob]
} else := "refuse" if {
	not is_number(t.value)
} else := "refuse" if {
	data.knobs[t.knob].field == "tier"
	not t.value in tiers_valid
} else := "refuse" if {
	locked(t.knob)
} else := "refuse" if {
	breaches_mandate(t.knob, t.value)
} else := "refuse" if {
	weaker(data.knobs[t.knob].stricter, t.value, data.knobs[t.knob].floor)
} else := "deviation" if {
	weaker(data.knobs[t.knob].stricter, t.value, ref)
} else := "record"

accepted("record", _)

accepted("deviation", t) if approved_deviation(t)

tweak(k) := ts[0] if {
	ts := [t | some t in tailoring; t.knob == k]
	count(ts) == 1
}

after_tweak(k, ref) := tweak(k).value if {
	accepted(judge(tweak(k), ref), tweak(k))
} else := ref

clamp(k, v) := max(array.concat([v], [m.limit | some m in mandates; m.knob == k; is_number(m.limit)])) if {
	data.knobs[k].stricter == "higher"
} else := min(array.concat([v], [m.limit | some m in mandates; m.knob == k; is_number(m.limit)]))

# the effective tier: the golden tier, an accepted tweak, then raised by a mandate limit
tier[axis] := t if {
	some axis, g in golden_tier
	k := concat(".", [axis, "tier"])
	t := clamp(k, after_tweak(k, g))
	t in tiers_valid
}

base[axis] := data.tiers[axis][format_int(t, 10)].settings if some axis, t in tier

knob_value(k) := clamp(k, after_tweak(k, base[kn.axis][kn.field])) if {
	kn := data.knobs[k]
	kn.field != "tier"
}

raised_by_mandate contains k if {
	some k, kn in data.knobs
	kn.field != "tier"
	knob_value(k) != after_tweak(k, base[kn.axis][kn.field])
}

overlay_settings[axis] := object.union_n([object.get(data.overlays[o], axis, {}) | some o in overlays]) if {
	some axis in ["security", "availability", "support"]
}

settings[axis] := s if {
	some axis, t in tier
	tuned := {kn.field: knob_value(k) | some k, kn in data.knobs; kn.axis == axis; kn.field != "tier"}
	s := object.union_n([base[axis], overlay_settings[axis], tuned, {"tier": t}])
}

verdicts contains v if {
	some t in tailoring
	kn := data.knobs[t.knob]
	kn.field == "tier"
	ref := golden_tier[kn.axis]
	v := {"knob": t.knob, "value": t.value, "verdict": judge(t, ref), "axis": kn.axis, "reference": ref}
}

verdicts contains v if {
	some t in tailoring
	kn := data.knobs[t.knob]
	kn.field != "tier"
	ref := base[kn.axis][kn.field]
	v := {"knob": t.knob, "value": t.value, "verdict": judge(t, ref), "axis": kn.axis, "reference": ref}
}

verdicts contains v if {
	some t in tailoring
	not data.knobs[t.knob]
	v := {"knob": t.knob, "value": t.value, "verdict": "refuse", "axis": "unknown", "reference": null}
}

# ---- capacity, path and gaps -----------------------------------------------------------------------------------

recorded if count(persons) > 0

forecast := {k: v | some _, o in chosen; some k, v in object.get(o, "provides", {})}

holders(role) := {p | some p, x in persons; role in x.roles}

critical_roles := ["platform_operator", "pki_custodian", "release_manager"]

actual := {
	"persons": count({p | some p, x in persons; not object.get(x, "external", false)}),
	"custodians": count(holders("pki_custodian")),
	"custodian_orgs": count({object.get(persons[p], "org", "self") | some p in holders("pki_custodian")}),
	"bus_factor": min([count(holders(r)) | some r in critical_roles]),
	"coverage": object.get(forecast, "coverage", 0),
}

capacity := actual if recorded

else := object.union(forecast, {"bus_factor": object.get(forecast, "persons", 0)})

path := name if {
	n := object.get(capacity, "persons", 1)
	best := max([p.min_persons | some _, p in data.golden_paths.paths; p.min_persons <= n])
	some name, p in data.golden_paths.paths
	p.min_persons == best
}

role_sets := {p: x.roles | some p, x in persons} if recorded

else := data.golden_paths.paths[path].assignment

conflicts contains c if {
	some p, roles in role_sets
	some pair in data.golden_paths.sod
	pair.roles[0] in roles
	pair.roles[1] in roles
	c := {"person": p, "roles": pair.roles, "compensation": pair.compensation}
}

compensations contains c if {
	settings.security.separation == "compensated"
	some c in conflicts
}

requires[axis] := data.tiers[axis][format_int(t, 10)].requires if some axis, t in tier

need_axis := {"coverage": "support", "persons": "support", "bus_factor": "support", "custodians": "security", "custodian_orgs": "security"}

gaps contains g if {
	some for_axis, req in requires
	some k, r in req
	have := object.get(capacity, k, 0)
	have < r
	g := {"axis": need_axis[k], "for": for_axis, "need": k, "required": r, "provided": have}
}

gaps contains g if {
	recorded
	some k in ["persons", "custodians", "custodian_orgs"]
	object.get(forecast, k, 0) > actual[k]
	g := {"axis": need_axis[k], "for": "intake", "need": k, "forecast": forecast[k], "provided": actual[k]}
}

gaps contains g if {
	settings.security.separation == "required"
	some c in conflicts
	g := {"axis": "security", "for": "security", "need": "separation", "person": c.person, "roles": c.roles}
}

verifier_ok(_, "drill", e) if e.verifier in data.competencies.graders

verifier_ok(pid, kind, e) if {
	kind != "drill"
	is_string(e.verifier)
	e.verifier != pid
}

competent(pid, cid) if {
	e := persons[pid].competencies[cid]
	e.evidence in data.competencies.catalog[cid].evidence
	verifier_ok(pid, e.evidence, e)
	object.get(e, "revoked", false) == false
	since := time.parse_ns("2006-01-02", e.since)
	since <= now
	time.add_date(since, 0, settings.security.competency_validity_months, 0) >= now
}

role_competent(pid, role) if {
	some cid, c in data.competencies.catalog
	role in c.for_roles
	competent(pid, cid)
}

gaps contains g if {
	some pid, p in persons
	some role in p.roles
	some cid, c in data.competencies.catalog
	role in c.for_roles
	not competent(pid, cid)
	g := {"axis": "education", "for": role, "need": cid, "person": pid, "learn": [l.ref | some l in c.learn]}
}

profile := {
	"path": path, "tiers": tier, "golden_tiers": golden_tier, "settings": settings, "overlays": overlays,
	"overlay_settings": overlay_settings, "capacity": capacity, "capacity_source": source, "raised_by_mandate": raised_by_mandate,
}

source := "recorded" if recorded

else := "forecast"

# ---- governed actions ------------------------------------------------------------------------------------------

req := object.get(input, "request", {})

body := object.get(req, "body", {})

digest := crypto.sha256(json.marshal(body))

act := data.governed_actions.actions[body.action]

claims(tok) := c if {
	[_, c, _] := io.jwt.decode(tok)
	io.jwt.verify_es256(tok, json.marshal(persons[c.sub].key))
	c.req == digest
	c.iat * 1000000000 <= now
	c.exp * 1000000000 > now
}

requester := c.sub if {
	c := claims(req.token)
	c.kind == "request"
}

approvers contains a if {
	some tok in object.get(req, "approvals", [])
	c := claims(tok)
	c.kind == "approve"
	a := c.sub
	a != requester # defence in depth: signers is a set, so the requester also counts once without it
	some r in act.approver_roles
	r in persons[a].roles
	role_competent(a, r)
}

signers := approvers | {requester} if requester

else := approvers

bands := {"green", "amber", "red", "black"}

default signal := "black"

signal := data.signals.band

band := signal if signal in bands

else := "black"

extra := 1 if band in {"red", "black"}

else := 0

quorum := max([settings.security[act.quorum], act.min_signers]) + extra

announced if {
	c := claims(req.announcement)
	c.kind == "announce"
	c.sub == requester
	c.iat * 1000000000 <= now - ((settings.security.compensation_delay_hours * 3600) * 1000000000)
}

open_exception if {
	some e in exceptions
	body.action in e.actions
	time.parse_ns("2006-01-02", e.expires) > now
}

compensable if {
	settings.security.separation == "compensated"
	band != "black"
}

compensable if {
	open_exception
	band != "black"
}

compensable if {
	settings.security.separation == "compensated"
	act.direction in {"restore", "reduce"}
}

compensable if {
	open_exception
	act.direction in {"restore", "reduce"}
}

mode := "quorum" if count(signers) >= quorum

else := "compensated" if {
	compensable
	announced
}

else := "short"

deny contains sprintf("configuration: %s", [e]) if some e in errors

deny contains "unknown action" if not act

deny contains "the request is not signed by an enrolled person, or is stale or for another body" if not requester

deny contains sprintf("requester does not hold %s", [act.role]) if {
	requester
	not act.role in persons[requester].roles
}

deny contains sprintf("requester has no valid %s competency", [c]) if {
	requester
	some c in act.competencies
	not competent(requester, c)
}

deny contains "black band: only restore and reduce actions pass" if {
	band == "black"
	act.direction == "increase"
}

deny contains sprintf("needs %d signers including the requester, has %d, and compensated mode is not open", [quorum, count(signers)]) if {
	act
	mode == "short"
}

decision := {"allow": count(deny) == 0, "deny": deny, "quorum": quorum, "mode": mode, "band": band} if act

else := {"allow": false, "deny": deny, "quorum": null, "mode": null, "band": band}
