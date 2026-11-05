# vdh.decide (ADR-0092): the common policy model evaluated by OPA. Rules are data (data.vdh.rules, compiled from
# policies/packs by tools/policy_compile.py); this evaluator mirrors tools/policy_engine.py effective() exactly, and adds
# the enforcement mode per risk band. A differential test keeps the two in agreement.
#
# input.context: scope dimensions (tenant, site, label, ...), trust (none|low|medium|high), band (green|amber|red|black;
#                absent means black), day (YYYY-MM-DD)
# result[topic]: {rule, effect, parameter, mode, conflicts, blocked, and the remaining-risk field}
package vdh.decide

import rego.v1

trust_rank := {"none": 0, "low": 1, "medium": 2, "high": 3}

modes := ["off", "announce", "observe", "warn", "enforce"]

mode_rank := {"off": 0, "announce": 1, "observe": 2, "warn": 3, "enforce": 4}

ctx := input.context

trust := object.get(ctx, "trust", "none")

# a missing band is the strictest, never green
band := object.get(ctx, "band", "black")

valid(r) if {
	r.valid_from <= ctx.day
	object.get(r, "valid_until", null) == null
}

valid(r) if {
	r.valid_from <= ctx.day
	until := object.get(r, "valid_until", null)
	until != null
	ctx.day <= until
}

matches(r) if {
	every dim, vals in object.get(r, "scope", {}) {
		object.get(ctx, dim, null) in vals
	}
}

# a rule that raises risk applies only at or above its minimum trust
allowed(r) if not object.get(r, "raises_risk", false)

allowed(r) if {
	object.get(r, "raises_risk", false)
	trust_rank[trust] >= trust_rank[r.min_trust]
}

matching contains r if {
	some r in data.vdh.rules
	valid(r)
	matches(r)
}

overlap(a, b) if {
	shared := {k | some k, _ in a} & {k | some k, _ in b}
	every k in shared {
		count({v | some v in a[k]; v in b[k]}) > 0
	}
}

# superseded by an allowed matching rule that names it, where their scopes overlap
superseded(r) if {
	some n in matching
	allowed(n)
	n.id != r.id
	some s in object.get(n, "supersedes", [])
	s.rule == r.id
	overlap(object.get(s, "scope", object.get(n, "scope", {})), object.get(r, "scope", {}))
}

cands contains r if {
	some r in matching
	allowed(r)
	not superseded(r)
}

spec(r) := count(object.get(r, "scope", {}))

topics := {r.topic | some r in matching}

param(r) := v if {
	v := object.get(object.get(r, "by_band", {}), band, null)
	v != null
} else := v if {
	v := object.get(object.get(r, "by_trust", {}), trust, null)
	v != null
} else := object.get(r, "parameter", null)

# the band floor: as the risk band rises, enforcement only tightens (policies/model.yaml band_enforcement)
floor := data.vdh.band_floor[band]

mode(r) := modes[max({mode_rank[object.get(r, "rollout", "enforce")], mode_rank[floor]})]

result[topic] := out if {
	some topic in topics
	usable := [r | some r in cands; r.topic == topic]
	count(usable) > 0
	top := max({spec(r) | some r in usable})
	best := sort([r.id | some r in usable; spec(r) == top])
	first := [r | some r in usable; r.id == best[0]][0]
	vals := {sprintf("%v|%v", [r.effect, param(r)]) | some r in usable; spec(r) == top}
	out := {
		"rule": first.id,
		"effect": first.effect,
		"parameter": param(first),
		"mode": mode(first),
		"conflicts": conflicts_of(best, vals),
		"blocked": sort([r.id | some r in matching; r.topic == topic; not allowed(r)]),
		"residual": object.get(first, "residual", null),
	}
}

result[topic] := out if {
	some topic in topics
	count([r | some r in cands; r.topic == topic]) == 0
	out := {
		"rule": null, "effect": null, "parameter": null, "mode": "off", "conflicts": [],
		"blocked": sort([r.id | some r in matching; r.topic == topic; not allowed(r)]),
		"residual": null,
	}
}

conflicts_of(best, vals) := best if count(vals) > 1

conflicts_of(_, vals) := [] if count(vals) <= 1

# exemptions are honoured below black; at black they are suspended (policies/model.yaml band_enforcement)
exemptions_honoured := band != "black"
