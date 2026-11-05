# Unit tests for vdh.decide (ADR-0092): band floors only tighten, supersession, trust-gated rules, specificity, by_band.
package vdh.decide_test

import rego.v1

import data.vdh.decide

floors := {"green": "off", "amber": "warn", "red": "enforce", "black": "enforce"}

rules := [
	{"id": "TLS-2024", "topic": "tls", "effect": "require", "parameter": "1.2", "scope": {}, "valid_from": "2024-01-01"},
	{"id": "TLS-2026", "topic": "tls", "effect": "require", "parameter": "1.3", "scope": {}, "valid_from": "2026-01-01", "supersedes": [{"rule": "TLS-2024"}]},
	{"id": "SESS", "topic": "session", "effect": "limit", "parameter": "8h", "by_band": {"amber": "1h", "red": "15m", "black": "0"}, "scope": {}, "valid_from": "2026-01-01", "rollout": "observe"},
	{"id": "SITE-X", "topic": "session", "effect": "limit", "parameter": "4h", "scope": {"site": ["edge-1"]}, "valid_from": "2026-01-01"},
	{"id": "RISKY", "topic": "usb", "effect": "allow", "raises_risk": true, "min_trust": "high", "scope": {}, "valid_from": "2026-01-01"},
]

result_for(ctx) := r if {
	r := decide.result with input as {"context": ctx}
		with data.vdh.rules as rules
		with data.vdh.band_floor as floors
}

test_supersession_picks_the_newer_rule if {
	r := result_for({"day": "2026-10-10", "trust": "low", "band": "green"})
	r.tls.rule == "TLS-2026"
	r.tls.parameter == "1.3"
}

test_before_valid_from_the_older_rule_stands if {
	r := result_for({"day": "2025-06-01", "trust": "low", "band": "green"})
	r.tls.rule == "TLS-2024"
}

test_band_floor_raises_observe_to_warn_and_enforce if {
	result_for({"day": "2026-10-10", "band": "green"}).session.mode == "observe"
	result_for({"day": "2026-10-10", "band": "amber"}).session.mode == "warn"
	result_for({"day": "2026-10-10", "band": "red"}).session.mode == "enforce"
}

test_by_band_tightens_the_parameter if {
	result_for({"day": "2026-10-10", "band": "green"}).session.parameter == "8h"
	result_for({"day": "2026-10-10", "band": "red"}).session.parameter == "15m"
	result_for({"day": "2026-10-10", "band": "black"}).session.parameter == "0"
}

test_the_more_specific_scope_wins if {
	r := result_for({"day": "2026-10-10", "band": "green", "site": "edge-1"})
	r.session.rule == "SITE-X"
}

test_risk_raising_rule_needs_its_trust if {
	r := result_for({"day": "2026-10-10", "trust": "medium", "band": "green"})
	r.usb.rule == null
	r.usb.blocked == ["RISKY"]
	result_for({"day": "2026-10-10", "trust": "high", "band": "green"}).usb.rule == "RISKY"
}

test_exemptions_are_suspended_at_black if {
	not decide.exemptions_honoured with input as {"context": {"band": "black", "day": "2026-10-10"}}
	decide.exemptions_honoured with input as {"context": {"band": "red", "day": "2026-10-10"}}
}

# review (ADR-0126): a context without a band decides as black, never as green
test_absent_band_is_black if {
	r := result_for({"day": "2026-10-10"})
	r.session.parameter == "0"
	r.session.mode == "enforce"
	not decide.exemptions_honoured with input as {"context": {"day": "2026-10-10"}}
}
