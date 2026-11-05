# Unit tests for the decision inbox's policy (ADR-0169): a verified operator files; an agent, a non-operator,
# an unknown act or a missing object is refused; an increase act needs a fresh sign-in; the level comes from the matrix.
# Keys and tokens come from the pane tests' throwaway fixtures.
package vdh.inbox_test

import rego.v1

import data.vdh.authz_pane_test as fx
import data.vdh.inbox

autonomy := {
	"actions": {
		"propose-change": {"direction": "neutral", "reversible": true},
		"rotate-certificate": {"direction": "reduce", "reversible": true},
		"grant-access": {"direction": "increase", "reversible": true},
	},
	"max_autonomy": {"low-appetite": {"propose-change": "autonomous", "rotate-certificate": "notify", "grant-access": "human"}},
}

now_s := time.now_ns() / 1000000000

ask(over, act) := d if {
	d := inbox.decision with input as {"token": fx.token(fx.good_key, over), "act": act, "object_found": true}
		with data.vdh.autonomy as autonomy
		with http.send as fx.mock_send
}

test_an_operator_files_a_neutral_act_at_its_matrix_level if {
	d := ask({"auth_time": now_s - 3600}, "propose-change")
	d.allow
	d.level == "autonomous"
	not d.needs_step_up
}

test_an_increase_act_needs_a_fresh_sign_in if {
	stale := ask({"auth_time": now_s - 3600}, "grant-access")
	not stale.allow
	stale.needs_step_up
	fresh := ask({"auth_time": now_s - 10}, "grant-access")
	fresh.allow
	fresh.level == "human"
}

test_an_agent_only_proposes if {
	d := ask({"auth_time": now_s, "act": {"sub": "agent-1"}}, "propose-change")
	not d.allow
	"an agent may only propose: a person files and decides" in d.reasons
}

test_a_non_operator_is_refused if {
	d := ask({"auth_time": now_s, "realm_access": {"roles": ["tenant-user"]}}, "propose-change")
	not d.allow
}

test_an_unknown_act_is_refused if {
	d := ask({"auth_time": now_s}, "wipe-everything")
	not d.allow
	"this act is not in the autonomy matrix" in d.reasons
}

test_a_missing_object_is_refused if {
	d := inbox.decision with input as {"token": fx.token(fx.good_key, {"auth_time": now_s}), "act": "propose-change", "object_found": false}
		with data.vdh.autonomy as autonomy
		with http.send as fx.mock_send
	not d.allow
}

test_a_forged_token_is_refused if {
	d := inbox.decision with input as {"token": fx.token(fx.evil_key, {"auth_time": now_s}), "act": "propose-change", "object_found": true}
		with data.vdh.autonomy as autonomy
		with http.send as fx.mock_send
	not d.allow
	"the sign-in could not be verified" in d.reasons
}
