package system.authz_test

import rego.v1

import data.system.authz

token := "lab-test-token-not-a-secret"

api := {"vdh": {"harbor_api": {"token_sha256": crypto.sha256(token)}}}

call(method, path, who) := {"method": method, "path": split(path, "/"), "identity": who}

test_the_evaluator_pushes_partners_and_releases_with_its_token if {
	authz.allow with input as call("PUT", "v1/data/vdh/harbor/partners", token) with data.vdh as api.vdh
	authz.allow with input as call("PUT", "v1/data/vdh/harbor/releases", token) with data.vdh as api.vdh
}

test_the_evaluator_asks_the_class_and_release_rules_with_its_token if {
	every p in ["allow", "trusted", "content_why", "may_release", "may_release_why"] {
		authz.allow with input as call("POST", concat("/", ["v1/data/vdh/harbor", p]), token) with data.vdh as api.vdh
	}
}

test_no_token_is_refused if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "data", "vdh", "harbor", "partners"]} with data.vdh as api.vdh
}

test_a_wrong_token_is_refused if {
	not authz.allow with input as call("PUT", "v1/data/vdh/harbor/partners", "guess") with data.vdh as api.vdh
}

test_the_hash_itself_is_not_a_token if {
	not authz.allow with input as call("PUT", "v1/data/vdh/harbor/partners", crypto.sha256(token)) with data.vdh as api.vdh
}

test_without_a_pinned_hash_everything_is_refused if {
	not authz.allow with input as call("PUT", "v1/data/vdh/harbor/partners", token) with data.vdh as {}
}

test_the_token_cannot_change_a_policy_or_read_data if {
	not authz.allow with input as call("PUT", "v1/policies/harbor", token) with data.vdh as api.vdh
	not authz.allow with input as call("GET", "v1/data/vdh/harbor/partners", token) with data.vdh as api.vdh
	not authz.allow with input as call("GET", "v1/data/vdh/harbor_api", token) with data.vdh as api.vdh
	not authz.allow with input as call("PUT", "v1/data/vdh/harbor/partner_cas", token) with data.vdh as api.vdh
	not authz.allow with input as call("PUT", "v1/data", token) with data.vdh as api.vdh
	not authz.allow with input as call("DELETE", "v1/data/vdh/harbor/partners", token) with data.vdh as api.vdh
}

test_the_class_rule_is_asked_not_written if {
	not authz.allow with input as call("PUT", "v1/data/vdh/harbor/allow", token) with data.vdh as api.vdh
	not authz.allow with input as call("PATCH", "v1/data/vdh/harbor/partners", token) with data.vdh as api.vdh
}

test_the_readiness_probe_needs_no_token_and_opens_nothing_else if {
	authz.allow with input as {"method": "GET", "path": ["health"]} with data.vdh as api.vdh
	not authz.allow with input as {"method": "GET", "path": ["health", "plugins"]} with data.vdh as api.vdh
	not authz.allow with input as {"method": "POST", "path": ["health"]} with data.vdh as api.vdh
	not authz.allow with input as {"method": "GET", "path": ["metrics"]} with data.vdh as api.vdh
}
