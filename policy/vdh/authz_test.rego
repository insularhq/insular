# Unit tests for vdh.authz (ADR-0109): the enforcement path answers as the data-ring rules decide.
package vdh.authz_test

import rego.v1

import data.vdh.authz

floors := {"green": "off", "amber": "warn", "red": "enforce", "black": "enforce"}

rules := [
	{"id": "RING-S", "topic": "data-max-ring", "effect": "limit", "parameter": "tenant", "scope": {"label": ["Sensitive"]}, "valid_from": "2026-10-01"},
	{"id": "RING-R", "topic": "data-max-ring", "effect": "limit", "parameter": "site", "scope": {"label": ["Restricted"]}, "valid_from": "2026-10-01"},
	{"id": "EXC", "topic": "data-max-ring", "effect": "limit", "parameter": "federation", "scope": {"label": ["Sensitive"], "tenant": ["vdh-demo"]}, "valid_from": "2026-10-01", "raises_risk": true, "min_trust": "high"},
]

check(h) := a if {
	a := authz.allow with input as {"attributes": {"request": {"http": {"headers": object.union({"x-vdh-day": "2026-10-10"}, h)}}}}
		with data.vdh.rules as rules
		with data.vdh.band_floor as floors
}

test_sensitive_within_the_tenant_is_allowed if {
	check({"x-vdh-label": "Sensitive", "x-vdh-reader-ring": "tenant"})
}

test_sensitive_to_a_partner_is_denied if {
	not check({"x-vdh-label": "Sensitive", "x-vdh-reader-ring": "federation"})
}

test_the_accepted_exception_needs_high_trust if {
	check({"x-vdh-label": "Sensitive", "x-vdh-tenant": "vdh-demo", "x-vdh-trust": "high", "x-vdh-reader-ring": "federation"})
	not check({"x-vdh-label": "Sensitive", "x-vdh-tenant": "vdh-demo", "x-vdh-trust": "medium", "x-vdh-reader-ring": "federation"})
}

test_restricted_stays_at_the_site if {
	check({"x-vdh-label": "Restricted", "x-vdh-reader-ring": "site"})
	not check({"x-vdh-label": "Restricted", "x-vdh-reader-ring": "tenant"})
}

test_missing_context_is_denied if {
	not check({"x-vdh-reader-ring": "site"})
	not check({"x-vdh-label": "Sensitive"})
}
