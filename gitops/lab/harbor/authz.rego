# Who may use the Harbor PDP's own API. OPA runs with --authentication=token and
# --authorization=basic, so every call to its REST API on 8181 is decided here; the ext_authz gRPC port (9191, Envoy)
# is not this API and is not affected.
#
# OPA applies this to the diagnostic port too, so the readiness probe's GET /health is allowed without a token (it
# says only that the server is up); nothing else is.
#
# Only the ring-side evaluator calls it, through a port-forward: it pushes the partners' states and the steward's
# releases, and asks the class rule (trusted: what the pane shows) and the release rule. Its token is made at admission (the lab tooling),
# kept root-only on the node; the PDP holds only its SHA-256 (Secret harbor-pdp-api, data.vdh.harbor_api). Anything
# else (another path, reading data, changing a policy) is refused, with the token or without.
package system.authz

import rego.v1

default allow := false

calls := {
	["PUT", "v1/data/vdh/harbor/partners"],
	["PUT", "v1/data/vdh/harbor/releases"],
	["POST", "v1/data/vdh/harbor/allow"],
	["POST", "v1/data/vdh/harbor/trusted"],
	["POST", "v1/data/vdh/harbor/content_why"],
	["POST", "v1/data/vdh/harbor/may_release"],
	["POST", "v1/data/vdh/harbor/may_release_why"],
}

allow if {
	is_string(input.identity)
	crypto.sha256(input.identity) == data.vdh.harbor_api.token_sha256
	[input.method, concat("/", input.path)] in calls
}

allow if {
	input.method == "GET"
	input.path == ["health"]
}
