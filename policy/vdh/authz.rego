# The enforcement path (ADR-0109): Envoy's ext_authz check request in, allow or deny out, decided by the same rules
# as everything else (vdh.decide). The reader may reach data only within the widest ring the rules allow for its label,
# tenant, trust and band. Lab: the context arrives in request headers; in production the gateway derives it from the
# verified session and the data's envelope and strips any client-supplied copy.
package vdh.authz

import rego.v1

import data.vdh.decide

rings := {"host": 0, "site": 1, "tenant": 2, "federation": 3, "public": 4}

headers := input.attributes.request.http.headers

today := substring(time.format(time.now_ns()), 0, 10)

context := object.union(
	{
		"day": object.get(headers, "x-vdh-day", today),
		"label": headers["x-vdh-label"],
		"trust": object.get(headers, "x-vdh-trust", "none"),
		"band": object.get(headers, "x-vdh-band", "black"), # absent is the strictest band
	},
	{k: v | some h, k in {"x-vdh-tenant": "tenant"}; v := headers[h]},
)

widest := r if {
	result := decide.result with input as {"context": context}
	r := result["data-max-ring"].parameter
}

default allow := false

# The data ring rule: never on the pane's host, where lab context headers could otherwise stand in for a sign-in.
allow if {
	not is_pane
	reader := headers["x-vdh-reader-ring"]
	rings[reader] <= rings[widest]
}

# The operator pane (ADR-0115): the gateway signs the user in with Keycloak and forwards the access token;
# this rule verifies that token itself (signature against the realm's published keys, issuer, audience, client,
# expiry) and admits only a pharos-operator to the pane's host. The values here are for a test ring; production takes them from the instance
# file.
# the ring's own pane host and issuer (gitops/lab/pdp/ring.json, the ring's domain substituted by Flux); these built-in
# values apply without it.
default pane_host := "pharos.lab.vdh.test"

pane_host := data.vdh.ring.pane_host

default pane_issuer := "https://id.lab.vdh.test/realms/vdh"

pane_issuer := data.vdh.ring.issuer

pane := {
	"host": pane_host,
	"issuer": pane_issuer,
	"client": "pharos",
	"role": "pharos-operator",
	"jwks": "http://keycloak.vdh-identity.svc.cluster.local:8080/realms/vdh/protocol/openid-connect/certs",
}

# NetBox, the site's DCIM/IPAM master (ADR-0171), sits behind the same sign-in and the same rule as the pane
default netbox_host := "netbox.lab.vdh.test"

netbox_host := data.vdh.ring.netbox_host

admin_hosts := {pane.host, netbox_host}

is_pane if split(input.attributes.request.http.host, ":")[0] in admin_hosts

bearer := t if {
	v := headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, 7, -1)
}

pane_claims := c if {
	resp := http.send({"method": "GET", "url": pane.jwks, "force_cache": true, "force_cache_duration_seconds": 300, "raise_error": false})
	resp.status_code == 200
	[valid, _, c] := io.jwt.decode_verify(bearer, {"cert": resp.raw_body, "iss": pane.issuer, "aud": pane.client, "time": time.now_ns()})
	valid
}

allow if {
	is_pane
	pane_claims.azp == pane.client
	pane.role in pane_claims.realm_access.roles
}
