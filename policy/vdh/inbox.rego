# The decision inbox (ADR-0169): may this person file this act on this object, at what autonomy level, and
# is a fresh sign-in needed first? The inbox asks with the person's raw access token, forwarded by the pane's gateway;
# this policy verifies it itself (the pane's issuer, client and the Isle's Keycloak keys: it works on an Isle cut off
# from its ring), so the inbox's word is never taken for who is asking. The level comes from the autonomy matrix in the
# bundle (governance/autonomy.yaml), never from the act's direction.
package vdh.inbox

import rego.v1

import data.vdh.authz

default tier := "low-appetite"

tier := data.vdh.ring.tier

# a step-up is a sign-in no older than this (the freshness of auth_time; the level of authentication is read
# only after it is checked against the identity provider, ADR-0169 consequences)
step_up_seconds := 300

claims := c if {
	resp := http.send({"method": "GET", "url": authz.pane.jwks, "force_cache": true, "force_cache_duration_seconds": 300, "raise_error": false})
	resp.status_code == 200
	[valid, _, c] := io.jwt.decode_verify(input.token, {"cert": resp.raw_body, "iss": authz.pane.issuer, "aud": authz.pane.client, "time": time.now_ns()})
	valid
	c.azp == authz.pane.client
}

# an agent's token carries the actor chain (RFC 8693 "act", policies/time-gating.yaml agent kind): agents only propose
is_agent if claims.act

person if {
	claims
	not is_agent
}

operator if authz.pane.role in claims.realm_access.roles

act := data.vdh.autonomy.actions[input.act]

level := data.vdh.autonomy.max_autonomy[tier][input.act]

fresh if time.now_ns() - (claims.auth_time * 1000000000) <= step_up_seconds * 1000000000

needs_step_up if {
	act.direction == "increase"
	not fresh
}

reasons contains "the sign-in could not be verified" if not claims

reasons contains "an agent may only propose: a person files and decides" if is_agent

reasons contains "only an operator of this Isle's pane may file acts" if {
	claims
	not operator
}

reasons contains "this act is not in the autonomy matrix" if not act

reasons contains "this act is forbidden at this Isle's appetite tier" if level == "forbidden"

reasons contains "the object was not found where it lives" if not input.object_found

reasons contains "this act widens access: sign in again with your passkey first" if needs_step_up

default step_up := false

step_up if needs_step_up

default subject := ""

subject := claims.sub

decision := {
	"allow": count(reasons) == 0,
	"level": object.get(object.get(data.vdh.autonomy.max_autonomy, tier, {}), input.act, "unknown"),
	"needs_step_up": step_up,
	"reasons": sort([r | some r in reasons]),
	"subject": subject,
}
