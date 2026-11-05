# The Harbor's decision (ADR-0111, ADR-0149, ADR-0151, federation design stages 4 to 6): what a federation partner may send
# through this ring's Harbor, by traffic class, from the partner's live FTEF state and band.
#
# input: Envoy's ext_authz check request. The partner is the verified client certificate's URI SAN (mTLS at the
# Harbor, validated against that partner's CA only); never a header the client could set.
# data.vdh.harbor.classes:  per class, the ladder states it is open in and the lowest band (policy, from the model)
# data.vdh.harbor.partners: per partner, {state, band, valid_until} pushed by the ring-side evaluator (FTEF evaluate.py)
# A partner the evaluator has not reported, or whose report is stale, gets management only, so evidence can still
# arrive to re-evaluate it; nothing else.
package vdh.harbor

import rego.v1

band_rank := {"none": 0, "low": 1, "medium": 2, "high": 3}

path := split(input.attributes.request.http.path, "?")[0]

host := split(object.get(input.attributes.request.http, "host", ""), ":")[0]

# this ring's identity provider and OpenCloud, reached by a partner's users: data-plane (they lead to the data);
# their names are this ring's own (data.vdh.harbor.ring.data_hosts, the ring's domain substituted by Flux)
data_host if host in data.vdh.harbor.ring.data_hosts

principal := input.attributes.source.principal

# a partner is bound to its own CA. The gateway verifies the client certificate against
# partner-ca (every admitted partner's CA in one bundle) and names the principal from its URI SAN; the bundle cannot say
# which CA belongs to which partner, so at the second partner one partner's CA could mint another's SAN. The PDP checks
# the leaf against the CA pinned for this principal at admission (data.vdh.harbor.partner_cas, ConfigMap
# harbor-partners). The leaf arrives in x-forwarded-client-cert (Cert, percent-encoded), which the gateway sets itself
# and strips from clients (SanitizeSet); Envoy Gateway cannot pass the peer certificate to ext_authz directly (an upstream limitation).
# Every decision needs the binding, management included.
xfcc := object.get(object.get(input.attributes.request.http, "headers", {}), "x-forwarded-client-cert", "")

peer_pem := urlquery.decode(replace(m[1], "+", "%2B")) if {
	m := regex.find_all_string_submatch_n(`(?:^|[;,])Cert="([^"]+)"`, xfcc, 1)[0]
}

default bound := false

# a principal's pin is the CA admitted for it (a string) or, while its CA is being replaced, a list
# of {"ca", "until"}: the old CA with the end of the overlap the operator gave, the new one with none. An entry past its
# end binds nothing, so an old CA fails closed when its overlap ends, whether or not anyone has pruned it yet; a removed
# partner has no entry and binds nothing at all.
pinned_cas contains ca if {
	ca := data.vdh.harbor.partner_cas[principal]
	is_string(ca)
}

pinned_cas contains e.ca if {
	pins := data.vdh.harbor.partner_cas[principal]
	is_array(pins)
	some e in pins
	not e.until
}

pinned_cas contains e.ca if {
	pins := data.vdh.harbor.partner_cas[principal]
	is_array(pins)
	some e in pins
	time.now_ns() < time.parse_rfc3339_ns(e.until)
}

bound if {
	some ca in pinned_cas
	[ok, _] := crypto.x509.parse_and_verify_certificates_with_options(
		concat("\n", [ca, peer_pem]),
		{"KeyUsages": ["KeyUsageClientAuth"]},
	)
	ok
}

class := "data-plane" if {
	not data_host
	startswith(path, "/data/")
}

class := "data-plane" if data_host

class := "telephony" if {
	not data_host
	startswith(path, "/_matrix/")
}

# a partner's homeserver discovers this one before it federates (Matrix server-server API, server discovery)
class := "telephony" if {
	not data_host
	path == "/.well-known/matrix/server"
}

class := "management" if {
	not data_host
	regex.match(`^/mgmt/(state|logs|evidence)(/.*)?$`, path)
}

# ADR-0153: content that leaves this ring by Open Cloud Mesh is fetched by the partner's server at /dav/ocm/<share>/...
# on this ring's OpenCloud. It leaves only as a release: the share registered by this ring's steward with the label of
# the space it comes from, for this partner, until a date; and only if that label may go to a federation (the label's
# widest ring, policies/packs/data-centric.yaml data-max-ring). An unreleased share is refused, whatever the band.
ocm_share := m[1] if {
	data_host
	m := regex.find_all_string_submatch_n(`^/dav/ocm/([^/]+)(/.*)?$`, path, 1)[0]
}

release := data.vdh.harbor.releases[ocm_share]

ring_rank := {"host": 0, "site": 1, "tenant": 2, "federation": 3, "public": 4}

label_may_federate if ring_rank[data.vdh.harbor.labels[release.label]] >= ring_rank.federation

# the steward's release step asks this, so the label rule has one place: input.release = {label}
default may_release := false

may_release if ring_rank[data.vdh.harbor.labels[input.release.label]] >= ring_rank.federation

default may_release_why := "an unlabelled share is unidentified: it stays on its site (DATA-RING-UNIDENTIFIED)"

may_release_why := sprintf("%s may go to a federation", [input.release.label]) if may_release

may_release_why := sprintf("%s stays within %s (data-max-ring)", [input.release.label, data.vdh.harbor.labels[input.release.label]]) if {
	data.vdh.harbor.labels[input.release.label]
	not may_release
}

released if {
	release.partner == principal
	time.parse_rfc3339_ns(release.until) > time.now_ns()
	label_may_federate
}

# content checks beyond the class: only an Open Cloud Mesh fetch carries a share to check
content_ok if not ocm_share

content_ok if released

default content_why := "not content"

content_why := "released" if released

content_why := "not released: no release for this share" if {
	ocm_share
	not release
}

content_why := sprintf("not released: label %s stays within %s", [release.label, data.vdh.harbor.labels[release.label]]) if {
	ocm_share
	release
	not label_may_federate
}

content_why := "not released: the release is for another partner or has ended" if {
	ocm_share
	release
	label_may_federate
	not released
}

reported := data.vdh.harbor.partners[principal]

fresh if time.parse_rfc3339_ns(reported.valid_until) > time.now_ns()

partner := reported if fresh

partner := {"state": "unreported", "band": "none", "stale": true} if not fresh

rule := data.vdh.harbor.classes[class]

default allow := false

allow if {
	bound
	trusted
}

# what this partner's state, band and the content allow, for a certificate bound to it. The evaluator asks this, not
# allow, to show on the pane which classes are open (ADR-0151 decision 4): its probe carries no connection, so it
# cannot be bound, and allow is exactly bound and trusted.
default trusted := false

trusted if {
	fresh
	partner.state in rule.states
	band_rank[partner.band] >= band_rank[rule.min_band]
	content_ok
}

trusted if {
	not fresh
	class == "management"
}

default class_name := "Internal"

class_name := class

# what the decision log and the Pharos counters record (never the request body)
decision := {
	"partner": principal,
	"class": class_name,
	"state": partner.state,
	"band": partner.band,
	"stale": object.get(partner, "stale", false),
	"allowed": allow,
	"bound": bound,
	"content": content_why,
	"label": release_label,
}

# the release's label for an Open Cloud Mesh fetch, else empty (an undefined share must not undefine the decision: the
# earlier inline form did, for every request that was not a fetch)
default release_label := ""

release_label := object.get(release, "label", "")
