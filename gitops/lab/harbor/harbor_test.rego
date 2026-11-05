package vdh.harbor_test

import rego.v1

import data.vdh.harbor

s := "spiffe://s.vdh.test/harbor"

x := "spiffe://x.vdh.test/harbor"

future := "2200-01-01T00:00:00Z" # OPA ns timestamps end in 2262

# the gateway's x-forwarded-client-cert for this connection, carrying the leaf it verified (harbor_test_certs.rego)
xfcc(leaf) := {"x-forwarded-client-cert": sprintf(`By=spiffe://m.vdh.test/harbor;Hash=00;Cert="%s";URI=%s`, [leaf, s])}

req(p, who) := {"attributes": {"source": {"principal": who}, "request": {"http": {
	"path": p, "host": "harbor.m.vdh.test",
	"headers": xfcc(leaf_s_xfcc),
}}}}

hreq(h, p) := {"attributes": {"source": {"principal": s}, "request": {"http": {
	"path": p, "host": h,
	"headers": xfcc(leaf_s_xfcc),
}}}}

cas := {s: ca_s, x: ca_x}

hosts := {"ring": {"data_hosts": ["id.m.vdh.test", "cloud.m.vdh.test"]}}

ok(p, state, band) if harbor.allow with input as req(p, s)
	with data.vdh.harbor.partners as {s: {"state": state, "band": band, "valid_until": future}}
	with data.vdh.harbor.partner_cas as cas

test_member_medium_opens_all_three if {
	ok("/data/docs/plan.md", "member", "medium")
	ok("/_matrix/client/v3/sync", "member", "medium")
	ok("/mgmt/evidence", "member", "medium")
}

test_member_low_band_closes_data_only if {
	not ok("/data/docs/plan.md", "member", "low")
	ok("/_matrix/client/v3/sync", "member", "low")
	ok("/mgmt/state", "member", "low")
}

test_restricted_and_suspended_keep_telephony_and_management if {
	every st in ["restricted", "suspended"] {
		not ok("/data/docs/plan.md", st, "none")
		ok("/_matrix/client/v3/rooms", st, "none")
		ok("/mgmt/logs", st, "none")
	}
}

test_withdrawn_closes_everything if {
	not ok("/data/docs/plan.md", "withdrawn", "none")
	not ok("/_matrix/client/v3/sync", "withdrawn", "none")
	not ok("/mgmt/evidence", "withdrawn", "none")
}

test_watch_needs_medium_for_data if {
	ok("/data/x", "watch", "medium")
	not ok("/data/x", "watch", "low")
}

test_unknown_or_stale_partner_gets_management_only if {
	harbor.allow with input as req("/mgmt/evidence", s) with data.vdh.harbor.partner_cas as cas
	not harbor.allow with input as req("/data/x", s) with data.vdh.harbor.partner_cas as cas
	not harbor.allow with input as req("/data/x", s)
		with data.vdh.harbor.partners as {s: {"state": "member", "band": "high", "valid_until": "2000-01-01T00:00:00Z"}}
		with data.vdh.harbor.partner_cas as cas
}

test_Internal_paths_and_other_mgmt_kinds_are_refused if {
	not ok("/admin", "member", "high")
	not ok("/mgmt/shell", "member", "high")
	not ok("/mgmtx/state", "member", "high")
}

hok(h, p, state, band) if harbor.allow with input as hreq(h, p)
	with data.vdh.harbor.partners as {s: {"state": state, "band": band, "valid_until": future}}
	with data.vdh.harbor.ring as hosts.ring
	with data.vdh.harbor.partner_cas as cas

test_identity_and_cloud_hosts_are_data_plane if {
	hok("id.m.vdh.test", "/realms/vdh/broker/ring-s/endpoint", "member", "medium")
	hok("cloud.m.vdh.test:443", "/remote.php/dav/spaces/x", "watch", "medium")
	not hok("id.m.vdh.test", "/realms/vdh/protocol/openid-connect/auth", "suspended", "none")
	not hok("cloud.m.vdh.test", "/graph/v1.0/me", "member", "low")
}

test_a_data_host_never_borrows_another_class_by_path if {
	not hok("cloud.m.vdh.test", "/mgmt/state", "suspended", "none")
	not hok("cloud.m.vdh.test", "/_matrix/client/versions", "restricted", "low")
}

test_an_unlisted_host_is_classed_by_path_only if {
	hok("harbor.m.vdh.test", "/mgmt/state", "suspended", "none")
	not hok("pharos.m.vdh.test", "/", "member", "high")
}

# ADR-0153: Open Cloud Mesh fetches leave only as releases whose label may go to a federation
ocm(p, releases) if harbor.allow with input as hreq("cloud.m.vdh.test", p)
	with data.vdh.harbor.ring as hosts.ring
	with data.vdh.harbor.partners as {s: {"state": "member", "band": "medium", "valid_until": future}}
	with data.vdh.harbor.releases as releases
	with data.vdh.harbor.labels as {"Internal": "federation", "Sensitive": "tenant", "Restricted": "site"}
	with data.vdh.harbor.partner_cas as cas

rel(label) := {"sh1": {"label": label, "partner": s, "until": future}}

test_an_internal_release_leaves if ocm("/dav/ocm/sh1/note.md", rel("Internal"))

test_a_sensitive_share_never_leaves_even_released if not ocm("/dav/ocm/sh1/note.md", rel("Sensitive"))

test_a_restricted_share_never_leaves if not ocm("/dav/ocm/sh1/note.md", rel("Restricted"))

test_an_unreleased_share_is_refused_at_band_medium if not ocm("/dav/ocm/sh2/note.md", rel("Internal"))

test_an_unlabelled_release_is_refused if not ocm("/dav/ocm/sh1/note.md", rel("Secret"))

test_a_release_for_another_partner_is_refused if {
	not ocm("/dav/ocm/sh1/note.md", {"sh1": {"label": "Internal", "partner": x, "until": future}})
}

test_an_ended_release_is_refused if {
	not ocm("/dav/ocm/sh1/note.md", {"sh1": {"label": "Internal", "partner": s, "until": "2020-01-01T00:00:00Z"}})
}

test_brokered_reading_inside_this_ring_is_not_a_release if ocm("/dav/spaces/abc/joint-plan.md", {})

test_a_released_share_still_needs_the_band if {
	not harbor.allow with input as hreq("cloud.m.vdh.test", "/dav/ocm/sh1/note.md")
		with data.vdh.harbor.ring as hosts.ring
		with data.vdh.harbor.partners as {s: {"state": "member", "band": "low", "valid_until": future}}
		with data.vdh.harbor.releases as rel("Internal")
		with data.vdh.harbor.labels as {"Internal": "federation", "Sensitive": "tenant", "Restricted": "site"}
		with data.vdh.harbor.partner_cas as cas
}

# the steward's release step asks the same policy (one place for the label rule)
mr(label) if harbor.may_release with input as {"release": {"label": label}}
	with data.vdh.harbor.labels as {"Internal": "federation", "Sensitive": "tenant", "Restricted": "site"}

test_the_release_step_may_release_internal_only if {
	mr("Internal")
	not mr("Sensitive")
	not mr("Restricted")
	not mr("unlabelled")
}

# ADR-0114 amendment: a partner's homeserver federates with this ring's Synapse as telephony, so federation stays open
# when the partner is restricted or suspended and data-plane traffic is closed
test_matrix_federation_is_telephony_and_survives_restriction if {
	every st in ["restricted", "suspended"] {
		hok("matrix.m.vdh.test", "/_matrix/federation/v1/send/1", st, "none")
		hok("matrix.m.vdh.test", "/_matrix/key/v2/server", st, "none")
		hok("matrix.m.vdh.test", "/.well-known/matrix/server", st, "none")
		not hok("matrix.m.vdh.test", "/data/docs/plan.md", st, "none")
	}
	not hok("matrix.m.vdh.test", "/_matrix/federation/v1/send/1", "withdrawn", "none")
}

# ---- a partner is bound to its own CA ----------------------------------------------------
# as S, member at band high, on every class: only the binding varies
as_s(headers, pinned) if harbor.allow with input as {"attributes": {"source": {"principal": s}, "request": {"http": {
	"path": "/mgmt/evidence", "host": "harbor.m.vdh.test", "headers": headers,
}}}}
	with data.vdh.harbor.partners as {s: {"state": "member", "band": "high", "valid_until": future}}
	with data.vdh.harbor.partner_cas as pinned

test_the_leaf_signed_by_the_partners_own_ca_binds if as_s(xfcc(leaf_s_xfcc), cas)

test_another_partners_ca_minting_the_same_san_is_refused if {
	not as_s(xfcc(leaf_forged_xfcc), cas)
	as_s(xfcc(leaf_forged_xfcc), {s: ca_x}) # the binding follows the pinned CA, nothing else
}

test_an_expired_leaf_is_refused if not as_s(xfcc(leaf_expired_xfcc), cas)

test_without_the_gateways_certificate_nothing_passes if {
	not as_s({}, cas)
	not as_s({"x-forwarded-client-cert": "By=a;Hash=b;URI=c"}, cas)
	not as_s({"x-forwarded-client-cert": `Cert="not a certificate"`}, cas)
	not as_s(xfcc(leaf_s_xfcc), {x: ca_x}) # a principal with no CA pinned
}

test_an_unreported_partner_without_the_binding_gets_nothing if {
	not harbor.allow with input as {"attributes": {"source": {"principal": s}, "request": {"http": {
		"path": "/mgmt/evidence", "host": "harbor.m.vdh.test",
		"headers": xfcc(leaf_forged_xfcc),
	}}}}
		with data.vdh.harbor.partner_cas as cas
}

test_a_plus_left_unencoded_by_the_gateway_still_binds if {
	as_s(xfcc(replace(leaf_s_xfcc, "%2B", "+")), cas)
}

test_the_decision_log_says_whether_the_partner_was_bound if {
	d := harbor.decision with input as req("/mgmt/evidence", s) with data.vdh.harbor.partner_cas as {s: ca_x}
	d.bound == false
	d.allowed == false
	d.label == ""
	b := harbor.decision with input as req("/mgmt/evidence", s) with data.vdh.harbor.partner_cas as cas
	b.bound == true
}

# the pane asks trusted (no connection, so never bound) and shows what a bound certificate gets; allow stays
# bound and trusted, so the same probe through allow is refused
probe(p) := {"attributes": {"source": {"principal": s}, "request": {"http": {"path": p}}}}

test_the_pane_shows_what_a_bound_partner_gets_and_the_probe_itself_is_refused if {
	every p in ["/data/probe", "/_matrix/probe", "/mgmt/state"] {
		harbor.trusted with input as probe(p)
			with data.vdh.harbor.partners as {s: {"state": "member", "band": "medium", "valid_until": future}}
			with data.vdh.harbor.partner_cas as cas
		not harbor.allow with input as probe(p)
			with data.vdh.harbor.partners as {s: {"state": "member", "band": "medium", "valid_until": future}}
			with data.vdh.harbor.partner_cas as cas
	}
}

test_the_pane_shows_a_suspended_partner_with_the_data_plane_closed if {
	not harbor.trusted with input as probe("/data/probe")
		with data.vdh.harbor.partners as {s: {"state": "suspended", "band": "none", "valid_until": future}}
	harbor.trusted with input as probe("/mgmt/state")
		with data.vdh.harbor.partners as {s: {"state": "suspended", "band": "none", "valid_until": future}}
}

test_the_pane_shows_an_unreported_partner_with_management_only if {
	harbor.trusted with input as probe("/mgmt/state") with data.vdh.harbor.partners as {}
	not harbor.trusted with input as probe("/data/probe") with data.vdh.harbor.partners as {}
	not harbor.trusted with input as probe("/_matrix/probe") with data.vdh.harbor.partners as {}
}

# replacing a partner's CA with an overlap, and removing a partner
past := "2020-01-01T00:00:00Z"

bound_with(pins) if harbor.allow with input as req("/mgmt/evidence", s)
	with data.vdh.harbor.partners as {s: {"state": "member", "band": "medium", "valid_until": future}}
	with data.vdh.harbor.partner_cas as {s: pins, x: ca_x}

test_during_an_overlap_the_old_ca_still_binds if {
	bound_with([{"ca": ca_s, "until": future}, {"ca": ca_x}])
}

test_after_the_overlap_the_old_ca_binds_nothing if {
	not bound_with([{"ca": ca_s, "until": past}, {"ca": ca_x}])
}

test_the_new_ca_without_an_end_binds if {
	bound_with([{"ca": ca_x, "until": past}, {"ca": ca_s}])
}

test_another_partners_ca_never_binds_this_principal if {
	not bound_with([{"ca": ca_x}])
}

test_a_removed_partner_binds_nothing if {
	not harbor.allow with input as req("/mgmt/evidence", s)
		with data.vdh.harbor.partners as {s: {"state": "member", "band": "medium", "valid_until": future}}
		with data.vdh.harbor.partner_cas as {x: ca_x}
}
