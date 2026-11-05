# Unit tests for the operator pane rule (ADR-0115): only a verified pharos-operator token for the pane's
# client reaches the pane; forged context headers never stand in for a sign-in. Throwaway test keys, generated for
# these tests only.
package vdh.authz_pane_test

import rego.v1

import data.vdh.authz

good_key := {"kty": "RSA", "kid": "good", "alg": "RS256", "n": "yVfTdAybUPNK0g1kpgkKb5gL85czsP35dsrZMQry51ItvKq45InNAuwTlhh892e7dyurJ3PvqRZeWXZyxqaLOTIZjI6gW2Dr9t61iCZJdfVHnghcQgSh-eCGqzsY-3egmP2f6n9VCt19Y7if3_VKoPcMyN6MLdAQtmBmp5961dizHvTXzPPLrT-o1WSWWQUjwrvdnTTbQvO3yyRgvtPTkQ9SaraGjeQNdeBTWetmFa9jUSkDv6j35KY0MC_-UDrTR2fyjNX5B50DRgBouFJQgZqbgjY1PgjbgrLyR0CjAtZr6E0c7QpRmKfl3pKZev5LvHW7AfkFStFDIpBvKMjdTw", "e": "AQAB", "d": "ExR2DtjE_SpZDEfFonBX41RayZYqCVtAATBe3aVmeGJSwD7Db7DZUy4Q-xfN-9oCK1xhh0cWzoS2oy602LtelSh4wFehvZcVNVtMg57xNjLsuv6a04zB1r6etGpQxz_CYc0jEuNHKVTs9X7A88W4cUGIHh7s1MiTVN0UzUyxJMONjRBQEfw_8tH0ceV-w3XPJDrAQZlN8A_AfSC6XgFj-OUpQUMOD5_lkZBQp7WZbrUWyWvOq7McyDgWJNUm6TowLnV9OPJAYZyODXi591LTFlQ8uutl_sFWLxECOUYHDGbqJQCIml00UGHeYAJ0UA63zD9IqszN0xRBix4LSCNFRQ", "p": "_Ee2SQOVf547Bu8cnLkBXg6UEEcGGEVUCTtlBYl5ZaNx3qDMtzPh_fjKec13ac3OO_77yCwEareIy1vuIwyOyNDnOp2CvRMhCMtYXOxu0BNaXQUYyj2Z2DkASg9byHQKm8haABxeGoYY47DWkRZSb9QYDM-SYuEJHDCR-SsrAJM", "q": "zE_XMRnGwKsqVpiFaF2ljwClAo77ZkAFrhJjEFJcorhKctgEwT8s3CuzQw0x4e2gVacGdgbyC_o7y26THNnlZylp1WkCWJabcYsiFPyO4TCChjS59NY1zSDMl-yyh-SZIWT8lsUuHT6IjAEkFKfmlWbD6S4S7lihe3PbCTkN8dU", "dp": "sF2R2clfojAEI_zVi9rqUc7vQ9HjOOR-s1WKciyBacSxvmm7s_fZbauYIT661ITEQL0pV-8tx003nLNP78C_sTQZ8qha1cOhvHwr8gp4DY76BT2i7v_RpY9z3FKQX7qAEBgokxtBzlkg3UyrNBLe3r7vcUVLmUSpEcQCyKadEXE", "dq": "HaglO2pbcFIoNiOzkb-uLYDRcvqgQWpfqLHgkVjzO2d23w6-OfLapybswXnj2MCuemBhTraZYeWz0ka9sf1rEDtxslmozoUmESg6DUPP1Z4-BA8ZQxHpA1qUeCUSkSk8lR1ckOIUXIhcN75ep2Tr0pn1LB7U_qX84rehfsg6XvU", "qi": "liX2fyjo2PCQ-jWnNR1NCWZgHozPkGPSr9Q3o5RC6Bdc2JXQB3XMHP4OUSXdlLv8loKO4yXuyN9HQX7Nvv1kirBYzVxk88MGKCbYSTYvaWEXTeNs1FHCR0Rq4lifINWJ0rYq5WMgIKeBT84WsZ9eJ0GNG61lfxj3AH4Z0MnmKGs"}

evil_key := {"kty": "RSA", "kid": "evil", "alg": "RS256", "n": "2dhszOotnu_Ix6Mpx53MHDqXopx5o9rAUho_CWHprTcQ3iXQQ_N83ufC0tc4PFJ1Gi6TrdCoiV5wGBNSeGRTzwj0hfEtXTrLX1aT1EpPOcvhwHDR5o9SjY9-drMd8GDmBEnCop5er3XL-cJVtkKNrvLowV75vakDz5AwYw0t2dVCtfWmtknriqGXpuatARFmD3NuruVJSLcQ25pbpoExd5yohC8CD-L9hqMri4DonSTwvBBC7Z39sEwLRsa81LnZ3V4DfuMJBuJl3n-xGnKn77u6RR7DxjqKM5v0GEdHm80s_HqxMQR_SUrUVHnJ82Ld9eWOQQt8XL4VfIVBYXU5sw", "e": "AQAB", "d": "A1egN7aiE42vQWzd77uajZZSjEKlVR--kqPncq_nY2p0XkwrOVerg0oAAbcenEJRnKC5UFHivBTQWHY3bjRv2r3S7pkoLoV_6EsOQpQPSh44LPkuJ0DsrdJVSOHvpCgAb3FoRJF0d3GxuvfB0-WKgfQlIQ5he4jzz4PxUhu6J9zoAQ9MADYcporOZsLMbxQGAksRjNa0W1UYLeoHupLgjj3az03LxTag9JE_quExyKJYC093OBYp989kt1UaoKQBATJs0Q9rN3DZ9w8U0tZ9cXHdeGtyWDagzxGjxb7Z3qTjPW69gvG4fl4OoNw3a04nt63SKfkb-LMSBOzP2Rq24Q", "p": "_RuOCX4h35xF-8FdyqZIpdkbaXjgEpqcwATpdjcbrMvn-PnHwXKISg2_wwCDkyMLReFGeWQTJcWQpBHnd6XaC8WqHSLMdB46GWL6ribzyXhGCH_qsPIFIX3sAgHEwpf6JyWPw7Em5zaIJyfT4LZKwZBYlNw0XEfJtw4-C2KvItM", "q": "3FW2puRdSwhWiAVPCluvpotcQtkG0Zg4Om6Boa9mwiBV1ZAa2oSOeBm-TeeSXER5epGWmu6l8cPw3MYqxO4LjyfCqcTLyUPJa7GcNcOtpNEAF0h4fltH3KE0gVRYm82Hb6vlNqZg2yNL6CKhgwLmNB3e_sr-F9smV47IWcmsgaE", "dp": "WJd7eNEgVB9j04HULWlUhlBequU3MOvTL9bITKtvUWUxtdDf3VMUZy82zq9wXmDmwjfergCcPx1Oyk7GAPgZQQOXzojunTozRc2CRtC1hfBGOxVi9TpRF27226D42M_PLEKWdn2cS1OoBmSHYeEMe4Hlr30ACsjJzvv6NYv-Fyc", "dq": "EcPHakVXUEln0Ke867TgwKjT03_0EMoZHnzybrrZqiU5RnLL93pgkkZhFZ7qKg5LTRqX7f332zpVHTfNEvuuauhlxZJca-nPP6OeWKdiRLulKjtpm6Z4cM1-kj7ethEoLlTJslJP1NtPr3O7WfjN3r3Z0OlE-19sA_s7JCIiioE", "qi": "nY-AdsDYav0suokZyIstGHzCQnrQgOCrw7SltFd1O4HKK4IX4CTrPXHfZHfFGyTxoPi2r0T42daOBE7H67JQoA7HNM-esEedkM5yMdwH-CVJRrxPn3YCjTp6Pz1nX2BUXJYQxy-HsrGMZmYmeA-acQjZcZqieD8BZABRgfPYJks"}

jwks := "{\"keys\": [{\"kty\": \"RSA\", \"kid\": \"good\", \"alg\": \"RS256\", \"use\": \"sig\", \"n\": \"yVfTdAybUPNK0g1kpgkKb5gL85czsP35dsrZMQry51ItvKq45InNAuwTlhh892e7dyurJ3PvqRZeWXZyxqaLOTIZjI6gW2Dr9t61iCZJdfVHnghcQgSh-eCGqzsY-3egmP2f6n9VCt19Y7if3_VKoPcMyN6MLdAQtmBmp5961dizHvTXzPPLrT-o1WSWWQUjwrvdnTTbQvO3yyRgvtPTkQ9SaraGjeQNdeBTWetmFa9jUSkDv6j35KY0MC_-UDrTR2fyjNX5B50DRgBouFJQgZqbgjY1PgjbgrLyR0CjAtZr6E0c7QpRmKfl3pKZev5LvHW7AfkFStFDIpBvKMjdTw\", \"e\": \"AQAB\"}]}"

now := time.now_ns()

claims(over) := object.union(
	{
		"iss": "https://id.lab.vdh.test/realms/vdh",
		"azp": "pharos",
		"aud": ["pharos", "account"],
		"exp": (now / 1000000000) + 300,
		"realm_access": {"roles": ["pharos-operator"]},
	},
	over,
)

token(key, over) := io.jwt.encode_sign({"alg": "RS256", "kid": key.kid}, claims(over), key)

mock_send(_) := {"status_code": 200, "raw_body": jwks}

check(host, h) := a if {
	a := authz.allow with input as {"attributes": {"request": {"http": {"host": host, "headers": h}}}}
		with http.send as mock_send
}

bearer(t) := {"authorization": concat(" ", ["Bearer", t])}

test_operator_reaches_the_pane if {
	check("pharos.lab.vdh.test", bearer(token(good_key, {})))
}

test_operator_reaches_the_pane_on_another_port if {
	check("pharos.lab.vdh.test:8443", bearer(token(good_key, {})))
}

test_other_view_role_is_refused if {
	not check("pharos.lab.vdh.test", bearer(token(good_key, {"realm_access": {"roles": ["pharos-auditor"]}})))
}

test_other_client_is_refused if {
	not check("pharos.lab.vdh.test", bearer(token(good_key, {"azp": "netbird"})))
}

test_other_issuer_is_refused if {
	not check("pharos.lab.vdh.test", bearer(token(good_key, {"iss": "https://evil.example/realms/vdh"})))
}

test_expired_token_is_refused if {
	not check("pharos.lab.vdh.test", bearer(token(good_key, {"exp": (now / 1000000000) - 60})))
}

test_token_signed_by_another_key_is_refused if {
	not check("pharos.lab.vdh.test", bearer(token(evil_key, {})))
}

test_no_token_is_refused if {
	not check("pharos.lab.vdh.test", {})
}

test_forged_data_ring_headers_never_open_the_pane if {
	not check("pharos.lab.vdh.test", {"x-vdh-label": "Public", "x-vdh-reader-ring": "host", "x-vdh-day": "2026-10-10"})
}

test_keys_unreachable_refuses if {
	not authz.allow with input as {"attributes": {"request": {"http": {"host": "pharos.lab.vdh.test", "headers": bearer(token(good_key, {}))}}}}
		with http.send as {"status_code": 503, "raw_body": ""}
}

keycloak_jwks := json.marshal({"keys": array.concat(
	json.unmarshal(jwks).keys,
	[object.union(evil_key_public, {"use": "enc", "alg": "RSA-OAEP", "kid": "enc"})],
)})

evil_key_public := {k: v | some k, v in evil_key; k in {"kty", "n", "e"}}

test_keycloak_key_set_with_an_encryption_key_still_verifies if {
	authz.allow with input as {"attributes": {"request": {"http": {"host": "pharos.lab.vdh.test", "headers": bearer(token(good_key, {}))}}}}
		with http.send as {"status_code": 200, "raw_body": keycloak_jwks}
}

test_token_addressed_only_to_account_is_refused if {
	not check("pharos.lab.vdh.test", bearer(token(good_key, {"aud": "account"})))
}

test_token_without_audience_is_refused if {
	not check("pharos.lab.vdh.test", bearer(token(good_key, {"aud": []})))
}

test_operator_reaches_netbox if {
	check("netbox.lab.vdh.test", bearer(token(good_key, {})))
}

test_netbox_refuses_another_role if {
	not check("netbox.lab.vdh.test", bearer(token(good_key, {"realm_access": {"roles": ["viewer"]}})))
}

test_netbox_refuses_no_token if {
	not check("netbox.lab.vdh.test", {})
}

test_forged_data_ring_headers_never_open_netbox if {
	not check("netbox.lab.vdh.test", {"x-vdh-label": "Public", "x-vdh-reader-ring": "host", "x-vdh-day": "2026-10-10"})
}
