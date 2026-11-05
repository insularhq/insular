"""KeyClerk on this workstation: the pinned engine beside Keycloak: desk, reconciler, console.

One podman pod, ports on 127.0.0.1 only: Keycloak 26.8.1 (pinned by digest), the reconciler (the one writer) and the
read-only console, from one engine image built from the engine repository at the pinned commit. The realm is the demo
tenant's: SCIM switched on, an admin-only user-profile attribute "anchor" behind SCIM externalId, and four clients with
one job each: the people feed (creates people through SCIM, as a tenant IdP would), the writer
(KeyClerk's group memberships), the reader (reads memberships, markers and role mappings) and the console (a public
client with PKCE; only holders of the keyclerk-viewer realm role may look), plus the desk's public client.
The desk (keyclerk.api, ADR-0179) is the records author: it starts from instances/vdh-demo/grants.yaml as its seed,
and every change people make there becomes a revision it signs with a local demo key; the reconciler and the console
read those revisions, and the reconciler refuses them unsigned or changed. Tokens carry the person's anchor (a claim
mapped from the admin-only profile attribute). Every demo person gets a generated password, so the demo can be
walked as the root, a deputy or a member. Trust input comes from instances/vdh-demo/trust.yaml. Secrets (the
Keycloak bootstrap password, the client secrets, the signing key, the passwords) are generated into a state folder
outside the repository and never printed.

Usage: python tools/keyclerk_local.py up [--engine ../keyclerk] | status | down
       then the desk at http://localhost:8091 (sign in as any demo person: passwords in the state folder's
       people-passwords.json), the console at http://localhost:8090 (local-viewer), Keycloak at http://localhost:18080.
"""
from __future__ import annotations

import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
STATE = Path.home() / ".keyclerk-local"
POD = "keyclerk-local"
REALM = "vdh-demo"
OUTSIDE = "http://localhost:18080"     # Keycloak as this workstation sees it: a name, not an address, because a
                                       # passkey belongs to a domain and WebAuthn refuses an IP address
ADMIN = "http://127.0.0.1:18080"      # this script's own admin calls, by address: "localhost" tries IPv6 first and
                                       # waits on every call, long enough for the admin token to expire mid-setup
INSIDE = "http://localhost:8080"       # Keycloak as the containers in the pod see it
RECORDS = ROOT / "instances" / "vdh-demo" / "grants.yaml"
CONFIG = ROOT / "config" / "keyclerk" / "keyclerk.yaml"
TRUST = ROOT / "instances" / "vdh-demo" / "trust.yaml"
CONSOLE = "http://localhost:8090"
DESK = "http://localhost:8091"
MAILPIT = "docker.io/axllent/mailpit:v1.31.4@sha256:b68349e3a014b90c5610bfb26b2ae36f3892d7b8cf25ee140c6c71c98d2fcf48"
ENTRA = "entra"                                # the customer's directory as an identity provider (ADR-0181)
STANDIN = "entra-standin"                      # a stand-in for it here: a second realm, same Keycloak
BROKERED = {"hana": "6b1f3c2e-8d4a-4f7b-9e21-3c5d7a9b0e14"}   # person -> object id in the stand-in (her anchor)
WORKFLOW_STEPS_ALLOWED = {"notify-user", "disable-user", "delete-user", "add-required-action", "remove-required-action"}
OTHER_FRONT_END = "keyclerk-other-front-end"   # a front end built by someone else: bearer tokens bound by DPoP (ADR-0181)
APPROVAL_LEVEL = "approval"                    # the authentication level bound to a passkey (ADR-0181)
CLIENTS = {   # client: (realm-management roles, SCIM audience)
    "keyclerk-people-feed": (("manage-users", "view-users", "query-users"), True),
    "keyclerk-writer": (("view-users", "query-users", "query-groups"), True),   # membership only: setup_permissions
    "keyclerk-reader": (("view-users", "query-users", "query-groups", "view-events"), False),
}


def keycloak_image() -> str:
    lock = (ROOT / "platform" / "stack.lock.yaml").read_text(encoding="utf-8")
    for line in lock.splitlines():
        if line.strip().startswith("Keycloak:"):
            return "quay.io/keycloak/keycloak@" + line.split('digest: "', 1)[1].split('"', 1)[0]
    raise RuntimeError("no Keycloak pin in platform/stack.lock.yaml")


def vm_path(p: Path) -> str:
    """A Windows path as the podman WSL machine mounts it (C:\\x -> /mnt/c/x); other paths unchanged."""
    s = str(p.resolve())
    if len(s) > 1 and s[1] == ":":
        return "/mnt/" + s[0].lower() + s[2:].replace("\\", "/")
    return s


def commands(engine_version: str, engine_dir: Path) -> tuple[list[list[str]], list[list[str]]]:
    """The podman commands that bring the pod up: before the realm setup, and after it (tests check them)."""
    image = f"localhost/keyclerk:{engine_version}"
    vol = lambda src, dst: f"{vm_path(src)}:{dst}:ro,Z"   # noqa: E731
    return [
        ["podman", "pod", "create", "--name", POD, "-p", "127.0.0.1:18080:8080", "-p", "127.0.0.1:8090:8090",
         "-p", "127.0.0.1:8091:8091", "-p", "127.0.0.1:8025:8025"],
        ["podman", "run", "-d", "--pod", POD, "--name", f"{POD}-mail", MAILPIT],   # the mail sink: SMTP 1025, web 8025
        ["podman", "run", "-d", "--pod", POD, "--name", f"{POD}-keycloak", "--env-file", str(STATE / "keycloak.env"),   # read by the podman client
         keycloak_image(), "start-dev",
         "--spi-events-listener--workflow-event-listener--step-runner-task-interval=1m"],   # delayed workflow steps: each minute here (12 h by default)
        ["podman", "build", "-t", image, str(engine_dir.resolve())],   # the client sends the context
        ["podman", "volume", "create", f"{POD}-state"],
        ["podman", "volume", "create", f"{POD}-desk"],
    ], [
        ["podman", "run", "-d", "--pod", POD, "--name", f"{POD}-desk", "--read-only",
         "-v", vol(CONFIG, "/etc/keyclerk/keyclerk.yaml"), "-v", vol(RECORDS, "/etc/keyclerk/seed.yaml"),
         "-v", vol(STATE / "records-signing.key", "/run/secrets/records.key"),
         "-v", f"{POD}-desk:/var/lib/keyclerk-desk:U", "-v", f"{POD}-state:/var/lib/keyclerk:ro",
         image, "keyclerk.api", "--config", "/etc/keyclerk/keyclerk.yaml", "--store", "/var/lib/keyclerk-desk",
         "--signing-key", "/run/secrets/records.key", "--seed", "/etc/keyclerk/seed.yaml", "--broker-state", "/var/lib/keyclerk",
         "--host", "0.0.0.0", "--port", "8091", "--allowed-host", "127.0.0.1:8091", "--allowed-host", "localhost:8091",
         "--oidc-public-issuer", f"{OUTSIDE}/realms/{REALM}", "--oidc-internal-issuer", f"{INSIDE}/realms/{REALM}",
         "--oidc-client", "keyclerk-desk", "--oidc-redirect", f"{DESK}/callback",
         "--api-client", OTHER_FRONT_END, "--dpop-client", OTHER_FRONT_END],
        ["podman", "run", "-d", "--pod", POD, "--name", f"{POD}-reconciler", "--read-only",
         "-v", vol(CONFIG, "/etc/keyclerk/keyclerk.yaml"), "-v", f"{POD}-desk:/var/lib/keyclerk-desk:ro",
         "-v", vol(STATE / "records.pub", "/etc/keyclerk/records.pub"), "-v", vol(TRUST, "/etc/keyclerk/trust.yaml"),
         "-v", vol(STATE / "keyclerk-writer", "/run/secrets/writer"),
         "-v", vol(STATE / "keyclerk-reader", "/run/secrets/reader"), "-v", f"{POD}-state:/var/lib/keyclerk",
         image, "keyclerk.reconcile", "--config", "/etc/keyclerk/keyclerk.yaml",
         "--records", "/var/lib/keyclerk-desk/records.yaml", "--signing-key", "/etc/keyclerk/records.pub", "--trust", "/etc/keyclerk/trust.yaml",
         "--keycloak", INSIDE, "--realm", REALM, "--client", "keyclerk-writer", "--secret-file", "/run/secrets/writer",
         "--reader-client", "keyclerk-reader", "--reader-secret-file", "/run/secrets/reader",
         "--approval-issuer", f"{OUTSIDE}/realms/{REALM}", "--approval-audience", "keyclerk-desk",
         "--state", "/var/lib/keyclerk", "--interval", "30", "--apply"],
        ["podman", "run", "-d", "--pod", POD, "--name", f"{POD}-console", "--read-only",
         "-v", vol(CONFIG, "/etc/keyclerk/keyclerk.yaml"), "-v", f"{POD}-desk:/var/lib/keyclerk-desk:ro",
         "-v", f"{POD}-state:/var/lib/keyclerk:ro", image, "keyclerk.console", "--config", "/etc/keyclerk/keyclerk.yaml",
         "--records", "/var/lib/keyclerk-desk/records.yaml", "--state", "/var/lib/keyclerk", "--host", "0.0.0.0", "--port", "8090",
         "--allowed-host", "127.0.0.1:8090", "--allowed-host", "localhost:8090",
         "--oidc-public-issuer", f"{OUTSIDE}/realms/{REALM}", "--oidc-internal-issuer", f"{INSIDE}/realms/{REALM}",
         "--oidc-client", "keyclerk-console", "--oidc-redirect", f"{CONSOLE}/callback", "--viewer-role", "keyclerk-viewer"],
    ]


# --- Keycloak setup, through its admin API from this workstation --------------------------------------------------

def _req(method, url, body=None, tok=None, form=None):
    data = urllib.parse.urlencode(form).encode() if form else (json.dumps(body).encode() if body is not None else None)
    h = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json", "Accept": "application/json"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method=method, data=data, headers=h), timeout=30) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw[:1] in (b"{", b"[") else None
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, ConnectionError, OSError):
        return 0, None   # not up yet


def _admin_token() -> str:
    pw = (STATE / "admin-password").read_text(encoding="utf-8").strip()
    return _req("POST", f"{ADMIN}/realms/master/protocol/openid-connect/token",
                form={"grant_type": "password", "client_id": "admin-cli", "username": "local-admin", "password": pw})[1]["access_token"]


def setup_realm() -> None:
    t = _admin_token()
    A = f"{ADMIN}/admin/realms"
    _req("POST", A, {"realm": REALM, "enabled": True, "scimApiEnabled": True, "displayName": "vdh-demo (KeyClerk local)"}, t)
    up = _req("GET", f"{A}/{REALM}/users/profile", None, t)[1]
    if not any(a["name"] == "anchor" for a in up["attributes"]):
        up["attributes"].append({"name": "anchor", "displayName": "Anchor (immutable id from the source)", "multivalued": False,
                                 "permissions": {"view": ["admin"], "edit": ["admin"]},
                                 "annotations": {"kc.scim.schema.attribute": "externalId"}})
        _req("PUT", f"{A}/{REALM}/users/profile", up, t)
    realm_settings(t)
    rm = _req("GET", f"{A}/{REALM}/clients?clientId=realm-management", None, t)[1][0]["id"]
    all_roles = _req("GET", f"{A}/{REALM}/clients/{rm}/roles", None, t)[1]
    for client, (names, scim) in CLIENTS.items():
        _req("POST", f"{A}/{REALM}/clients", {"clientId": client, "publicClient": False, "serviceAccountsEnabled": True,
                                              "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                                              "fullScopeAllowed": False}, t)
        cid = _req("GET", f"{A}/{REALM}/clients?clientId={client}", None, t)[1][0]["id"]
        roles = [r for r in all_roles if r["name"] in names]
        sa = _req("GET", f"{A}/{REALM}/clients/{cid}/service-account-user", None, t)[1]["id"]
        _req("POST", f"{A}/{REALM}/users/{sa}/role-mappings/clients/{rm}", roles, t)
        _req("POST", f"{A}/{REALM}/clients/{cid}/scope-mappings/clients/{rm}", roles, t)   # full scope off: these only
        have = {m["name"] for m in _req("GET", f"{A}/{REALM}/clients/{cid}/protocol-mappers/models", None, t)[1]}
        for name, base in ((("scim-audience-pod", INSIDE), ("scim-audience-workstation", OUTSIDE)) if scim else ()):
            if name not in have:
                _req("POST", f"{A}/{REALM}/clients/{cid}/protocol-mappers/models", {
                    "name": name, "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper",
                    "config": {"included.custom.audience": f"{base}/realms/{REALM}/scim/v2", "access.token.claim": "true"}}, t)
        secret = _req("GET", f"{A}/{REALM}/clients/{cid}/client-secret", None, t)[1]["value"]
        _private(STATE / client, secret)
    setup_console(t)
    setup_permissions(t)
    setup_stepup(t)
    setup_other_front_end(t)
    setup_entra_standin(t)
    setup_client_policies(t)
    setup_workflows(t)


def workflows() -> list[dict]:
    """Keycloak Workflows for this realm (ADR-0181): reminders before a lease ends, deleting an account after the
    retention period once its lease has ended, and disabling a brokered account after inactivity (every sign-in
    restarts the clock). Never group membership: that is KeyClerk's, and the reconciler would undo it.
    Measured here: Keycloak re-checks a workflow's if-condition before every delayed step, but never the event
    that started it, so a destructive step is guarded by a condition that says the reason still holds (not a member of
    /leases:active again); a disable cannot be undone by a workflow (there is no enable step)."""
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    keep = cfg["external_access"]["steps"]["offboarding"]["retention"]["account_delete_days"]
    out = [{"name": "keyclerk-lease-retention", "on": "user-group-membership-removed(/leases:active)",
            "if": "not is-member-of(/leases:active)",           # re-checked before the delete: a renewed lease keeps it
            "steps": [{"uses": "notify-user", "with": {
                          "subject": "Your access has ended",
                          "message": f"<p>Your access has ended. Your account is deleted in {keep} days unless your access "
                                     "is renewed before then.</p>"}},
                      {"uses": "delete-user", "after": f"{keep}d"}]}]
    for d in cfg["external_access"]["steps"]["during"]["reminder_days"]:
        out.append({"name": f"keyclerk-lease-ending-{d}d", "on": f"user-group-membership-added(/leases:ending-{d}d)",
                    "steps": [{"uses": "notify-user", "with": {
                        "subject": f"Your access ends in {d} day{'s' if d != 1 else ''}",
                        "message": f"<p>Hello ${{user.firstName}},</p><p>your access ends in {d} day{'s' if d != 1 else ''}. "
                                   "If you still need it, ask the person who arranged it to renew it.</p>"}}]})
    out.append({"name": "keyclerk-brokered-inactive", "on": "user-authenticated", "if": f"has-identity-provider-link({ENTRA})",
                "concurrency": {"restart-in-progress": True},
                "steps": [{"uses": "notify-user", "after": "60d", "with": {
                              "subject": "Your account will be disabled",
                              "message": "<p>You have not signed in for 60 days; your account will be disabled in 30 days.</p>"}},
                          {"uses": "disable-user", "after": "30d"}]})
    return out


def setup_workflows(t: str) -> None:
    A = f"{ADMIN}/admin/realms/{REALM}"
    have = {w["name"]: w["id"] for w in (_req("GET", f"{A}/workflows", None, t)[1] or [])}
    for w in workflows():
        if w["name"] in have:
            _req("DELETE", f"{A}/workflows/{have[w['name']]}", None, t)
        _req("POST", f"{A}/workflows", w, t)


def setup_entra_standin(t: str) -> None:
    """Identity brokering (ADR-0181): the customer's Entra is an identity provider of the realm, and a person's anchor
    is their Entra object id (the oid claim), imported once at first sign-in and never editable by them. Here a second
    realm stands in for Entra; a real tenant needs the customer's app registration (issuer
    https://login.microsoftonline.com/<tenant>/v2.0, the same oid mapper)."""
    A = f"{ADMIN}/admin/realms"
    # one issuer however it is reached (as a real Entra has): the browser and this Keycloak use different addresses
    if _req("POST", A, {"realm": STANDIN, "enabled": True, "displayName": "Entra (stand-in)",
                        "attributes": {"frontendUrl": OUTSIDE}}, t)[0] == 201:
        _req("POST", f"{A}/{STANDIN}/clients", {"clientId": "keyclerk-broker", "publicClient": False, "standardFlowEnabled": True,
                                                "directAccessGrantsEnabled": False, "frontchannelLogout": False,
                                                "redirectUris": [f"{OUTSIDE}/realms/{REALM}/broker/{ENTRA}/endpoint"],
                                                "attributes": {"pkce.code.challenge.method": "S256"}}, t)
        cid = _req("GET", f"{A}/{STANDIN}/clients?clientId=keyclerk-broker", None, t)[1][0]["id"]
        _req("POST", f"{A}/{STANDIN}/clients/{cid}/protocol-mappers/models", {
            "name": "oid", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {"user.attribute": "oid", "claim.name": "oid", "jsonType.label": "String",
                       "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}}, t)
        up = _req("GET", f"{A}/{STANDIN}/users/profile", None, t)[1]
        up["attributes"].append({"name": "oid", "displayName": "object id", "permissions": {"view": ["admin"], "edit": ["admin"]}})
        _req("PUT", f"{A}/{STANDIN}/users/profile", up, t)
        pw = json.loads((STATE / "people-passwords.json").read_text(encoding="utf-8")) if (STATE / "people-passwords.json").exists() else {}
        for name, oid in BROKERED.items():
            pw.setdefault(name, secrets.token_urlsafe(12))
            _req("POST", f"{A}/{STANDIN}/users", {"username": name, "enabled": True, "firstName": name.capitalize(),
                                                  "lastName": "Entra", "email": f"{name}@customer.example.invalid",
                                                  "emailVerified": True, "attributes": {"oid": [oid]},
                                                  "credentials": [{"type": "password", "value": pw[name], "temporary": False}]}, t)
        _private(STATE / "people-passwords.json", json.dumps(pw, indent=1, sort_keys=True))
    cid = _req("GET", f"{A}/{STANDIN}/clients?clientId=keyclerk-broker", None, t)[1][0]["id"]
    secret = _req("GET", f"{A}/{STANDIN}/clients/{cid}/client-secret", None, t)[1]["value"]
    pub, inner = f"{OUTSIDE}/realms/{STANDIN}/protocol/openid-connect", f"{INSIDE}/realms/{STANDIN}/protocol/openid-connect"
    idp = {"alias": ENTRA, "displayName": "Your organisation (Entra)", "providerId": "oidc", "enabled": True,
           "trustEmail": False, "storeToken": False, "firstBrokerLoginFlowAlias": "first broker login",
           "config": {"authorizationUrl": f"{pub}/auth", "tokenUrl": f"{inner}/token", "jwksUrl": f"{inner}/certs",
                      "userInfoUrl": f"{inner}/userinfo", "issuer": f"{OUTSIDE}/realms/{STANDIN}", "validateSignature": "true",
                      "useJwksUrl": "true", "clientId": "keyclerk-broker", "clientSecret": secret,
                      "clientAuthMethod": "client_secret_post", "pkceEnabled": "true", "pkceMethod": "S256",
                      "defaultScope": "openid profile email", "syncMode": "IMPORT"}}
    if _req("POST", f"{A}/{REALM}/identity-provider/instances", idp, t)[0] == 409:
        _req("PUT", f"{A}/{REALM}/identity-provider/instances/{ENTRA}", idp, t)
    have = {m["name"] for m in _req("GET", f"{A}/{REALM}/identity-provider/instances/{ENTRA}/mappers", None, t)[1] or []}
    if "anchor-from-oid" not in have:   # the anchor is the object id, set once (IMPORT), admin-only in the profile
        _req("POST", f"{A}/{REALM}/identity-provider/instances/{ENTRA}/mappers", {
            "name": "anchor-from-oid", "identityProviderAlias": ENTRA, "identityProviderMapper": "oidc-user-attribute-idp-mapper",
            "config": {"claim": "oid", "user.attribute": "anchor", "syncMode": "IMPORT"}}, t)


def realm_settings(t: str) -> None:
    """Hardening and events (ADR-0181): brute-force protection, a password policy, unmanaged attributes off, user and
    admin events kept 30 days, short access tokens (a removed membership is claimed at most 5 minutes), mail to the
    pod's mail sink."""
    A = f"{ADMIN}/admin/realms/{REALM}"
    r = _req("GET", A, None, t)[1]
    r.update({"bruteForceProtected": True, "permanentLockout": False, "failureFactor": 10, "maxFailureWaitSeconds": 900,
              "passwordPolicy": "length(14) and notUsername and notEmail and maxLength(128)",
              "eventsEnabled": True, "eventsExpiration": 2592000, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True,
              "accessTokenLifespan": 300, "ssoSessionIdleTimeout": 1800, "ssoSessionMaxLifespan": 28800,
              "adminPermissionsEnabled": True,
              "smtpServer": {"host": "localhost", "port": "1025", "from": "keyclerk@example.invalid",
                             "fromDisplayName": "KeyClerk (local demo)"}})
    _req("PUT", A, r, t)
    _req("PUT", f"{A}/events/config", {"eventsEnabled": True, "adminEventsEnabled": True, "adminEventsDetailsEnabled": True,
                                       "eventsListeners": ["jboss-logging"], "eventsExpiration": 2592000}, t)
    up = _req("GET", f"{A}/users/profile", None, t)[1]
    up.pop("unmanagedAttributePolicy", None)                 # absent means disabled: no attribute outside the profile
    _req("PUT", f"{A}/users/profile", up, t)


def setup_permissions(t: str) -> None:
    """The writer manages group membership and KeyClerk's groups, and views users: fine-grained admin permissions v2
    instead of manage-users (ADR-0181). It cannot edit a person, their credentials, roles or anchor."""
    A = f"{ADMIN}/admin/realms/{REALM}"
    ap = _req("GET", f"{A}/clients?clientId=admin-permissions", None, t)[1][0]["id"]
    Z = f"{A}/clients/{ap}/authz/resource-server"
    writer = _req("GET", f"{A}/clients?clientId=keyclerk-writer", None, t)[1][0]["id"]
    _req("POST", f"{Z}/policy/client", {"name": "keyclerk-writer", "clients": [writer], "logic": "POSITIVE"}, t)
    pol = [x for x in _req("GET", f"{Z}/policy?name=keyclerk-writer", None, t)[1] if x["name"] == "keyclerk-writer"][0]["id"]
    for name, rtype, scopes in (("keyclerk-writer-groups", "Groups", ["view", "manage", "view-members", "manage-membership"]),
                                ("keyclerk-writer-users", "Users", ["view", "manage-group-membership"])):
        _req("POST", f"{Z}/permission/scope", {"name": name, "resourceType": rtype, "scopes": scopes, "policies": [pol],
                                               "decisionStrategy": "UNANIMOUS"}, t)


def setup_stepup(t: str) -> None:
    """Sign-in at level 1 (password); an approval asks for level 2 (a passkey, after the password) through the acr
    "approval" (ADR-0181, engine decision 0006). People register passkeys in the account console."""
    A = f"{ADMIN}/admin/realms/{REALM}"
    F = f"{A}/authentication"
    flow = "keyclerk-browser"
    if _req("POST", f"{F}/flows", {"alias": flow, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                                   "description": "levels of authentication: 1 password, 2 passkey"}, t)[0] == 201:
        _req("POST", f"{F}/flows/{flow}/executions/execution", {"provider": "auth-cookie"}, t)
        _req("POST", f"{F}/flows/{flow}/executions/flow", {"alias": f"{flow}-levels", "type": "basic-flow"}, t)
        for level, provider in ((1, "auth-username-password-form"), (2, "webauthn-authenticator-passwordless")):
            sub = f"{flow}-level-{level}"
            _req("POST", f"{F}/flows/{flow}-levels/executions/flow", {"alias": sub, "type": "basic-flow"}, t)
            _req("POST", f"{F}/flows/{sub}/executions/execution", {"provider": "conditional-level-of-authentication"}, t)
            _req("POST", f"{F}/flows/{sub}/executions/execution", {"provider": provider}, t)
        for e in _req("GET", f"{F}/flows/{flow}/executions", None, t)[1]:
            name, prov = e.get("displayName", ""), e.get("providerId")
            if prov == "auth-cookie" or name == f"{flow}-levels":
                req = "ALTERNATIVE"
            elif name.startswith(f"{flow}-level-"):
                req = "CONDITIONAL"
            elif prov in ("conditional-level-of-authentication", "auth-username-password-form",
                          "webauthn-authenticator-passwordless"):
                req = "REQUIRED"
            else:
                continue
            _req("PUT", f"{F}/flows/{flow}/executions", {**e, "requirement": req}, t)
        for e in _req("GET", f"{F}/flows/{flow}/executions", None, t)[1]:
            if e.get("providerId") == "conditional-level-of-authentication":
                parent = _parent_name(t, flow, e)
                level = "2" if parent.endswith("level-2") else "1"
                _req("POST", f"{F}/executions/{e['id']}/config",
                     {"alias": f"keyclerk-level-{level}", "config": {"loa-condition-level": level,
                                                                      "loa-max-age": "0" if level == "2" else "36000"}}, t)
    r = _req("GET", A, None, t)[1]
    r.update({"browserFlow": flow})
    r.setdefault("attributes", {})["acr.loa.map"] = json.dumps({APPROVAL_LEVEL: 2, "password": 1})
    _req("PUT", A, r, t)
    for ra in _req("GET", f"{F}/required-actions", None, t)[1] or []:
        if ra.get("alias") == "webauthn-register-passwordless" and not ra.get("enabled"):
            _req("PUT", f"{F}/required-actions/{ra['alias']}", {**ra, "enabled": True}, t)


def _parent_name(t: str, flow: str, execution: dict) -> str:
    """The sub-flow an execution sits in (executions list flat, in order: the nearest flow above it at a lower level)."""
    rows = _req("GET", f"{ADMIN}/admin/realms/{REALM}/authentication/flows/{flow}/executions", None, t)[1]
    i = next(k for k, r in enumerate(rows) if r["id"] == execution["id"])
    for r in reversed(rows[:i]):
        if r.get("authenticationFlow") and r.get("level", 0) == execution.get("level", 0) - 1:
            return r.get("displayName", "")
    return ""


def setup_other_front_end(t: str) -> None:
    """A front end built by someone else: a public client with PKCE whose access tokens are DPoP-bound (ADR-0181)."""
    A = f"{ADMIN}/admin/realms/{REALM}"
    _req("POST", f"{A}/clients", {"clientId": OTHER_FRONT_END, "publicClient": True, "standardFlowEnabled": True,
                                  "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "frontchannelLogout": False,
                                  "redirectUris": ["http://127.0.0.1:8099/callback"], "webOrigins": ["http://127.0.0.1:8099"],
                                  "fullScopeAllowed": False,
                                  "attributes": {"pkce.code.challenge.method": "S256", "dpop.bound.access.tokens": "true"}}, t)
    cid = _req("GET", f"{A}/clients?clientId={OTHER_FRONT_END}", None, t)[1][0]["id"]
    have = {m["name"] for m in _req("GET", f"{A}/clients/{cid}/protocol-mappers/models", None, t)[1]}
    if "anchor" not in have:
        _req("POST", f"{A}/clients/{cid}/protocol-mappers/models", {
            "name": "anchor", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
            "config": {"user.attribute": "anchor", "claim.name": "anchor", "jsonType.label": "String",
                       "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}}, t)


def setup_client_policies(t: str) -> None:
    """One policy for every client of the realm (ADR-0181): PKCE S256, no implicit grant, no password grant, no
    front-channel logout."""
    A = f"{ADMIN}/admin/realms/{REALM}"
    _req("PUT", f"{A}/client-policies/profiles", {"profiles": [{
        "name": "keyclerk-secure", "description": "KeyClerk's clients: PKCE, no implicit or password grant, back-channel logout",
        "executors": [{"executor": "pkce-enforcer", "configuration": {"auto-configure": "false"}},
                      {"executor": "reject-implicit-grant", "configuration": {"auto-configure": "false"}},
                      {"executor": "reject-ropc-grant", "configuration": {}},
                      {"executor": "secure-logout", "configuration": {"allow-front-channel-logout": "false", "auto-configure": "false"}}]}]}, t)
    _req("PUT", f"{A}/client-policies/policies", {"policies": [{
        "name": "keyclerk-all-clients", "description": "every client of the realm", "enabled": True,
        "conditions": [{"condition": "any-client", "configuration": {}}], "profiles": ["keyclerk-secure"]}]}, t)


def _private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def setup_console(t: str) -> None:
    """The console's public client (PKCE only), its viewer role, and one local viewer with a generated password."""
    A = f"{ADMIN}/admin/realms/{REALM}"
    # the broker posts a logout token to the desk and the console when a session ends: from inside the pod
    back = lambda port: {"backchannel.logout.url": f"http://localhost:{port}/backchannel-logout",   # noqa: E731
                         "backchannel.logout.session.required": "true"}
    _req("POST", f"{A}/clients", {"clientId": "keyclerk-console", "publicClient": True, "standardFlowEnabled": True,
                                  "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "frontchannelLogout": False,
                                  "redirectUris": [f"{CONSOLE}/callback"], "webOrigins": [CONSOLE],
                                  "attributes": {"pkce.code.challenge.method": "S256",
                                                 "post.logout.redirect.uris": CONSOLE, **back(8090)}}, t)
    _req("POST", f"{A}/clients", {"clientId": "keyclerk-desk", "publicClient": True, "standardFlowEnabled": True,
                                  "directAccessGrantsEnabled": False, "implicitFlowEnabled": False, "frontchannelLogout": False,
                                  "redirectUris": [f"{DESK}/callback"], "webOrigins": [DESK],
                                  "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": DESK + "/",
                                                 **back(8091)}}, t)
    for client in ("keyclerk-console", "keyclerk-desk"):
        cid = _req("GET", f"{A}/clients?clientId={client}", None, t)[1][0]["id"]
        have = {m["name"] for m in _req("GET", f"{A}/clients/{cid}/protocol-mappers/models", None, t)[1]}
        if "anchor" not in have:   # the person's anchor in the tokens: the desk acts as that person (ADR-0179)
            _req("POST", f"{A}/clients/{cid}/protocol-mappers/models", {
                "name": "anchor", "protocol": "openid-connect", "protocolMapper": "oidc-usermodel-attribute-mapper",
                "config": {"user.attribute": "anchor", "claim.name": "anchor", "jsonType.label": "String",
                           "id.token.claim": "true", "access.token.claim": "true", "userinfo.token.claim": "true"}}, t)
    _req("POST", f"{A}/roles", {"name": "keyclerk-viewer", "description": "may look at everything in KeyClerk"}, t)
    role = _req("GET", f"{A}/roles/keyclerk-viewer", None, t)[1]
    for client in ("keyclerk-console", "keyclerk-desk"):   # tokens carry only the viewer role (full scope is deprecated)
        c = _req("GET", f"{A}/clients?clientId={client}", None, t)[1][0]
        _req("PUT", f"{A}/clients/{c['id']}", {**c, "fullScopeAllowed": False}, t)
        _req("POST", f"{A}/clients/{c['id']}/scope-mappings/realm", [role], t)
    if not (STATE / "viewer-password").exists():
        _private(STATE / "viewer-password", secrets.token_urlsafe(18))
    pw = (STATE / "viewer-password").read_text(encoding="utf-8").strip()
    _req("POST", f"{A}/users", {"username": "local-viewer", "enabled": True, "firstName": "Local", "lastName": "Viewer",
                                "email": "local-viewer@example.invalid", "emailVerified": True,
                                "credentials": [{"type": "password", "value": pw, "temporary": False}]}, t)
    uid = _req("GET", f"{A}/users?username=local-viewer&exact=true", None, t)[1][0]["id"]
    _req("POST", f"{A}/users/{uid}/role-mappings/realm", [role], t)


def people_logins() -> int:
    """A generated password for every demo person (kept in the state folder, never printed), and the profile fields
    Keycloak asks for at sign-in, so the demo can be walked as any of them."""
    t = _admin_token()
    A = f"{ADMIN}/admin/realms/{REALM}"
    f = STATE / "people-passwords.json"
    pw = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    users = _req("GET", f"{A}/users?briefRepresentation=false&max=500", None, t)[1] or []
    n = 0
    for u in users:
        if not (u.get("attributes") or {}).get("anchor") or u["username"].startswith("service-account") \
                or u.get("federationLink") or u["username"] in BROKERED:
            continue
        u.update({"firstName": u.get("firstName") or u["username"].split("-")[0].capitalize(), "lastName": u.get("lastName") or "Demo",
                  "email": u.get("email") or f"{u['username']}@example.invalid", "emailVerified": True, "requiredActions": []})
        _req("PUT", f"{A}/users/{u['id']}", u, t)
        pw.setdefault(u["username"], secrets.token_urlsafe(12))
        _req("PUT", f"{A}/users/{u['id']}/reset-password", {"type": "password", "value": pw[u["username"]], "temporary": False}, t)
        n += 1
    _private(f, json.dumps(pw, indent=1, sort_keys=True))
    return n


def sign() -> None:
    """The local demo signing key (generated once, kept in the state folder): the desk gets the private half and signs
    every revision; the reconciler gets the public half. A deployment gives the desk its own key and pins the public
    half."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    STATE.mkdir(exist_ok=True)
    kf = STATE / "records-signing.key"
    if not kf.exists():
        _private(kf, Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(kf.read_text(encoding="utf-8").strip()))
    (STATE / "records.pub").write_text(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(), encoding="utf-8")


def seed_people() -> int:
    """The demo people through SCIM with their anchor as externalId, as the tenant's IdP feed would deliver them."""
    doc = yaml.safe_load(RECORDS.read_text(encoding="utf-8"))
    secret = (STATE / "keyclerk-people-feed").read_text(encoding="utf-8").strip()
    tok = _req("POST", f"{OUTSIDE}/realms/{REALM}/protocol/openid-connect/token",
               form={"grant_type": "client_credentials", "client_id": "keyclerk-people-feed", "client_secret": secret})[1]["access_token"]
    scim = f"{OUTSIDE}/realms/{REALM}/scim/v2/Users"
    # people sign in; workloads and agents do not (a workload is a service client, an agent acts by token exchange on
    # behalf of its director, engine decision 0011); an admin persona is its own login, named after its purpose
    purpose = {x["anchor"]: x["purpose"] for p in doc.get("persons", []) for x in p.get("personas") or []}
    people = {a: p["person"] + ("-" + purpose[a] if purpose.get(a, "daily") not in ("daily", "unspecified") else "")
              for p in doc.get("persons", []) if p["kind"] not in ("workload", "agent") for a in p["anchors"]}
    for ls in doc.get("leases", []):
        people.setdefault(ls["anchor"], ls["anchor"].split(":")[-1])
    for g in doc.get("grants", []):
        people.setdefault(g["subject"]["anchor"], g["subject"]["anchor"].split(":")[-1])
    made = 0
    for anchor, name in sorted(people.items()):
        if anchor in BROKERED.values():
            continue                      # arrives through the identity provider at first sign-in (ADR-0181)
        q = urllib.parse.urlencode({"filter": f'externalId eq "{anchor}"'})
        if (_req("GET", f"{scim}?{q}", None, tok)[1] or {}).get("totalResults"):
            continue
        uname = name if name not in {p for p in people.values() if list(people.values()).count(p) > 1} else f"{name}-{anchor[-4:]}"
        s, _ = _req("POST", scim, {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": uname,
                                   "name": {"givenName": name.capitalize()}, "externalId": anchor, "active": True}, tok)
        made += s == 201
    return made


def _run(cmd: list[str], check: bool = True) -> str:
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd[:4])}...: {r.stderr.strip()[:300]}")
    return (r.stdout or "").strip()


def up(engine_dir: Path) -> None:
    sys.path.insert(0, str(ROOT / "tools"))
    import keyclerk_config
    version = keyclerk_config.pinned_version()
    installed = (engine_dir / "keyclerk" / "__init__.py").read_text(encoding="utf-8")
    if f'__version__ = "{version}"' not in installed:
        raise RuntimeError(f"the engine at {engine_dir} is not the pinned {version}")
    head = _run(["git", "-C", str(engine_dir), "rev-parse", "HEAD"])
    dirty = _run(["git", "-C", str(engine_dir), "status", "--porcelain"])
    if head != keyclerk_config.pinned_commit() or dirty:
        raise RuntimeError(f"the engine at {engine_dir} is not the pinned commit with a clean tree")
    STATE.mkdir(exist_ok=True)
    if not (STATE / "admin-password").exists():
        (STATE / "admin-password").write_text(secrets.token_urlsafe(24), encoding="utf-8")
    pw = (STATE / "admin-password").read_text(encoding="utf-8").strip()
    (STATE / "keycloak.env").write_text(f"KC_BOOTSTRAP_ADMIN_USERNAME=local-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD={pw}\n", encoding="utf-8")
    first, second = commands(version, engine_dir)
    for cmd in first:
        _run(cmd)
    for _ in range(60):
        if _req("GET", f"{ADMIN}/realms/master")[0] == 200:
            break
        time.sleep(3)
    setup_realm()
    sign()
    print(f"people seeded through SCIM: {seed_people()}; sign-ins prepared: {people_logins()}")
    for cmd in second:
        _run(cmd)
    print(f"KeyClerk desk: {DESK} (any demo person, passwords in {STATE / 'people-passwords.json'})\n"
          f"KeyClerk console: {CONSOLE} (local-viewer, password in {STATE / 'viewer-password'})\n"
          f"Keycloak: {OUTSIDE} (local-admin, password in {STATE / 'admin-password'})")


def down() -> None:
    _run(["podman", "pod", "rm", "-f", POD], check=False)
    _run(["podman", "volume", "rm", "-f", f"{POD}-state"], check=False)
    _run(["podman", "volume", "rm", "-f", f"{POD}-desk"], check=False)
    # the stand-in realm lives in the Keycloak container and goes with it


def main(argv: list[str]) -> int:
    if argv[:1] == ["up"]:
        engine = Path(argv[argv.index("--engine") + 1]) if "--engine" in argv else ROOT.parent / "keyclerk"
        up(engine)
    elif argv[:1] == ["down"]:
        down()
    elif argv[:1] == ["status"]:
        print(_run(["podman", "ps", "--pod", "--filter", f"pod={POD}", "--format", "{{.Names}} {{.Status}}"], check=False))
    else:
        print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
