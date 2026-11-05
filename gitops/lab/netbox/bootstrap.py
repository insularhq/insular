# NetBox's service accounts and their tokens (Insular ADR-0171 points 2, 3 and 5), run inside the NetBox
# image through Django's shell (manage.py shell --command). No superuser, no staff, no password: pipeline-dcim may
# view, add and change the site's IPAM (never delete), ipam-drift may only view it. Each account holds one managed
# token, version 2 (hashed with the pepper), expiring after 14 days and replaced when fewer than 7 remain (trust is a
# lease); the Authorization header goes into a Secret per account through the Kubernetes API and is never printed.
import json
import ssl
import urllib.error
import urllib.request
from datetime import timedelta

from core.models import ObjectType
from django.utils import timezone
from users.models import ObjectPermission, Token, User

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
API = "https://kubernetes.default.svc"
MANAGED = "vdh-managed"
ACCOUNTS = {
    "pipeline-dcim": {"secret": "netbox-token-pipeline-dcim", "write": True,
                      "perms": [("ipam", "prefix", ["view", "add", "change"]), ("ipam", "ipaddress", ["view", "add", "change"]),
                                ("extras", "tag", ["view", "add"])]},
    "ipam-drift": {"secret": "netbox-token-ipam-drift", "write": False,
                   "perms": [("ipam", "prefix", ["view"]), ("ipam", "ipaddress", ["view"])]},
}


def k8s(method, path, body=None):
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    token = open(f"{SA}/token", encoding="utf-8").read().strip()
    req = urllib.request.Request(API + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def put_secret(ns, name, header):
    body = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name}, "type": "Opaque",
            "stringData": {"authorization": header}}
    if k8s("GET", f"/api/v1/namespaces/{ns}/secrets/{name}") == 404:
        return k8s("POST", f"/api/v1/namespaces/{ns}/secrets", body)
    return k8s("PUT", f"/api/v1/namespaces/{ns}/secrets/{name}", body)


def run():
    ns = open(f"{SA}/namespace", encoding="utf-8").read().strip()
    for name, a in ACCOUNTS.items():
        u, _ = User.objects.get_or_create(username=name)
        u.is_superuser, u.is_staff, u.is_active = False, False, True
        u.set_unusable_password()
        u.save()
        for app, model, actions in a["perms"]:
            p, _ = ObjectPermission.objects.get_or_create(name=f"{name}: {app}.{model}", defaults={"actions": actions})
            p.actions, p.enabled, p.constraints = actions, True, None
            p.save()
            p.object_types.set([ObjectType.objects.get(app_label=app, model=model)])
            p.users.set([u])
        managed = Token.objects.filter(user=u, description=MANAGED)
        fresh = [t for t in managed if t.expires and t.expires > timezone.now() + timedelta(days=7)]
        if fresh and k8s("GET", f"/api/v1/namespaces/{ns}/secrets/{a['secret']}") == 200:
            print(f"{name}: token valid until {fresh[0].expires:%Y-%m-%d}, unchanged")
            continue
        t = Token(user=u, version=2, write_enabled=a["write"], expires=timezone.now() + timedelta(days=14), description=MANAGED)
        t.full_clean()
        t.save()
        status = put_secret(ns, a["secret"], t.get_auth_header_prefix() + t.token)
        if status in (200, 201):
            managed.exclude(pk=t.pk).delete()
            print(f"{name}: new token until {t.expires:%Y-%m-%d}, written to {a['secret']}")
        else:
            t.delete()
            print(f"{name}: the Secret could not be written ({status}); the new token was removed")


run()
