"""NetBox's own keys, generated once inside the ring (Insular ADR-0171 point 2): Django's secret key, the
API token pepper and the cache's password, into the Secret netbox-keys, created when absent and never printed or
changed afterwards (a new pepper would void every token). Standard library only; runs as a CronJob so a new ring gets
its keys before NetBox starts. Usage: python3 /app/keys.py
"""
from __future__ import annotations

import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.request

# the token directory: the automounted default, or where the sa-token template puts it (SA_DIR)
SA = os.environ.get("SA_DIR", "/var/run/secrets/kubernetes.io/serviceaccount")
API = "https://kubernetes.default.svc"
NAME = "netbox-keys"


def k8s(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    token = open(f"{SA}/token", encoding="utf-8").read().strip()
    req = urllib.request.Request(API + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def main() -> int:
    ns = open(f"{SA}/namespace", encoding="utf-8").read().strip()
    status, _ = k8s("GET", f"/api/v1/namespaces/{ns}/secrets/{NAME}")
    if status == 200:
        print(f"{NAME}: present, unchanged")
        return 0
    if status != 404:
        print(f"{NAME}: the API answered {status}; nothing done")
        return 1
    data = {"secret_key": secrets.token_urlsafe(64), "api_token_pepper_1": secrets.token_urlsafe(64),
            "valkey_password": secrets.token_urlsafe(32)}
    status, _ = k8s("POST", f"/api/v1/namespaces/{ns}/secrets",
                    {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": NAME}, "type": "Opaque", "stringData": data})
    print(f"{NAME}: {'created' if status == 201 else f'not created ({status})'}")
    return 0 if status == 201 else 1


if __name__ == "__main__":
    sys.exit(main())
