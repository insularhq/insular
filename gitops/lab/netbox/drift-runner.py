"""The address-drift reconciler on the Isle (Insular ADR-0171 point 5): every INTERVAL seconds it reads what
the Isle holds (nodes, services and Cilium's pools from the Kubernetes API; never pods or secrets) and what NetBox
records for the site (prefixes and addresses with the site's tag, through a view-only token), compares them with
drift.compare, and serves the counts per rule with a heartbeat on /metrics and the findings on /findings (in the ring
only; no route). It never writes. Standard library only.
"""
from __future__ import annotations

import http.server
import ipaddress
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import drift  # noqa: E402

SA = "/var/run/secrets/kubernetes.io/serviceaccount"
API = "https://kubernetes.default.svc"
NB = os.environ.get("NETBOX_URL", "http://netbox.vdh-netbox.svc.cluster.local:8080")
TOKEN_FILE = os.environ.get("TOKEN_FILE", "/token/authorization")
FLEET = ipaddress.ip_network(os.environ.get("FLEET", "fd00:0:0::/48"))
SLUG = os.environ.get("SITE_TAG", "vdh-site-1")
INTERVAL = int(os.environ.get("INTERVAL", "600"))
STATE = {"metrics": drift.metrics([], ok=False, seeded=False, now=time.time()), "findings": [], "missing": {}}
LOCK = threading.Lock()


# services that sit on a fixed address from the address plan (ADR-0075, ADR-0172), so NetBox records the address
FIXED_SERVICES = {("kube-system", "kube-dns"): "cluster-dns", ("vdh-dns", "knot"): "dns-authoritative",
                  ("vdh-dns", "resolver"): "dns-resolver"}

def get(url: str, headers: dict, ctx=None) -> dict | None:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None          # a resource kind the cluster does not have (no Cilium pools yet)
        raise


def k8s(path: str) -> dict | None:
    ctx = ssl.create_default_context(cafile=f"{SA}/ca.crt")
    token = open(f"{SA}/token", encoding="utf-8").read().strip()
    return get(API + path, {"Authorization": f"Bearer {token}"}, ctx)


def netbox(path: str) -> list[dict]:
    auth = open(TOKEN_FILE, encoding="utf-8").read().strip()
    out, url = [], f"{NB}{path}&limit=500"
    while url:
        page = get(url, {"Authorization": auth, "Accept": "application/json"})
        out += page["results"]
        url = page.get("next")
    return out


def in_fleet(a: str) -> bool:
    try:
        return ipaddress.ip_address(a) in FLEET
    except ValueError:
        return False


def observe() -> dict:
    held, pod_ranges, service_addresses, pools = {}, {}, [], {}
    for n in (k8s("/api/v1/nodes") or {}).get("items", []):
        name = n["metadata"]["name"]
        for a in n.get("status", {}).get("addresses", []):
            if a["type"] in ("InternalIP", "ExternalIP") and in_fleet(a["address"]):
                held[a["address"]] = f"node {name}"
        pod_ranges[name] = n.get("spec", {}).get("podCIDRs", [])
    for s in (k8s("/api/v1/services") or {}).get("items", []):
        ns, name = s["metadata"]["namespace"], s["metadata"]["name"]
        ips = [ip for ip in s["spec"].get("clusterIPs", []) if ip != "None"]
        service_addresses += ips
        if (ns, name) in FIXED_SERVICES:   # services on a fixed address from the plan: their address is held
            held.update({ip: FIXED_SERVICES[(ns, name)] for ip in ips if in_fleet(ip)})
        for ing in s.get("status", {}).get("loadBalancer", {}).get("ingress", []):
            if ing.get("ip") and in_fleet(ing["ip"]):
                held[ing["ip"]] = f"load balancer {ns}/{name}"
    for version in ("v2", "v2alpha1"):
        lb = k8s(f"/apis/cilium.io/{version}/ciliumloadbalancerippools")
        if lb is not None:
            for p in lb.get("items", []):
                pools[f"lb pool {p['metadata']['name']}"] = [b["cidr"] for b in p["spec"].get("blocks", []) if b.get("cidr")]
            break
    for cn in (k8s("/apis/cilium.io/v2/ciliumnodes") or {}).get("items", []):
        pools[f"cilium node {cn['metadata']['name']}"] = cn.get("spec", {}).get("ipam", {}).get("podCIDRs", [])
    return {"addresses": held, "pod_ranges": pod_ranges, "service_addresses": service_addresses, "pools": pools}


def intended() -> dict:
    prefixes = {p["description"].split(" ")[0]: p["prefix"] for p in netbox(f"/api/ipam/prefixes/?tag={SLUG}")}
    addresses = {a["address"].split("/")[0]: a["status"]["value"] for a in netbox(f"/api/ipam/ip-addresses/?tag={SLUG}")}
    return {"prefixes": prefixes, "addresses": addresses}


def run_once() -> None:
    now = time.time()
    try:
        want = intended()
        seeded = bool(want["prefixes"])
        findings, missing = drift.compare(observe(), want, STATE["missing"], now) if seeded else ([], {})
        ok = True
    except (OSError, KeyError, ValueError) as e:
        print(json.dumps({"event": "ipam_drift.run_failed", "error": type(e).__name__}), flush=True)
        findings, missing, ok, seeded = [], STATE["missing"], False, True
    with LOCK:
        STATE.update(metrics=drift.metrics(findings, ok=ok, seeded=seeded, now=now), findings=findings, missing=missing)
    print(json.dumps({"event": "ipam_drift.run", "ok": ok, "seeded": seeded,
                      "findings": {r: sum(f["rule"] == r for f in findings) for r in drift.RULES}}), flush=True)


def loop() -> None:
    while True:
        run_once()
        time.sleep(INTERVAL)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        with LOCK:
            body = {"/metrics": STATE["metrics"], "/findings": json.dumps(STATE["findings"], indent=1),
                    "/healthz": "ok"}.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Type", "text/plain; version=0.0.4" if self.path == "/metrics" else "application/json")
        self.end_headers()
        self.wfile.write((body or "").encode())


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6   # the Isles are IPv6-only


if __name__ == "__main__":
    threading.Thread(target=loop, daemon=True).start()
    Server(("::", int(os.environ.get("PORT", "9102"))), Handler).serve_forever()
