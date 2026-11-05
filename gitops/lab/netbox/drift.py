"""Address drift on an Isle (Insular ADR-0171 point 5): compares the addresses the Isle holds with what
NetBox records for the site, by record class, and turns each difference into a finding. Read-only: it reads nodes,
services and Cilium's pools from the Kubernetes API (never pods or secrets) and the site's IPAM objects from NetBox's
REST API with a site-scoped read token; it never writes. Standard library only.

Record classes (ADR-0171 table):
  per address    node addresses, load-balancer addresses in use, the NAT64 translator, the cluster resolver
  prefixes only  the pod range, each node's pod range, the service range (pods and services churn: never per address)

Rules:
  unrecorded-address   a per-address-class address the Isle holds and NetBox does not record
  outside-prefix       an address the Isle holds outside every prefix NetBox records for the site
  recorded-not-held    an address NetBox records active that nobody held in two consecutive runs past the grace window
  pod-range-outside    a node's pod range outside the site's pod prefix
  service-outside      a service address outside the site's service prefix
  pool-disagrees       a Cilium pool range outside the site's pod or load-balancer prefix
"""
from __future__ import annotations

import ipaddress
import json
import time

RULES = ("unrecorded-address", "outside-prefix", "recorded-not-held", "pod-range-outside", "service-outside", "pool-disagrees")
GRACE_SECONDS = 900   # rollouts and reboots: an address may be away this long before "held by nobody" counts


def _net(s: str):
    return ipaddress.ip_network(s, strict=False)


def _addr(s: str):
    return ipaddress.ip_address(s.split("/")[0])


def compare(observed: dict, intended: dict, previous_missing: dict | None = None, now: float | None = None) -> tuple[list[dict], dict]:
    """observed: {"addresses": {addr: source}, "pod_ranges": {node: [cidr]}, "service_addresses": [addr], "pools": {name: [cidr]}}
    intended: {"prefixes": {role: cidr}, "addresses": {addr: status}} (roles: nodes, lb_pool, pods, services, ...)
    previous_missing: {addr: first_missing_ts} from the last run. Returns (findings, missing to carry to the next run)."""
    now = time.time() if now is None else now
    previous_missing = previous_missing or {}
    findings = []
    prefixes = {role: _net(c) for role, c in intended["prefixes"].items()}
    recorded = {str(_addr(a)): st for a, st in intended["addresses"].items()}
    held = {str(_addr(a)): src for a, src in observed["addresses"].items()}

    def finding(rule, obj, evidence):
        findings.append({"rule": rule, "object": obj, "evidence": evidence})

    for a, src in sorted(held.items()):
        ip = ipaddress.ip_address(a)
        if not any(ip in n for n in prefixes.values()):
            finding("outside-prefix", a, f"held by {src}; in no prefix recorded for the site")
        elif a not in recorded:
            finding("unrecorded-address", a, f"held by {src}; no record in NetBox")
    missing = {}
    for a, st in sorted(recorded.items()):
        if st != "active" or a in held:
            continue
        first = previous_missing.get(a, now)
        missing[a] = first
        if a in previous_missing and now - first >= GRACE_SECONDS:
            finding("recorded-not-held", a, f"recorded active; held by nobody for {int(now - first)} s over two runs")
    pods = prefixes.get("pods")
    for node, cidrs in sorted(observed.get("pod_ranges", {}).items()):
        for c in cidrs:
            if _net(c).version == 6 and (pods is None or not _net(c).subnet_of(pods)):
                finding("pod-range-outside", node, f"pod range {c} outside the site's pod prefix {pods}")
    svc = prefixes.get("services")
    for a in sorted(set(observed.get("service_addresses", []))):
        ip = _addr(a)
        if ip.version == 6 and (svc is None or ip not in svc):
            finding("service-outside", a, f"service address outside the site's service prefix {svc}")
    allowed = [p for r, p in prefixes.items() if r in ("pods", "lb_pool")]
    for name, cidrs in sorted(observed.get("pools", {}).items()):
        for c in cidrs:
            n = _net(c)
            if n.version == 6 and not any(n.subnet_of(p) for p in allowed if p.version == 6):
                finding("pool-disagrees", name, f"Cilium pool {c} outside the site's pod and load-balancer prefixes")
    return findings, missing


def metrics(findings: list[dict], ok: bool, seeded: bool, now: float) -> str:
    """Counts per rule plus a heartbeat; an unseeded site or a failed run exports no counts (the NOC reads unknown)."""
    out = ["# HELP vdh_ipam_drift_run_timestamp_seconds when the reconciler last finished a run",
           "# TYPE vdh_ipam_drift_run_timestamp_seconds gauge",
           f'vdh_ipam_drift_run_timestamp_seconds{{outcome="{"ok" if ok and seeded else ("unseeded" if ok else "failed")}"}} {now:.0f}']
    if ok and seeded:
        out += ["# HELP vdh_ipam_drift_findings address drift findings per rule (ADR-0171)", "# TYPE vdh_ipam_drift_findings gauge"]
        out += [f'vdh_ipam_drift_findings{{rule="{r}"}} {sum(1 for f in findings if f["rule"] == r)}' for r in RULES]
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    import sys
    data = json.load(sys.stdin)
    f, m = compare(data["observed"], data["intended"], data.get("previous_missing"))
    print(json.dumps({"findings": f, "missing": m}, indent=1))
