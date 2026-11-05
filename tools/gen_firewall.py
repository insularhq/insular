"""Site firewall as the aggregate of all application intents (CALM 'connects').

For every host, the inbound allow-list is the union of the flows whose destination runs on that host;
everything else is denied. Output: an Aerleon policy (YAML) per host, an nftables preview, and a drift
check against an observed ruleset (rules present on the host that no CALM relationship explains).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from model import Flow, flows, host_of, interface, load_calm, nodes  # noqa: E402


def source_address(calm: dict, node_id: str) -> str:
    """Where traffic from a node comes from, as seen by the destination host."""
    ns = nodes(calm)
    n = ns[node_id]
    if n["node-type"] == "actor":
        return "ANY"
    host = host_of(calm, node_id) or node_id
    for iid in ("private-ip", "public-ip"):
        try:
            return interface(ns[host], iid)["host"]
        except KeyError:
            continue
    peers = _sdn().get("addresses", {}).get("wireguard_peers", {})
    if host in peers:
        return peers[host].split("/")[0]
    raise ValueError(f"source {node_id} (on {host}) has no address: declare it in CALM or platform/sdn.yaml")


def _sdn() -> dict:
    import yaml as _yaml
    from pathlib import Path as _P
    p = _P(__file__).resolve().parent.parent / "platform" / "sdn.yaml"
    return _yaml.safe_load(p.read_text(encoding="utf-8")) if p.exists() else {}


def host_rules(calm: dict) -> dict[str, list[dict]]:
    rules: dict[str, list[dict]] = defaultdict(list)
    for f in flows(calm):
        host = host_of(calm, f.dst)
        if not host:
            continue  # destination not placed on a modelled host (e.g. an external system)
        rules[host].append({"rel": f.rel_id, "src": source_address(calm, f.src), "dport": f.port, "proto": f.proto,
                            "from": f.src, "to": f.dst})
    return {h: sorted(r, key=lambda x: (x["dport"], x["src"])) for h, r in rules.items()}


def aerleon_policy(host: str, rules: list[dict]) -> dict:
    """Aerleon YAML policy: one term per CALM relationship, then a final deny."""
    terms = []
    for r in rules:
        term = {"name": f"{r['rel']}-{r['dport']}", "comment": f"CALM {r['rel']}: {r['from']} -> {r['to']}",
                "protocol": r["proto"], "destination-port": f"PORT_{r['dport']}", "action": "accept"}
        if r["src"] != "ANY":
            term["source-address"] = f"HOST_{r['src'].replace('.', '_')}"
        terms.append(term)
    terms.append({"name": "default-deny", "action": "deny"})
    return {"filters": [{"header": {"targets": {"nftables": "inet input"}, "comment": f"{host}: generated from CALM"},
                         "terms": terms}]}


def nft_preview(host: str, rules: list[dict]) -> str:
    lines = [f"# {host}: generated from CALM, do not edit. Host services only: pod traffic is enforced by Cilium,",
             "# VM traffic by the Proxmox firewall (platform/sdn.yaml).", "table inet vdh_calm {", "  chain input {",
             "    type filter hook input priority 0; policy drop;", "    ct state established,related accept",
             "    iif lo accept",
             "    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, packet-too-big } accept",
             "    icmp type echo-request limit rate 5/second accept",
             "    udp dport 51820 accept comment \"wireguard (baseline)\""]
    for r in rules:
        fam = "ip6" if ":" in r["src"] else "ip"
        src = "" if r["src"] == "ANY" else f"{fam} saddr {r['src']} "
        lines.append(f"    {src}{r['proto']} dport {r['dport']} accept comment \"{r['rel']}\"")
    lines += ["  }", "  chain output {", "    type filter hook output priority 0; policy accept;",
              "    # host egress allow-listing is not generated here; pod egress is Cilium FQDN policy", "  }", "}"]
    return "\n".join(lines) + "\n"


def drift(expected: list[dict], observed: list[dict]) -> dict:
    """Compare (src, proto, dport) sets. 'unexplained' = open on the host but in no CALM relationship."""
    key = lambda r: (r.get("src", "ANY"), r["proto"], int(r["dport"]))
    exp, obs = {key(r) for r in expected}, {key(r) for r in observed}
    return {"unexplained": sorted(obs - exp), "missing": sorted(exp - obs), "in_sync": obs == exp}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("build/firewall"))
    ap.add_argument("--observed", type=Path, help="JSON list of observed rules {src, proto, dport} for one host")
    ap.add_argument("--host", default="hub")
    a = ap.parse_args(argv)
    calm = load_calm()
    rules = host_rules(calm)
    a.out.mkdir(parents=True, exist_ok=True)
    for host, rs in rules.items():
        (a.out / f"{host}.aerleon.yaml").write_text(yaml.safe_dump(aerleon_policy(host, rs), sort_keys=False), encoding="utf-8")
        (a.out / f"{host}.nft").write_text(nft_preview(host, rs), encoding="utf-8")
        print(f"{host}: {len(rs)} allow rules")
    if a.observed:
        d = drift(rules.get(a.host, []), json.loads(a.observed.read_text(encoding="utf-8")))
        print(json.dumps(d, indent=2))
        return 0 if d["in_sync"] else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
