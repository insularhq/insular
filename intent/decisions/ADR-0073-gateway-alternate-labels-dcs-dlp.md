# ADR-0073: kgateway as the gateway alternate; the gateway's part in labelling, DCS and DLP

- Status: accepted
- Date: 2026-10-08
- Decider: maintainer

## Decision
kgateway is the ready-to-swap alternate for Envoy Gateway: CNCF, the same Envoy data plane (OPA ext_authz, Coraza as
Wasm and rate limits carry over), official Gateway API conformance reports v1.3 to v1.6. Traefik moves to hold (the
heaviest advisory record measured; OIDC and JWT mostly commercial); APISIX stays on the radar as the data-plane
diversity option (no published Gateway API conformance). Accepted trade-off: kgateway shares Envoy's vulnerabilities;
the answer to an Envoy-wide flaw is the 72-hour patch SLA, not a gateway swap during an incident.

The ingress contract gains the gateway's labelling and data-centric duties: label cells with a high-water mark,
obligation headers from the authorisation decision to the backend, bounded request metadata or body for label
decisions, decision logs with labels, per-label TLS profiles, and key-release requests through the focal point. Heavy
DLP is explicitly not in the gateway: inline content inspection would break end-to-end encryption, add latency and
make the gateway the fat single point the model forbids (no payload transformation); it lives where data crosses a
label boundary: the release gateway, ai-egress-gate's leak gate and the egress perimeters.

## Consequence for sovereignty
Traefik (French origin) was the only European exit for ingress; with kgateway as the alternate, Envoy Gateway and
cert-manager become accepted neutral-foundation sovereignty gaps (catalog/provenance.yaml), contained by Gateway API
conformance and route generation from CALM.
