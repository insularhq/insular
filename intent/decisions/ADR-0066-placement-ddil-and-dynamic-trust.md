# ADR-0066: Placement with DDIL, buffer, federation and reconcile models; dynamic trust next to risk

- Status: accepted
- Date: 2026-10-08
- Decider: maintainer

## Decision
platform/placement.yaml now places all 77 runtime components on the tiers VDHome core, tenant instance, DRP site
(new), edge site and endpoint, each with its behaviour when cut off (works, degraded, stops), buffer (queue, cache,
journal, none), federation (independent, leaf, mirror, replica, central), reconciliation after the cut (auto, gated
by the reconnect pipeline, rebuild, none) and DRP role (warm standby, replica, snapshot, backup copy, cold). GitOps and
ITSM gain their DRP-site placement. The edge essentials (identity, policy, secrets, network, reconciliation) are tested
to keep working in isolation.

platform/adaptive-policy.yaml and tools/adaptive.py add trust beside risk: twelve sensors (attested or self-reported)
publish signed CAEP-shaped events on NATS; the evaluator keeps the latest timestamped value; trust is computed from
evidence quality (attested, signed, fresh, strong identity), with self-reported evidence capped at medium and stale
evidence at low; each path names a minimum trust and a worst risk band, and both must hold. Continuous-access events
(session revoked, credential change, device compliance, assurance, persona status, world state, egress incident,
unknown seam) re-evaluate open sessions at once; unknown events are anomalies.
