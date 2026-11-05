# ADR-0040: The reconnect pipeline

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
The target loop is centralised policy, decentralised policy caching, distributed DDIL enforcement
at all layers, automated drift detection, trust analysis, risk visualisation and gated risk approval; on reconnect
re-profiling and visualisation, drift, risk, then reconciliation, quarantine or destruction.

## Decision
The pieces existed (control plane and signed bundles, bounded edge caches, local OPA per cell and site, firewall and
deviation drift, the green light and signed federation, decision cards, the autonomy matrix, the return classes);
`tools/rejoin.py` joins them into one pipeline:
1. **re-profile**: attestation, unexpected and missing components, policy bundle version, cache ages;
2. **drift**: observed flows outside the allowed set, configuration differences;
3. **risk**: critical when stale or unattested; otherwise points for drift, break-glass, unexpected software, stale
   caches, an outdated bundle and a long absence (low, medium, high);
4. **visualisation**: a plain-language card for the risk owner;
5. **decision**: low reconciles autonomously; medium quarantines then reconciles gated; high quarantines and the risk
   owner decides; critical destroys and rebuilds from the signed image with the external authority.
Hardened on the way: a last-seen time in the future or unparseable counts as infinitely absent (NET-07); one malformed
or unknown-state child report turns that child RED instead of crashing the fleet light (NET-06).
