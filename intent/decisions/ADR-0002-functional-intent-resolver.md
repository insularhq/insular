# ADR-0002: Applications are declared as functional intent and compiled through architect patterns

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
Writing ports, CIDRs and protocols per application requires a technical analysis by the app owner and lets mistakes
or over-permissive rules in. The aim is to move to intent: the owner states that the application should work, following a
policy designed by the security architect, with only the protocols the wanted functions need.

## Decision
App owners write `intent/apps/<app>.yaml` with functions, data label, users and DDIL class only. The security
architect owns `catalog/patterns.yaml` (function -> flows, controls, exposure) and the vetted component list. The
deterministic resolver `tools/resolve.py` compiles intent + patterns + label rules + isolation floors into flows,
controls and a runtime class, and refuses technical fields, unknown functions, missing prerequisites and exposures
the label forbids. An LLM may draft an intent; only the resolver produces configuration.

## Consequences
- New functionality that has no pattern is a request to the security architect, not an app-owner workaround.
- The hand-written CALM flows become generated output step by step; the first equivalence (vault/CryptPad) is tested.
- Prior art used: Score and Radius (developer intent + platform-owned recipes), Kratix and Crossplane (platform
  promises and compositions), RFC 9315/9316 (intent-based networking), FINOS CALM (architecture as code).

## Amendment (2026-10-25): toward a workload manifest
The app intent above is to grow into a workload manifest, the one declaration a
tenant workload is admitted on in any ring: its enforcement points and policy roots, audit shape, telemetry, signer
and provenance, data classes, egress, owner and lifecycle. The decision itself is
taken when the OpenCloud work (ADR-0137) starts, after a prior-art review and an adversarial review. Two constraints are already
set: it builds on public standards (CALM stays the architecture backbone; contents and evidence in CycloneDX, SPDX,
in-toto and SLSA; ownership in the service-catalogue vocabulary; OpenTofu is a generated output and its plan and state
are drift evidence; a CMDB is an export and a view, the git inventory stays the source of truth), and it feeds and is
fed by FTEF (the workload's evidence yields its band; the band bounds what it is admitted for). Until then this ADR
stands as written.
