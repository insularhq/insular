# ADR-0047: Progressive, scoped and loud enforcement of controls and features

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
Decision makers must be able to enforce the available features and controls granularly and
progressively, and the platform must be loud about it ("in two weeks the compliance check on the network will take
effect") to drive adoption and communication.

## Decision
- Controls move through announce, observe, warn, enforce; features through announce, preview, default, on.
  Each rollout has a scope (platform, tenant, site, environment, group, application), dated stages and a signer whose
  role matches the scope (operator for platform floors, risk owner for tenant, site and environment, tenant admin for
  groups, service owner for applications). Overlays only tighten; a delay of a platform floor is a deviation with
  expiry.
- The focal point still decides; the mode decides what a deny becomes: counted (announce), logged and shown to the
  owner (observe), allowed with a "Warning: 299" message naming the date and the fix (warn), denied unless a valid
  exemption with expiry covers the subject (enforce).
- An experience-changing stage is announced at least 14 days ahead; enforce follows at least 14 days of observe or
  warn; a stage moving to enforce holds when the observed would-deny rate exceeds what the signer accepted, and the
  signer gets a decision card; no stage is skipped.
- Loud: countdown notices at 14, 7, 1 and 0 days on the portal and login banners, mail, Matrix, push, the status page,
  the gateway warning header and the CLI; and a personal notice to every subject seen in observe or warn, with the fix.
- The RTOP shows every rollout. Model: platform/enforcement-rollout.yaml; tool: tools/rollout.py.
- Prior art: Kubernetes Pod Security Admission, OPA Gatekeeper enforcement actions, Kyverno Audit/Enforce, the
  Kubernetes warning header, OpenFeature.
