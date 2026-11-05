# ADR-0008: Holistic identity for persons, machines and agents

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
ICAM must not stop at human users and privileged access management. Persons, workloads, devices, infrastructure and
AI agents all need identifiers, credentials, attributes and policy, designed together from the start even if not
every component is deployed in every size.

## Decision
- `platform/identity.yaml`: five subject kinds, each with identifier, credentials, assurance and lifecycle (NIST
  800-63-4, SPIFFE/WIMSE, RATS RFC 9334 and EAT RFC 9711, RFC 8693 actor chains, SCIM, SD-JWT RFC 9901 and the EU
  wallet for attributes).
- An identity is a stable identifier, bound credentials and **attributes**, each registered with its authority,
  freshness and lawful basis. Policies may only use registered attributes; special categories (marital status,
  health, religion and the like) are never used for access decisions; stale attributes count as absent.
- One request shape for every subject (OpenID AuthZEN Authorization API 1.0): subject, action, resource, context and
  actor chain. Deny overrides: roles, attributes and adaptive context (device posture, evidence state, location) must
  all pass. Agents act only on behalf of a named delegator, never with more rights, never for irreversible actions,
  chain depth at most two.
- `tools/authz.py` pins the semantics in tests; production evaluation is OPA behind the enforcement points.

## Consequences
The same policy file governs a consultant, the summarising agent acting for them, the workload unwrapping a data key
and a device enrolling into the fleet (tested with `policies/vault-access.yaml`).
