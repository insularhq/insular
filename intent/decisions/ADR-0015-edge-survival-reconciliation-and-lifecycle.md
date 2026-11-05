# ADR-0015: Edge survival, reconciliation after absence or break-glass, and lifecycle order

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Decision
- `platform/edge.yaml`: an edge site is an ordinary instance with an edge profile. Surviving locally: login with
  local passkeys, token validation against cached keys, certificate issuance from a name-constrained edge
  intermediate (leaves max 24 h, intermediate 30 days, so a captured site's issuing power expires by itself), local
  OPA with the last signed bundle, enforcement points on their last configuration, cached revocation lists, a local
  time source with a 30-second drift alarm, a local resolver, Flux on the last bundle with a local image cache,
  local evidence, green light and audit chain, local alerting through the site GSM modem, local runbooks, local
  backups. Central only: upstream federation, the vault, new deviations, risk register and root operations, new
  tenants or sites. Every cache has a maximum age; after the offline grace Internal continues with alerts,
  Confidential goes read-only without new sessions, Restricted fails closed.
- `tools/reconcile.py`: a returning site is short (within grace: resync revocations, policy and configuration, data,
  audit chains, evidence, in that order), long (beyond grace or any break-glass: quarantine with evidence upload
  only, verify chain and attestation, resync, rotate credentials, gated re-admission) or stale (beyond the edge
  intermediate's lifetime, broken chain, failed attestation or suspected compromise: isolate, preserve a forensic
  copy, wipe and reinstall from the signed image, re-attest, new keys, import data only through inspection,
  re-admission by the external authority). Each break-glass action becomes a retroactive decision card: ratified
  effects are kept until their expiry as accepted risk, unratified effects are reverted and opened as incidents,
  undecided ones are reverted at the deadline.
- `platform/lifecycle.yaml` and `tools/lifecycle.py`: every size has a dependency order for bootstrap and upgrades
  (dependencies first, canary first) and decommissions in reverse, ending with evidence export and crypto-erasure.
