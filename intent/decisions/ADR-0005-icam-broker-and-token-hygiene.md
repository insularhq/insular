# ADR-0005: ICAM through one broker, crypto agility and short-lived, bound tokens

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
Identity providers, trust anchors and algorithms will change (client IdPs, national eID, the EU wallet, post-quantum
cryptography). Backends that are hard to migrate must not be reconfigured every time.

## Decision
`platform/icam.yaml`: applications trust one stable broker issuer per tenant and a fixed claims contract; upstream
IdPs (OIDC, SAML, eID, EUDI wallet, local passkeys) are switched in the broker; legacy backends sit behind an
identity-aware proxy or token exchange; trust anchors and keys roll over with published overlap. Algorithms come from
an allow-list with dated legacy exceptions and a hybrid post-quantum plan. Token lifetimes, refresh rules and sender
constraints are set per data label; credentials are short-lived (SPIFFE, dynamic database credentials, SSH
certificates), static API keys are forbidden; secrets live in OpenBao and HSMs and are delivered at runtime.

## Consequences
Tested invariants: stricter labels never get longer lifetimes; sensitive labels require sender-constrained tokens;
ICAM lifetimes agree with the PKI policy; no tool hard-codes a weak algorithm.
