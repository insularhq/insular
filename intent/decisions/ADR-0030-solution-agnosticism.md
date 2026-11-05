# ADR-0030: Solution agnosticism by interface

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
The question was whether brokers, API calls, front-ends and back-ends are replaceable everywhere. They were in
places (identity broker and claims contract, crypto allow-list, conformant Kubernetes, substrates, OSCAL, OCSF,
CloudEvents, AuthZEN, OpenTelemetry, the Dataspace Protocol) but components were named directly in most of the
model, without a rule.

## Decision
`catalog/interfaces.yaml`: 38 capabilities, each bound to an open interface, with its implementations, verified open
alternatives, a lock-in level and an exit plan. Rules: front-ends talk only to versioned APIs (OpenAPI, AsyncAPI)
through the gateway via a backend-for-frontend; data leaves every component in an open format on request; a component
swap is a normal change whose interface tests must pass. Tested: every runtime component in every size and module
implements a named capability; a capability without an alternative must have a standard interface.

## Honest lock-ins
- **High:** the end-to-end encrypted vault (CryptPad): no standard exists for end-to-end encrypted collaboration; the
  exit is export to open formats and re-import.
- **Medium:** workflows (Argo-specific definitions, regenerated from the model for another engine), dashboards
  (Grafana; Perses is the CNCF alternative), ITSM (GLPI as a view; git stays the source of truth).
- Checked on the way: Synapse's old repository is archived (it moved to Element under AGPL); authentik and Infisical
  are open core, so not listed as alternatives.
