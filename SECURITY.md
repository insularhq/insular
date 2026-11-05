# Security

Insular is security tooling, so reports of a weakness are welcome and taken seriously.

## Reporting a weakness

Report privately, never in a public issue or pull request, through a private security advisory on this repository:
https://github.com/insularhq/insular/security/advisories/new

Include what you did, what you expected and what happened, with a minimal example that uses fictional data only. Never
send real personal or client data. We agree a disclosure timeline with you before anything is made public, and credit
you if you want it.

### Response targets

- We acknowledge a report within 5 working days.
- For a confirmed issue we give you a fix or a plan with dates within 30 days.

These are targets for a project in start-up mode without a support contract, not guarantees; if we need longer we
say so and why.

## Supported versions

| Version | Supported |
|---|---|
| main and the latest release | yes |
| older | no |

## Scope

In scope: this repository's own model, policies, tools and GitOps tree. A finding in an upstream component goes to that
project; tell us too if the way Insular composes it makes it worse. KeyClerk takes reports at
https://github.com/keyclerk/keyclerk/security/advisories/new.

Out of scope here: detailed test reports, known limits and any live deployment. Those are kept by the maintainer, not in
this repository.
