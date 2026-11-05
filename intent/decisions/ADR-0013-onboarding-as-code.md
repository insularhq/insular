# ADR-0013: Onboarding and documentation as code, gated by release

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
Missing onboarding, missing documentation and hiding the architecture undermine trust and compliance. Every user
must be guided from zero, in the flavour of their role, and must be able to inspect the whole architecture if they
want to. Documentation must never be older than the system.

## Decision
- `catalog/features.yaml`: every feature is user-facing or backend-only, lists the roles it touches and, if
  user-facing, the screen state (app, path, fixture) to capture.
- `onboarding/journeys.yaml`: roles (end user, team champion, security officer, tenant-admin, risk owner, site
  sysadmin) with flavour (plain or technical), transparency level (overview, detailed, full) and physical package
  (booklet, quick reference card, keys in tamper-evident bags, issuance handbook and register, runbooks, a
  break-glass card without secrets); journeys per role with "where" and "ask whom" in every step.
- `tools/onboarding.py`: coverage (every user-facing feature has steps for each role it touches; plain flavours pass
  the jargon lint), release check (a screenshot captured for this release for every user-facing screen), rendering
  per role and tenant with a release stamp and the transparency section.
- Printed material carries the release, a printed-on date and a QR code to the current version, and never secrets.
- A release produces a "what changes for you" page per role. Screenshot capture (Playwright on an ephemeral instance
  with fictional fixtures) and HTML/PDF rendering (renderfact) are tracked in a separate work item.

## Consequences
The coverage check caught four gaps in the first journeys (a step pointing at a missing feature, roles without
activation or key steps); they were fixed in the journeys, not in the check.
