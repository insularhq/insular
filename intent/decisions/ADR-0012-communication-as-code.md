# ADR-0012: Communication as code, tested every day

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
When something fails or maintenance is planned, the people who depend on the affected capability must know in time,
even when the network or the platform itself is down, and someone on site must be reached when the person cannot.
A yearly test is only a snapshot.

## Decision
- `platform/communication.yaml` and `tools/notify.py`: channels ranked by independence from the platform and from
  the network (Matrix, mail, ntfy push, SMS through an on-site GSM modem with Gammu, an EU SMS provider, automated
  voice through Asterisk, a status page on separate hosting with Gatus).
- Criticality per person from the registered identity attribute `stakeholder_level`: mission-critical people need at
  least three channels, two independent of the platform, one that works without the network, and a delegate;
  maintenance notice 72 h (key users 48 h, users 24 h).
- Impact is derived from what each person depends on; escalation goes person -> delegate -> site contact (the hands
  and eyes on site) -> service owner, each step waiting for an acknowledgement and recorded as a run.
- Triggers: detected outage, lost access (including islanded sites), predicted loss (expiry, budget, capacity),
  planned maintenance from the change record.
- Continuous testing: daily silent tests of every channel path to test endpoints with delivery receipts, daily
  reachability checks without ringing, weekly acknowledged tests with delegates and site contacts; results are a
  green-light control (stale turns AMBER, then RED).

## Consequences
Components: ntfy and Gammu from M, Asterisk in L, an EU SMS provider as a paid service where wanted. Gatus stays the
status page (configuration as code) rather than Uptime Kuma (configuration in its database).
