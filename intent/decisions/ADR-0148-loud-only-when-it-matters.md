# ADR-0148: Loud only when it matters: events defined by policy, acknowledged, with their trust impact per part

- Status: accepted (the direction); the build follows, on the band per part of ADR-0147
- Date: 2026-10-14
- Decider: maintainer

## Context (what exists)
`platform/observability.yaml`: the chain signal, condition, event, alarm with owner and risk, pane card with evidence
and allowed controls, signed request, decision inbox, execution, result; events as CloudEvents carrying `riskids`,
`trustimpact`, `severity` (mapped to a band), `site` and `layer`; "no alert without an action"; alert classes with
owner, risks, runbook, action and autonomy (for example break-glass-used, host-trust-drop, policy-deny-spike).
`governance/autonomy.yaml`: per action the most autonomy allowed (autonomous, notify, gated, human); the situation can
only lower it; increase actions never run on their own; a kill switch. ADR-0145: decided rules; ADR-0146: rollouts.

## Decision
1. **Defined, not discovered.** Only an event class defined in the model (by policy, by the security teams, by the
   CISO office: each class with its decision record) can become loud. Everything else stays a signal in the store.
2. **A threshold to be loud.** A class states when an event becomes important enough: its severity, its trust impact
   on the part it touches, and how often in what time. Below the threshold it is counted and visible on drill-down,
   never pushed. Policy changes, break-glass uses and decisions are always loud.
3. **Acknowledged.** A loud event needs a named person to acknowledge it, or to analyse it where its class says so;
   the acknowledgement is a record (who, when, what was checked) in the audit chain, and an unacknowledged event past
   its class's time escalates.
4. **Placed.** Every loud event shows the risks and the measures it concerns (risk ids, rules, rollouts) and its impact
   on the trust band of the part it touches: a component, a layer, a site or Isle, a logical location, a period.
5. **Then options, then automation.** The card offers the controls the viewer may request (remitigate, reconcile,
   quarantine, as `governance/autonomy.yaml` allows); later, the operator decides and the action runs, within the
   autonomy cap and the kill switch, never for an increase action.
6. **On the pane.** Pharos shows the loud events by part, place and period with their state (new, acknowledged,
   analysed, closed), their category of risk and measure, and their trust impact, and drills down to the evidence.

## Consequences
The build extends the alert classes with the threshold and acknowledgement fields, adds an acknowledgement record, the
pane's event view and tests; it uses the band per part of ADR-0147 for the trust impact.
