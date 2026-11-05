# ADR-0033: The middle label is called Sensitive, not Confidential

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Decision
The data labels are Internal, Sensitive and Restricted. "Confidential" is renamed to "Sensitive" everywhere in the
current model (YAML, tools, tests, CALM, policies, the generated brief); resource types follow (sensitive-document), as does the gateway cell (sensitive). Project names and other
senses are untouched ("Confidential Containers", "confidential computing", "confidentiality").

## Consequences
Decision records before this one keep their original wording as history. All 70 tests pass after the rename.
