# ADR-0027: Data products and data mesh on the platform

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Decision
The four data mesh principles map onto mechanisms the platform already has:
- **Domain ownership:** domains (people, operations, cases in the examples) each with a data owner who is a person,
  usually not IT, deciding through decision cards.
- **Data as a product:** the contract (owner, label, schema, purposes, quality suite, lineage, retention, review),
  discoverable in OpenMetadata, addressable as a NATS subject, an Iceberg table and, when shared, a dataspace asset.
- **Self-serve data platform:** a data product intent compiles (`tools/dataproducts.py`, like app intents) into the
  subject, schema registration, table, catalog entry, access policy (purposes, minimum consumer label, personal data
  masking from Confidential), quality suite, lineage, review schedule and crypto-erasure destruction.
- **Federated computational governance:** the global data policy is code (labels, maximum retention per label,
  masking, required fields); domain overlays may only tighten it, checked like every other floor.
Across organisations the mesh continues as a dataspace (Eclipse EDC, ADR-0023).
