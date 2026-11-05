# ADR-0023: Data platform: publish once, subscribe through policy

- Status: accepted
- Date: 2026-10-06
- Decider: maintainer

## Context
Bilateral integrations between data sources and consumers grow as n*(n-1)/2 and each one re-implements security,
labels and contracts. The aim is a sovereign open-source platform that applies the infrastructure once
to all data, covering data platform, enterprise service bus, data connectivity and data as a service.

## Decision
`platform/data-platform.yaml` and `tools/dataproducts.py`:
- One backbone: NATS JetStream (also the federation bus, now from M; leaf nodes at the edge for DDIL), CloudEvents
  envelopes carrying label, product and trace id.
- Data products with contracts (Open Data Contract Standard, schemas in Apicurio Registry, channels in AsyncAPI):
  owner, label, schema, allowed purposes, DDIL class, retention.
- Connectors as code (Apache Camel YAML DSL) and change data capture (Debezium Server onto JetStream).
- From L: Iceberg tables on Garage object storage (Deuxfleurs, France; MinIO excluded, its repository was archived in
  2026), Trino with OPA row and column control, DuckDB at the edge, OpenMetadata catalog with OpenLineage, and
  Eclipse Dataspace Components for sovereign sharing between organisations (Dataspace Protocol, ODRL usage policies,
  Gaia-X compatible).
- Subscriptions are decided by the same identity model and policy: purpose must be allowed, the consumer's
  environment label must be at least the product's, and a lower-labelled consumer is routed to the release gateway.
- No bilateral integrations (tested). Airbyte is not used (mixed licence).
