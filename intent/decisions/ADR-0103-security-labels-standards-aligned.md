# ADR-0103: One security label, rendered into SPIF, STANAG 4774/4778, ESS, RFC 7444, XEP-0258 and Matrix

- Status: accepted
- Date: 2026-10-10
- Decider: maintainer

## Context
The model's data envelopes carry a label, a ring, purposes, a tenant and an assurance (ADR-0096..0100). Mail, chat
and partner exchange need that label in the formats other systems understand. Prior art found and checked
(2026-10-10):
- **Mail:** RFC 7444, the SIO-Label header.
- **XMPP:** XEP-0258.
- **ESS security labels:** RFC 2634.
- **Policy exchange:** the Open XML SPIF.
- **Public NATO standards:** ADatP-4774 (confidentiality metadata label syntax) and ADatP-4778 (metadata binding),
  both Edition A Version 1. Both state that they are authorized for public disclosure, and both forbid
  reproduction.
- **Matrix:** a security-labels implementation by Element, with a proto-MSC, is due at the Matrix Conference on
  2026-10-21.

## Decision
`policies/security-labels.yaml` defines the VDHOME labelling policy:
- an X.667 UUID-based OID, which needs no registration;
- three classifications with display markings that always name the policy, such as `VDHOME RESTRICTED`, with RFC
  7444 colours;
- five category tag sets, using the STANAG 4774 types:
  - Releasable Within and Purpose: permissive;
  - Tenant: restrictive;
  - Assurance and Provenance: informative, which SPIF expresses as the free-form `tagType7`.

`tools/security_labels.py` derives one canonical label from an envelope and renders it as:
- **SPIF 3.0.** The policy validates against the published schema under libxml2. xmlschema reports one finding: it
  applies the schema's own `requiredClass` default to a key reference (the
  validation output is kept with the project's standards evidence).
- **STANAG 4774 XML**, the canonical rich form, in the published namespace and structure.
- **ESS (RFC 2634) in DER.** It carries the policy, classification and a privacy mark; the categories travel in the
  4774 form. It decodes the RFC 7444 and XEP-0258 published examples and reproduces the XEP-0258 example byte for
  byte.
- **The RFC 7444 SIO-Label header.** It carries the 4774 label as `type=":xml"` or the ESS label as `type=":ess"`,
  folded to 78 columns with RFC 2231 continuations, and round-trips.
- **XEP-0258.** The 4774 label goes in `<label/>` and the ESS label in `<equivalentlabel/>`.
- **A Matrix event field** (`org.vdhome.security_label`). It is provisional, carries both forms, and moves to the
  spec's field when the Matrix proposal lands; Matrix is expected to absorb and supersede these formats.
- **A STANAG 4778 metadata binding container.** The 4774 originator label is bound to the unit's digest, with the
  envelope signature as an extension element.

Where the standards differ, the model maps explicitly:
- SPIF has no informative tag type, so 4774 INFORMATIVE becomes `tagType7`;
- ESS categories need registered category OIDs, so the categories travel in the 4774 form instead.

## Boundaries
- VDHOME is a business labelling policy. No equivalence with any government or NATO classification is claimed, and
  none may be inferred from shared words.
- Alignment uses only the publicly disclosed editions, and none of their text is reproduced.
- Conformance is claimed only after the official editions are obtained in VDHome's name. Until then the 4774 and
  4778 renderings are structural alignments, and the 4778 attribute details remain to be verified.

## Consequences
- Test `test_one_security_label_renders_into_every_standard_form`.
- Check `security_labels`.
- New register entries: rfc-2634, rfc-7444, xep-0258, xmlspif, adatp-4774, adatp-4778.
- The mail gate (to come) writes SIO-Label headers and 4778 bindings. Matrix rooms and messages carry the field
  until the spec catches up.
