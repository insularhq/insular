# Security summary

This is the short version on purpose. It says what Insular is designed to protect, what it does not cover and how the
design is checked. Detailed test reports, known limits and any live deployment are kept by the maintainer. To report a
weakness, see [`SECURITY.md`](../SECURITY.md).

Nothing here has run in production, and passing the checks in this repository shows that the model is consistent, not
that a deployment is secure.

## What the design is meant to protect against

- **An outside attacker** reaching a site: access goes through one identity broker with short-lived, bound tokens, and
  a policy decision on each request.
- **A compromised workload or tenant** moving sideways: network segmentation, a platform-owned way out, and policy
  evaluated close to the workload.
- **A tampered change** reaching a site: one execution path for automation, signed GitOps artifacts, and locked digests.
- **A careless or overreaching insider:** separated roles, approvals that are the approver's own signature, and audit.
- **A federation partner** claiming more than it should: trust is earned by evidence, local to each site, and can be
  withdrawn.

## What is out of scope

- A provider or operator with physical control of the hardware, beyond what attestation and encryption can show.
- A compromised endpoint that a person is actively using.
- Denial of service by a well-resourced attacker.
- Legal or regulatory compliance. Mappings to frameworks are engineering aids, not a compliance claim or legal advice.
- Classified information. Label formats follow public standards only; that says nothing about accreditation.

## How the design is checked

| Area | What guards it |
|---|---|
| Contracts between components | `tools/contracts.py`, `tools/api_schemas.py` |
| Sources of truth and supply chain | `tools/sources_of_truth.py`, `tools/provenance.py` |
| Policy rules | `tools/policy_compile.py` and the tests in `policy/` |
| Detection and response | `tools/detection_response.py` |
| Data handling and labels | `tools/data_policy.py`, `tools/data_provenance.py`, `tools/security_labels.py` |
| Access, grants and delegation | `tools/access_paths.py`, `tools/grants.py`, `tools/leases.py`, `tools/delegation.py` |

`python ci/check_public.py` runs these checks and the tests. The maintainer also runs adversarial reviews and lab tests
on a private copy with the full model. Their findings are fixed or tracked there, and are not published.
