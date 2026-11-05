# ADR-0061: Model completeness is tested

- Status: accepted
- Date: 2026-10-08
- Decider: maintainer

## Findings
tools/model_audit.py found: two model files that were not valid YAML (an assurance review file and
the inventory schema), never caught because nothing parsed them; seven files no tool or test read; runtime parts
named only in prose (Coraza and OWASP CRS ran in the gateway without a size or BOM entry; the hawkBit server, the
Unbound site resolver and the VDI session agent existed only in text); host and stick items only in prose
(tpm2-pkcs11, wpa_supplicant with pkcs11-provider, osquery); step-ca missing from the lifecycle.

## Decision
All of these are declared (sizes, BOM, lock, provenance, resilience, lifecycle, keep-review, interfaces, seams, or
the host, stick and managed-device image lists), and test_model_is_complete runs the audit in the gate: every model
file parses and has a checker, every runtime component is in every register, nothing the model runs is named only in
prose, every principle has its test, every tool has a test, and every ADR the model cites exists. Size budgets: S 23,
M 36, L 48 (the WAF was already running, now counted).
