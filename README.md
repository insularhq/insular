<h1><picture><source media="(prefers-color-scheme: dark)" srcset="brand/insular/svg/insular-lockup-horizontal-dark.svg"><img alt="Insular" src="brand/insular/svg/insular-lockup-horizontal-light.svg" width="320"></picture></h1>

<p>
  <a href="https://github.com/insularhq/insular/actions/workflows/ci.yml"><img src="https://github.com/insularhq/insular/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/insularhq/insular"><img src="https://api.scorecard.dev/projects/github.com/insularhq/insular/badge" alt="OpenSSF Scorecard"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-EUPL--1.2-blue" alt="Licence: EUPL-1.2"></a>
</p>

A secure delivery platform, as code: the model, its decisions and the checks that hold them together.

Some work is too sensitive to send to a general cloud service: a client hands over confidential material, someone works
on it, and the client wants to be able to check that the environment is compliant and that the provider cannot read the
content. Insular describes such a platform for a small organisation: separate sites that each stand on their own, with
identity, access, keys, policy and evidence defined together, and federation between organisations through a controlled
gateway.

## What this repository is

A published slice of the platform's **model**, not a product you install: registers, generators, checkers, a policy
bundle and a GitOps tree, with a selection of the design decisions. The full model, its lab evidence and its test reports
are private, so some references point at records that are not here: decision records (ADR numbers) other than
those in `intent/decisions/`, the operator pane (Pharos) with its generator and its own tree, and the lab evidence.

| Where | What |
|---|---|
| [`docs/security.md`](docs/security.md) | What the design protects against, what it does not, and how it is checked |
| [`intent/decisions/`](intent/decisions/) | A selection of the decision records (ADRs) |
| [`platform/`](platform/), [`policies/`](policies/), [`policy/`](policy/) | The registers and the policy rules |
| [`gitops/`](gitops/) | The Kubernetes tree for a lab site, with generalised addresses; the operator pane's own tree is not included |
| [`instances/vdh-demo/`](instances/vdh-demo/) | A fictional example instance |
| [`tools/`](tools/), [`tests/`](tests/) | The checkers and generators, and the tests that hold them together |

The access engine is a separate project, [KeyClerk](https://github.com/keyclerk/keyclerk), pinned by commit; CI installs that release's wheel by its hash.

## Status

Early. Parts of the model have been tried on a private lab; much of it has not, and nothing here has run in production.

## Try the checks

Python 3.12 on Linux on x86-64 (`fetch_opa` downloads the linux amd64 binary) with network access. CI installs from
`requirements-ci.txt`, which pins hashes.

```sh
git clone https://github.com/insularhq/insular && cd insular
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pip install -r requirements-keyclerk.txt
python tools/fetch_opa.py --dest .venv/bin/opa
python ci/check_public.py
```

## Support

Run by VDHome (Belgium) in start-up mode. There is no support, no service level
and no roadmap promise; issues are answered on a best-effort basis. See [`CONTRIBUTING.md`](CONTRIBUTING.md) and, for a security weakness,
[`SECURITY.md`](SECURITY.md).

## AI assistance

Insular is human-designed and AI-coded (Claude, by Anthropic): the design decisions are the maintainer's, and much of the
code and text was written with AI. Read it with that in mind.

## Licence and name

[EUPL-1.2](LICENSE). The name and the mark are covered by [`TRADEMARK.md`](TRADEMARK.md).
