# Contributing

Thank you for your interest. Insular is in start-up mode, so this page says plainly what helps.

## What is welcome

- **Issues:** bugs, unclear documentation, a check that passes when it should not, ideas. Use the issue forms, and
  fictional data only in every example.
- **Proposals to change a decision:** a selection of the design decisions is in `intent/decisions/`. Open an issue that names the
  ADR or the behaviour it would change and says what would be done differently and why.
- **Security weaknesses:** never in a public issue; see [`SECURITY.md`](SECURITY.md).

## Outside code

Outside code is not merged for now. The licence model has to stay simple while the project settles, and a contributor
licence agreement will be in place before any first outside merge. Until then, please describe a change in an issue
rather than sending a pull request.

## How the maintainer's changes work

- Every change keeps `python ci/check_public.py` green: it runs the published checks and tests, and all must pass.
- A change that alters intent carries a decision record.
- A failure says what happened, why, and what completes the task.
- A change worth a line in the release notes adds it to `CHANGELOG.md`.
- AI use is stated: the pull request template has the level, and commits say so in an `Assisted-by:` trailer. The
  maintainer's own work is "Human-designed, AI-coded".
- Everything posted here is public at once: text and diffs pass a public text check.

## Licence

EUPL-1.2. See [`LICENSE`](LICENSE) and, for the name and mark, [`TRADEMARK.md`](TRADEMARK.md).
