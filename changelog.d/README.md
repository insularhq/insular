# Changelog fragments

A pull request records its change here instead of editing `CHANGELOG.md`, so open pull requests never conflict over
the same list. Add one file per change, named `<issue>.<section>.md`:

- `<issue>` is the issue number (or a short lowercase slug when there is none);
- `<section>` is one of `added`, `changed`, `deprecated`, `removed`, `fixed`, `security` (Keep a Changelog).

The file holds Markdown bullets in the style of `CHANGELOG.md`: each entry starts with `- `, continuation lines are
indented two spaces, lines stay within 120 columns, punctuation is plain ASCII. Example, `13.added.md`:

    - Request policies are compiled and tested in CI before a site can load them.

`python ci/changelog.py check` checks the fragments (the public gate runs it); `show` prints the coming release notes.
Preparing a release, `release X.Y.Z` folds the fragments into `## [X.Y.Z]` and removes them; `ci/release_notes.py`
reads that section for the release.
