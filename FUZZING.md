# Fuzzing

Insular has no fuzzing targets of its own, on purpose. This repository is a model: registers, generators and checkers
that read files from this repository, not input from strangers. Code that parses outside input belongs to the projects
that run it, such as [KeyClerk](https://github.com/keyclerk/keyclerk). The access lifecycle has stateful property tests
(Hypothesis) instead; see `tests/`. If a tool here starts reading outside input, it gets a fuzz target.
