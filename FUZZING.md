# Fuzzing

Most of this repository is a model: registers, generators and checkers that read files from this repository, not input
from strangers. The tools that do read outside input are fuzzed:

- `tools/fuzz_provenance_log.py`: the transparency log's verifiers. Inclusion and consistency proofs and signed tree
  heads arrive from other sites; a verifier answers true or false and never raises, an inclusion proof verifies only for
  the leaf at that index, and a consistency proof only for a tree that is a prefix of the larger one.
- `tools/fuzz_signing.py`: signature verification for approvals, signed lights and chain heads; a forged or malformed
  signature never raises, and a signature verifies only over the object it was made over.

ClusterFuzzLite (`.clusterfuzzlite/`, `.github/workflows/cflite.yml`) fuzzes them for two minutes on every pull
request and for ten minutes every week. `tests/test_fuzz_targets.py` runs the same entries on seeded inputs in every
test run, so the properties hold without the fuzzer too. Its first run found a tree head of the wrong shape raising
instead of being refused; that is fixed. The access lifecycle has stateful property tests (Hypothesis) as well; see
`tests/`. Code that parses outside input in its own projects, such as [KeyClerk](https://github.com/keyclerk/keyclerk),
is fuzzed there.
