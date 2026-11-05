"""Fuzzes the transparency log's verifiers (tools/provenance_log.py) with Atheris under ClusterFuzzLite
(.clusterfuzzlite/); tests/test_fuzz_targets.py runs the same entry on seeded inputs without Atheris.

Proofs and tree heads arrive from other sites, so the verifiers read untrusted input. What must hold for every input:
- verify_inclusion, verify_consistency and verify_sth answer True or False and never raise;
- an inclusion proof verifies only for the leaf that is at that index of the tree;
- a consistency proof verifies only when the smaller tree is a prefix of the larger;
- the honest proofs of a tree built from the input always verify.
"""
import json
import sys

try:
    import atheris
except ImportError:          # the seeded test runs the entry without the fuzzer
    atheris = None

if atheris:
    with atheris.instrument_imports():
        import provenance_log as P
else:
    import provenance_log as P


def _leaves(data: bytes) -> list[bytes]:
    n = 1 + data[0] % 9 if data else 1
    return [bytes([i]) + data[i: i + 3] for i in range(n)]


def _proof(data: bytes) -> list[bytes]:
    return [data[i: i + 32] for i in range(0, len(data), 32)][:12]


def test_one_input(data: bytes) -> None:
    if len(data) < 4:
        return
    leaves = _leaves(data)
    n = len(leaves)
    root = P.mth(leaves)
    i = data[1] % (n + 2)          # sometimes past the end
    m = data[2] % (n + 2)
    rest = data[3:]

    # honest proofs verify
    if i < n:
        assert P.verify_inclusion(i, n, leaves[i], P.inclusion_proof(i, leaves), root)
    if 0 < m <= n:
        assert P.verify_consistency(m, n, P.mth(leaves[:m]), root, P.consistency_proof(m, leaves))

    # fuzzed proofs: a bool, never an exception, and never a proof of something false
    leaf = rest[:4]
    ok = P.verify_inclusion(i, n, leaf, _proof(rest), root)
    assert isinstance(ok, bool)
    if ok:
        assert i < n and leaves[i] == leaf, "an inclusion proof verified a leaf that is not at that index"
    root_m = rest[:32] if len(rest) >= 32 else P.mth(leaves[:m])
    ok = P.verify_consistency(m, n, root_m, root, _proof(rest[32:]))
    assert isinstance(ok, bool)
    if ok:
        assert 0 < m <= n and root_m == P.mth(leaves[:m]), "a consistency proof verified a tree that is not a prefix"

    # a tree head from anywhere: verify_sth answers, it never raises
    try:
        sth = json.loads(rest.decode("utf-8", "replace"))
    except ValueError:
        sth = {"sig": rest.hex(), "size": n}
    assert P.verify_sth(sth, _PUB) in (True, False)


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

_PUB = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32).public_key()


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
