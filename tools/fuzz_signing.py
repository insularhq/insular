"""Fuzzes signature verification (tools/signing.py) with Atheris under ClusterFuzzLite (.clusterfuzzlite/);
tests/test_fuzz_targets.py runs the same entry on seeded inputs without Atheris.

Approvals, signed lights and chain heads carry a signature from someone else, so verify() reads untrusted input. What
must hold for every input:
- verify answers True or False and never raises, whatever the signature and the signed object look like;
- a signature verifies only for the object it was made over: an honest signature over the input verifies, and the
  same signature over a changed object does not.
"""
import json
import sys

try:
    import atheris
except ImportError:          # the seeded test runs the entry without the fuzzer
    atheris = None

if atheris:
    with atheris.instrument_imports():
        import signing as S
else:
    import signing as S

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

KEY = Ed25519PrivateKey.from_private_bytes(bytes([5]) * 32)
PUB = S.public_b64(KEY)


def _obj(data: bytes):
    try:
        return json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return {"raw": data.hex()}


def test_one_input(data: bytes) -> None:
    if not data:
        return
    split = data[0] % (len(data) or 1)
    sig_part, obj = data[1: split + 1], _obj(data[split + 1:])

    # a forged or malformed signature: a bool, never an exception
    for sig in (sig_part.decode("latin-1"), sig_part.hex(), sig_part):
        assert S.verify(PUB, sig, obj) in (True, False)

    # an honest signature verifies, and only over its own object
    good = S.sign(KEY, obj)
    assert S.verify(PUB, good, obj)
    other = {"wrapped": obj}
    assert not S.verify(PUB, good, other)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
