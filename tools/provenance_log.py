"""Transparency log, signed checkpoints and key validity for data provenance (ADR-0097).

The log follows RFC 9162 (Certificate Transparency 2.0) tree shape: leaf hash H(0x00 || d), node hash
H(0x01 || l || r), split at the largest power of two below n. It gives inclusion proofs (an envelope was logged) and
consistency proofs (a later tree extends an earlier one: nothing was rewritten). Tree heads are signed (Ed25519), so a
site can log while cut off and prove on reconnect that its log only grew.

Keys carry validity windows (not_before, not_after, revoked_at): a step signed by an identity that has since died, such
as a workload in a spun-down ephemeral PoP, stays verifiable when its time falls inside the window. That is the
Sigstore model: short-lived signing identities, long-lived verifiability through the log.
"""
from __future__ import annotations

import hashlib
import json


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _k(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


def mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return _h(b"")
    if n == 1:
        return _h(b"\x00" + leaves[0])
    k = _k(n)
    return _h(b"\x01" + mth(leaves[:k]) + mth(leaves[k:]))


def inclusion_proof(m: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _k(n)
    if m < k:
        return inclusion_proof(m, leaves[:k]) + [mth(leaves[k:])]
    return inclusion_proof(m - k, leaves[k:]) + [mth(leaves[:k])]


def verify_inclusion(index: int, size: int, leaf: bytes, proof: list[bytes], root: bytes) -> bool:
    if index >= size:
        return False
    fn, sn, r = index, size - 1, _h(b"\x00" + leaf)
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _h(b"\x01" + p + r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = _h(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _subproof(m: int, leaves: list[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [mth(leaves)]
    k = _k(n)
    if m <= k:
        return _subproof(m, leaves[:k], complete) + [mth(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def consistency_proof(m: int, leaves: list[bytes]) -> list[bytes]:
    return [] if m == 0 or m == len(leaves) else _subproof(m, leaves, True)


def verify_consistency(m: int, n: int, root_m: bytes, root_n: bytes, proof: list[bytes]) -> bool:
    if m == n:
        return root_m == root_n and not proof
    if m == 0 or m > n or not proof and m & (m - 1) != 0:
        return False
    path = ([root_m] if m & (m - 1) == 0 else []) + list(proof)
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _h(b"\x01" + c + fr)
            sr = _h(b"\x01" + c + sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _h(b"\x01" + sr + c)
        fn >>= 1
        sn >>= 1
    return fr == root_m and sr == root_n and sn == 0


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()


class Log:
    """Append-only log of envelope digests with signed tree heads; untrusted storage, verifiable by anyone."""

    def __init__(self, name: str = "log"):
        self.name = name
        self.leaves: list[bytes] = []

    def append(self, digest: str) -> int:
        self.leaves.append(digest.encode())
        return len(self.leaves) - 1

    def root(self, size: int | None = None) -> bytes:
        return mth(self.leaves[: len(self.leaves) if size is None else size])

    def inclusion(self, index: int, size: int | None = None) -> list[bytes]:
        return inclusion_proof(index, self.leaves[: len(self.leaves) if size is None else size])

    def consistency(self, m: int, n: int | None = None) -> list[bytes]:
        return consistency_proof(m, self.leaves[: len(self.leaves) if n is None else n])

    def sth(self, key, ts: str) -> dict:
        head = {"log": self.name, "size": len(self.leaves), "root": self.root().hex(), "ts": ts}
        return head | {"sig": key.sign(_canon(head)).hex()}


def verify_sth(sth: dict, pub) -> bool:
    from cryptography.exceptions import InvalidSignature
    try:
        pub.verify(bytes.fromhex(sth["sig"]), _canon({k: v for k, v in sth.items() if k != "sig"}))
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def key_valid(entry, at: str) -> bool:
    """A key entry is a public key (always valid, model shorthand) or {key, not_before, not_after, revoked_at}."""
    if not isinstance(entry, dict):
        return True
    at = str(at)
    if entry.get("not_before") and at < str(entry["not_before"]):
        return False
    if entry.get("not_after") and at > str(entry["not_after"]):
        return False
    return not (entry.get("revoked_at") and at >= str(entry["revoked_at"]))


def public_key(entry):
    return entry["key"] if isinstance(entry, dict) else entry


def checkpoint(key, verifier: str, digest: str, log_size: int, lineage: list[str] | None = None) -> dict:
    """A verifier's signed statement: everything up to `digest` was verified against a log of `log_size`. A site that
    vouches for a forwarded bundle also signs the `lineage` it verified (the digests of the envelopes and of the
    upstream checkpoints it relied on), so a tombstone or a revocation that arrives later still reaches the forwarded
    copy, and stripping the lineage breaks the signature."""
    body = {"digest": digest, "verifier": verifier, "log_size": log_size}
    if lineage:
        body["lineage"] = sorted(set(lineage))
    return body | {"sig": key.sign(_canon(body)).hex()}


def trusted_digests(checkpoints: list[dict], signers: dict, revoked: set | frozenset = frozenset()) -> dict[str, str]:
    """Digests vouched for by a valid signature of a registered checkpoint signer and not revoked, mapped to that
    signer. A signer entry is a public key or {key, scope: {products, max_label}}."""
    from cryptography.exceptions import InvalidSignature
    out: dict[str, str] = {}
    for c in checkpoints or []:
        entry = signers.get(c.get("verifier"))
        if not entry or c.get("digest") in revoked:
            continue
        try:
            public_key(entry).verify(bytes.fromhex(c["sig"]), _canon({k: v for k, v in c.items() if k != "sig"}))
            out[c["digest"]] = c["verifier"]
        except (InvalidSignature, KeyError, ValueError):
            continue
    return out
