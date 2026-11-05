"""Ed25519 signatures for approvals, signed lights and chain heads.

A party signs with its private key (in production on a hardware token); verifiers hold only public keys, so a
parent cannot forge a child's light and a writer to the repository cannot forge an approval.
"""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, default=str).encode()


def sign(private: Ed25519PrivateKey, obj) -> str:
    return base64.b64encode(private.sign(canonical(obj))).decode()


def public_b64(private: Ed25519PrivateKey) -> str:
    return base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def load_public(b64: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(b64))


def verify(public: Ed25519PublicKey | str, signature: str, obj) -> bool:
    key = load_public(public) if isinstance(public, str) else public
    try:
        key.verify(base64.b64decode(signature), canonical(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
