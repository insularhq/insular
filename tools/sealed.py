"""Sealed artefacts: segments above the carrier's label are encrypted per segment, their keys wrapped for a key
access service (KAS) with the access policy bound as authenticated data. The carrier can travel through lower
domains; only a compliant system holding the trust anchor and the required attributes gets the keys back.

Reference model of the ZTDF/OpenTDF idea with standard primitives: AES-256-GCM per segment, X25519 + HKDF-SHA256 key
wrapping, Ed25519 signature over the manifest. Segments are padded to size buckets so the ciphertext length does not
reveal the content length. Production would use OpenTDF and a hybrid post-quantum wrap.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from signing import sign, verify

BUCKETS = [1024, 4096, 16384, 65536, 262144, 1048576]
LABELS = ["Internal", "Sensitive", "Restricted"]


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def pad(data: bytes) -> bytes:
    size = next((b for b in BUCKETS if b >= len(data) + 4), None)
    if size is None:
        raise ValueError("segment too large for the padding buckets")
    return len(data).to_bytes(4, "big") + data + bytes(size - len(data) - 4)


def unpad(data: bytes) -> bytes:
    n = int.from_bytes(data[:4], "big")
    return data[4:4 + n]


def _kek(shared: bytes, policy: dict) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=None, info=json.dumps(policy, sort_keys=True).encode()).derive(shared)


def seal_segment(plain: bytes, policy: dict, kas_public: X25519PublicKey) -> dict:
    dek = AESGCM.generate_key(bit_length=256)
    aad = json.dumps(policy, sort_keys=True).encode()
    n1 = os.urandom(12)
    ct = AESGCM(dek).encrypt(n1, pad(plain), aad)
    eph = X25519PrivateKey.generate()
    kek = _kek(eph.exchange(kas_public), policy)
    n2 = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(n2, dek, aad)
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"policy": policy, "nonce": _b64(n1), "ciphertext": _b64(ct),
            "wrapped_key": {"ephemeral": _b64(eph_pub), "nonce": _b64(n2), "key": _b64(wrapped)}}


class KAS:
    """Key access service in the high domain: releases a segment key only to an attested, compliant requester whose
    attributes satisfy the bound policy, before expiry and unless revoked; every request is logged."""

    def __init__(self):
        self._key = X25519PrivateKey.generate()
        self.public = self._key.public_key()
        self.revoked: set[str] = set()
        self.log: list[dict] = []

    def rewrap(self, segment: dict, requester: dict, now: datetime) -> bytes | None:
        pol = segment["policy"]
        why = None
        if not requester.get("trust_anchor_ok"):
            why = "requester system not attested against the trust anchor"
        elif not set(pol["attributes"]) <= set(requester.get("attributes", [])):
            why = "requester lacks the required attributes"
        elif now > datetime.fromisoformat(pol["expires"]):
            why = "policy expired"
        elif pol["id"] in self.revoked:
            why = "key revoked"
        self.log.append({"segment": pol["id"], "requester": requester.get("id"), "at": now.isoformat(), "granted": why is None, "why": why})
        if why:
            return None
        w = segment["wrapped_key"]
        eph = X25519PublicKey.from_public_bytes(_unb64(w["ephemeral"]))
        kek = _kek(self._key.exchange(eph), pol)
        return AESGCM(kek).decrypt(_unb64(w["nonce"]), _unb64(w["key"]), json.dumps(pol, sort_keys=True).encode())


def open_segment(segment: dict, dek: bytes) -> bytes:
    aad = json.dumps(segment["policy"], sort_keys=True).encode()
    return unpad(AESGCM(dek).decrypt(_unb64(segment["nonce"]), _unb64(segment["ciphertext"]), aad))


def build(parts: list[dict], carrier_label: str, kas: KAS, signer, expires: str) -> dict:
    """parts: [{id, label, content: bytes}]. Parts above the carrier label are sealed; the rest stay clear."""
    rendered, sealed = [], {}
    for p in parts:
        if LABELS.index(p["label"]) > LABELS.index(carrier_label):
            pol = {"id": p["id"], "label": p["label"], "attributes": [f"clearance:{p['label'].lower()}"], "expires": expires}
            sealed[p["id"]] = seal_segment(p["content"], pol, kas.public)
            rendered.append({"id": p["id"], "placeholder": f"[sealed {p['label']} segment]"})
        else:
            rendered.append({"id": p["id"], "text": p["content"].decode()})
    manifest = {"carrier_label": carrier_label, "contains_sealed": sorted({sealed[k]["policy"]["label"] for k in sealed}),
                "rendered": rendered, "sealed": sealed}
    return {"manifest": manifest, "signature": sign(signer, manifest)}


def reimport(artefact: dict, signer_public, kas: KAS, requester: dict, now: datetime) -> dict:
    """On a compliant system: verify the signature, ask the KAS per segment, re-render whatever may be opened."""
    if not verify(signer_public, artefact["signature"], artefact["manifest"]):
        return {"ok": False, "why": "signature does not verify: tampered or foreign artefact"}
    out = []
    for r in artefact["manifest"]["rendered"]:
        if "text" in r:
            out.append(r["text"])
            continue
        seg = artefact["manifest"]["sealed"][r["id"]]
        dek = kas.rewrap(seg, requester, now)
        out.append(open_segment(seg, dek).decode() if dek else r["placeholder"])
    return {"ok": True, "document": out}
