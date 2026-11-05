"""Artefacts rendered from code and data: computed labels, information-flow check, signed reproducible manifests,
lossless carrier round-trip, and fingerprint scanning for higher-labelled text."""

from __future__ import annotations

import hashlib
import hmac
import json
import re

LABELS = ["Internal", "Sensitive", "Restricted"]


def computed_label(inputs: list[dict]) -> str:
    """Highest input label, raised one level when an input's aggregation ceiling is exceeded."""
    if not inputs:
        return LABELS[-1]
    label = max((i["label"] for i in inputs), key=LABELS.index)
    for i in inputs:
        ceiling = i.get("aggregation_ceiling")
        if ceiling and i.get("records", 0) > ceiling and LABELS.index(label) < len(LABELS) - 1:
            label = LABELS[LABELS.index(label) + 1]
    return label


def check_render(env_label: str, inputs: list[dict], declared_marking: str | None = None) -> list[str]:
    errs = [f"input {i['id']} is {i['label']}, above the {env_label} environment: refused before rendering"
            for i in inputs if LABELS.index(i["label"]) > LABELS.index(env_label)]
    label = computed_label(inputs)
    if LABELS.index(label) > LABELS.index(env_label):
        errs.append(f"computed label {label} exceeds the {env_label} environment (aggregation)")
    if declared_marking and declared_marking != label:
        errs.append(f"marking {declared_marking} differs from the computed label {label}")
    return errs


def manifest(inputs: list[dict], template_sha: str, renderer_digest: str, output_sha: str) -> dict:
    return {"inputs": sorted((i["id"], i["sha256"]) for i in inputs), "template": template_sha,
            "renderer": renderer_digest, "output": output_sha, "label": computed_label(inputs)}


def roundtrip_ok(product_rows: list[dict], embedded: str) -> bool:
    """Lossless carrier: the embedded JSON parses back to exactly the product rows."""
    return json.loads(embedded) == product_rows


def _shingles(text: str, n: int) -> list[str]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return [" ".join(words[i:i + n]) for i in range(max(0, len(words) - n + 1))]


def fingerprint(text: str, salt: bytes, n: int = 6) -> set[str]:
    return {hmac.new(salt, s.encode(), hashlib.sha256).hexdigest() for s in _shingles(text, n)}


def scan(text: str, fingerprints: set[str], salt: bytes, n: int = 6) -> int:
    """Number of shingles in the artefact text that match the higher-labelled corpus."""
    return len(fingerprint(text, salt, n) & fingerprints)
