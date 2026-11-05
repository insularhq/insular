"""The fuzz targets in tools/fuzz_*.py run here on seeded inputs, without Atheris, so their properties hold in every
test run; ClusterFuzzLite runs the same entries with coverage guidance (.clusterfuzzlite/, decision I4 of 2026-11-05)."""
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import fuzz_provenance_log  # noqa: E402
import fuzz_signing  # noqa: E402

SHAPES = [b"", b"\x00", b"{}", b'{"sig": 5}', b'{"sig": null, "size": "x"}', b'[1, 2]', b'"text"', b"\xff" * 80,
          b'{"sig": "zz", "log": "a"}', bytes(range(256))]


@pytest.mark.parametrize("target", [fuzz_provenance_log, fuzz_signing], ids=["provenance_log", "signing"])
def test_a_fuzz_target_holds_on_seeded_inputs(target):
    r = random.Random(20261105)
    inputs = [s + bytes([k]) * 4 for s in SHAPES for k in (0, 3, 7)] + \
             [bytes(r.getrandbits(8) for _ in range(r.randint(1, 160))) for _ in range(3000)]
    for data in inputs:
        target.test_one_input(data)
