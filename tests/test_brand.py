"""The Insular brand (ADR-0161): built from one source, says Insular, safe to embed."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRAND = ROOT / "brand" / "insular"
KINDS = ["insular-mark", "insular-mark-small", "insular-wordmark", "insular-wordmark-small", "insular-lockup-horizontal",
         "pharos-symbol", "pharos-symbol-small", "insular-pharos-lockup"]
WAYS = ["light", "dark", "mono", "mono-white"]


def test_the_brand_is_built_from_one_source_and_says_insular():
    built = {p.name for p in (BRAND / "svg").glob("*.svg")}
    expected = {f"{k}-{w}.svg" for k in KINDS for w in WAYS}
    assert built == expected, f"missing {sorted(expected - built)}, unexpected {sorted(built - expected)}"
    for name in sorted(built):
        text = (BRAND / "svg" / name).read_text(encoding="utf-8")
        assert text.isascii(), name
        assert "isolae" not in text.lower(), f"{name} still names Isolae"
        label = re.search(r'aria-label="([^"]+)"', text).group(1)
        assert label.lower().startswith("insular"), f"{name}: label {label!r}"
        assert "Pharos" in label or not name.startswith(("pharos", "insular-pharos")), \
            f"{name}: Pharos never stands without the house name (ADR-0115)"
        assert "<script" not in text and "href" not in text and "<image" not in text, f"{name}: no script or external reference"
    src = (BRAND / "build.py").read_text(encoding="utf-8")
    assert "Never hand-edit the SVGs" in src and (BRAND / "BRAND.md").exists()
    assert "OFL" in src and len(re.findall(r'"[0-9a-f]{64}"', src)) == 2, "both fonts pinned by hash, their licence named"
    assert not (BRAND / "fonts").exists(), "no font files in the repository: build.py fetches them pinned"
