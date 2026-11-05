"""Insular brand (ADR-0161): every mark, wordmark, symbol and lockup is derived here from one geometry.

Run from the repository root:
    uv run --with fonttools python brand/insular/build.py           # write brand/insular/svg/*.svg
    uv run --with fonttools,cairosvg python brand/insular/build.py --png   # also a contact sheet to review by eye

Never hand-edit the SVGs; change the geometry below and rebuild. Units are mark units on the 136 x 132 grid, font units
(2000 per em) for the wordmark.
"""
import argparse
import math
from pathlib import Path

HERE = Path(__file__).parent
OUT = HERE / "svg"
# Manrope (SIL Open Font License 1.1, https://github.com/google/fonts/blob/main/ofl/manrope/OFL.txt), fetched pinned by
# hash into the ignored build/ folder and used only to outline the wordmarks; the SVGs carry outlines, no font.
FONTS = {
    "Manrope-500.ttf": ("https://cdn.jsdelivr.net/fontsource/fonts/manrope@5.0.20/latin-500-normal.ttf",
                        "780ec331b2fe79bfc184a27859ad0b7931c7ad0c7c8d44013be389461b774d69"),
    "Manrope-600.ttf": ("https://cdn.jsdelivr.net/fontsource/fonts/manrope@5.0.20/latin-600-normal.ttf",
                        "73e2e86cf0063d4d92931c04e8d2f1b872b197089bff68d4fa6a2733925bdbb0"),
}
FONT_DIR = HERE.parent.parent / "build" / "fonts"


def font(name):
    """The pinned font file, fetched once; refuses a file whose hash differs."""
    import hashlib
    import urllib.request
    path = FONT_DIR / name
    url, sha = FONTS[name]
    if not path.exists():
        FONT_DIR.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=30) as r:
            path.write_bytes(r.read())
    got = hashlib.sha256(path.read_bytes()).hexdigest()
    if got != sha:
        path.unlink()
        raise SystemExit(f"{name}: sha256 {got} is not the pinned {sha}")
    return path

INK, PLUM, ORANGE, SIGNAL, PAPER, MIST, BLACK, WHITE = (
    "#1F0E36", "#3B1F63", "#EA6118", "#FF7A33", "#F7F3EE", "#B49BE0", "#111111", "#FFFFFF")
# colourway: (ink, gate) per ground
WAYS = {"light": (INK, ORANGE), "dark": (PAPER, SIGNAL), "mono": (BLACK, BLACK), "mono-white": (WHITE, WHITE)}

# The eye at the centre: a vesica (two arcs through the tips), the iris an open wake cut out of the ink, an orange pupil
# (the Chartroom, the out-of-band harbor that watches every crossing).
EX, EY, TIP_L, TIP_R, HH = 68.5, 66.0, 52.0, 85.0, 12.0
ER = ((TIP_R - TIP_L) / 2) ** 2 / (2 * HH) + HH / 2
VESICA = f"M{TIP_L} {EY} A{ER:.3f} {ER:.3f} 0 0 1 {TIP_R} {EY} A{ER:.3f} {ER:.3f} 0 0 1 {TIP_L} {EY} Z"
PUPIL, PUPIL_GAP, IRIS_R, IRIS_OPEN = 4.5, 1.2, 7.5, (20, 70)


def _eye_top(x):
    return EY + ER - HH - math.sqrt(ER ** 2 - (x - EX) ** 2)


def _eye_bottom(x):
    return EY - ER + HH + math.sqrt(ER ** 2 - (x - EX) ** 2)


# Four islands. Each route leaves the eye orthogonally, turns once at 45 degrees and runs straight at the island's
# centre, so gate, route and the wake's opening share one axis. (exit point, turn point, centre, radius)
ISLANDS = [
    ((TIP_L, EY), (43.1, EY), (24.1, 85.0), 17.0),
    ((65.55, round(_eye_top(65.55), 2)), (65.55, 32.0), (51.55, 18.0), 9.0),
    ((TIP_R, EY), (94.0, EY), (110.0, 50.0), 13.0),
    ((69.6, round(_eye_bottom(69.6), 2)), (69.6, 90.6), (90.0, 111.0), 6.5),
]
STROKE, KNOT, KNOT_CUT = 2.0, 3.4, 5.2
WAKE_CLEAR = 4.0           # a wake stops this far (stroke edge to stroke edge) from its arriving route
SMALL_STROKE = 4.5         # the small mark (below 48 px)


def wake_radius(r):
    return max(r * 1.24, r + 3.2)


def gate(turn, c, r):
    ux, uy = c[0] - turn[0], c[1] - turn[1]
    n = math.hypot(ux, uy)
    return c[0] - ux / n * r, c[1] - uy / n * r


def _line(d, ink, w=STROKE, cap="round"):
    return (f'<path d="{d}" fill="none" stroke="{ink}" stroke-width="{w}" stroke-linecap="{cap}" '
            f'stroke-linejoin="round"/>')


def _wake(turn, c, r, ink):
    R = wake_radius(r)
    th = math.atan2(turn[1] - c[1], turn[0] - c[0])          # towards the arriving route
    h = math.asin((WAKE_CLEAR + STROKE) / R)
    x0, y0 = c[0] + R * math.cos(th + h), c[1] + R * math.sin(th + h)
    x1, y1 = c[0] + R * math.cos(th - h), c[1] + R * math.sin(th - h)
    return _line(f"M{x0:.2f} {y0:.2f} A{R:.2f} {R:.2f} 0 1 1 {x1:.2f} {y1:.2f}", ink)


def _iris_holes():
    P = lambda r, a: f"{EX + r * math.cos(math.radians(a)):.3f} {EY - r * math.sin(math.radians(a)):.3f}"
    a0, a1 = IRIS_OPEN
    ro, ri, cap = IRIS_R + STROKE / 2, IRIS_R - STROKE / 2, STROKE / 2
    ring = (f" M{P(ro, a1)} A{ro} {ro} 0 1 0 {P(ro, a0)} A{cap} {cap} 0 0 0 {P(ri, a0)}"
            f" A{ri} {ri} 0 1 1 {P(ri, a1)} A{cap} {cap} 0 0 0 {P(ro, a1)} Z")
    g = PUPIL + PUPIL_GAP
    return ring + f" M{EX - g} {EY} a{g} {g} 0 1 0 {2 * g} 0 a{g} {g} 0 1 0 {-2 * g} 0 Z"


def mark(ink, gate_c, mid="k"):
    """The full mark, from 48 px."""
    gates = [gate(t, c, r) for _, t, c, r in ISLANDS]
    cut = "".join(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{KNOT_CUT}" fill="#000"/>' for x, y in gates)
    body = "".join(_line(f"M{e[0]} {e[1]} L{t[0]} {t[1]} L{g[0]:.2f} {g[1]:.2f}", ink)
                   for (e, t, c, r), g in zip(ISLANDS, gates))
    body += "".join(f'<circle cx="{c[0]}" cy="{c[1]}" r="{r}" fill="{ink}"/>' for _, _, c, r in ISLANDS)
    body += "".join(_wake(t, c, r, ink) for _, t, c, r in ISLANDS)
    body += f'<path d="{VESICA}{_iris_holes()}" fill="{ink}" fill-rule="evenodd"/>'
    knots = "".join(f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{KNOT}" fill="{gate_c}"/>' for x, y in gates)
    return (f'<defs><mask id="{mid}" maskUnits="userSpaceOnUse" x="-4" y="-4" width="144" height="140">'
            f'<rect x="-4" y="-4" width="144" height="140" fill="#fff"/>{cut}</mask></defs>'
            f'<g mask="url(#{mid})">{body}</g>{knots}'
            f'<circle cx="{EX}" cy="{EY}" r="{PUPIL}" fill="{gate_c}"/>')


def mark_small(ink, _gate=None, _mid=None):
    """Below 48 px: no wakes, gates or iris; heavier routes; the eye keeps a pupil hole."""
    body = "".join(_line(f"M{e[0]} {e[1]} L{t[0]} {t[1]} L{c[0]} {c[1]}", ink, SMALL_STROKE, "butt")
                   for e, t, c, r in ISLANDS)
    body += "".join(f'<circle cx="{c[0]}" cy="{c[1]}" r="{r}" fill="{ink}"/>' for _, _, c, r in ISLANDS)
    g = 4.6
    return body + (f'<path d="{VESICA} M{EX - g} {EY} a{g} {g} 0 1 0 {2 * g} 0 a{g} {g} 0 1 0 {-2 * g} 0 Z" '
                   f'fill="{ink}" fill-rule="evenodd"/>')


# Pharos (ADR-0115, ADR-0161): a lighthouse in the house style. The lantern is the wordmark's island glyph (disc, open
# wake, gate) under a 45 degree roof, on a gallery deck and a solid tapered tower with one level band; every gap 2.
PS, PCX, PCY, PGAP, PDY = 0.44, 68.0, 40.0, 2.0, 3.0
P_WAKE = 41 * PS
P_APEX = PCY - (P_WAKE + 1 + 1 + PGAP) * 2 ** 0.5
P_DECK = PCY + P_WAKE + 1 + PGAP + 1
P_TOP, P_BOT, P_TL, P_TR, P_BL, P_BR = P_DECK + 1 + PGAP, 118.0, 60.5, 75.5, 53.0, 83.0


def _tower_x(y, left=True):
    f = (y - P_TOP) / (P_BOT - P_TOP)
    return P_TL + (P_BL - P_TL) * f if left else P_TR + (P_BR - P_TR) * f


def pharos(ink, gate_c, mid="p"):
    """The Pharos symbol, from 48 px."""
    ox, oy = PCX - 50 * PS, PCY - 50 * PS
    p = lambda x, y: f"{ox + x * PS:.2f} {oy + y * PS:.2f}"
    gx, gy = ox + 70.51 * PS, oy + 29.49 * PS
    b1, b2 = P_TOP + 15, P_TOP + 19.5
    band = f"M{_tower_x(b1):.2f} {b1:.2f} H{_tower_x(b1, False):.2f} L{_tower_x(b2, False):.2f} {b2:.2f} H{_tower_x(b2):.2f} Z"
    return (f'<defs><mask id="{mid}" maskUnits="userSpaceOnUse" x="-4" y="-4" width="144" height="140">'
            f'<rect x="-4" y="-4" width="144" height="140" fill="#fff"/>'
            f'<circle cx="{gx:.2f}" cy="{gy:.2f}" r="{KNOT_CUT}" fill="#000"/></mask></defs>'
            f'<g transform="translate(0 {PDY})"><g mask="url(#{mid})">'
            f'<circle cx="{PCX}" cy="{PCY}" r="{29 * PS:.2f}" fill="{ink}"/>'
            f'<path d="M{p(90.44, 43.25)} A{P_WAKE:.2f} {P_WAKE:.2f} 0 1 1 {p(56.75, 9.56)}" fill="none" '
            f'stroke="{ink}" stroke-width="{STROKE}" stroke-linecap="round"/></g>'
            + _line(f"M52 {P_APEX + 16:.2f} L68 {P_APEX:.2f} L84 {P_APEX + 16:.2f} M53 {P_DECK:.2f} H83", ink)
            + f'<path d="M{P_TL} {P_TOP:.2f} H{P_TR} L{P_BR} {P_BOT} H{P_BL} Z {band}" fill="{ink}" fill-rule="evenodd"/>'
            f'<circle cx="{gx:.2f}" cy="{gy:.2f}" r="{KNOT}" fill="{gate_c}"/></g>')


def pharos_small(ink, _gate=None, _mid=None):
    """Below 48 px: no wake, gate or band; strokes 9 and 7, gaps of 9 units (1 px at 16 px)."""
    r, cy, g = 19.0, 48.0, 9.0
    apex, deck = cy - (r + g + 4.5) * 2 ** 0.5, cy + r + g + 3.5
    top = deck + 3.5 + 8
    return (f'<g transform="translate(0 2)"><circle cx="68" cy="{cy}" r="{r}" fill="{ink}"/>'
            + _line(f"M45 {apex + 23:.2f} L68 {apex:.2f} L91 {apex + 23:.2f}", ink, 9, "butt")
            + _line(f"M47 {deck:.2f} H89", ink, 7, "butt")
            + f'<path d="M57 {top:.2f} H79 L88 126 H48 Z" fill="{ink}"/></g>')


# The wordmark: Manrope SemiBold, lowercase, tracking -1.5%, outlined. The dot of the i is the gate (1.35 x Manrope's
# own dot) in its wake (stroke 36, gap 42, open at the upper right like the iris); below 32 px type the wake drops.
TRACK, TITTLE, W_GAP, W_SW, BELOW = -30, 104.5 * 1.35, 42.0, 36.0, 30
W_RW = TITTLE + W_GAP + W_SW / 2
W_CX, W_CY = 264.5, -(1080 + W_RW + W_SW / 2 + 120)
W_TOP = round(-W_CY + W_RW + W_SW / 2)


def _outline(text, font_file, dotless_i=False):
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.pens.transformPen import TransformPen
    from fontTools.ttLib import TTFont
    font = TTFont(font_file)
    cmap, gs = font.getBestCmap(), font.getGlyphSet()
    pen, x = SVGPathPen(gs), 0.0
    for n, ch in enumerate(text):
        name = cmap[0x131] if (ch == "i" and dotless_i) else cmap[ord(ch)]
        gs[name].draw(TransformPen(pen, (1, 0, 0, -1, x, 0)))
        x += gs[name].width + (TRACK if n < len(text) - 1 else 0)
    d = pen.getCommands()
    import re
    return re.sub(r"(\d+\.\d)\d+", r"\1", d), round(x)


def wordmark_body(ink, gate_c, d, wake=True):
    body = f'<path d="{d}" fill="{ink}"/><circle cx="{W_CX}" cy="{W_CY:.1f}" r="{TITTLE:.1f}" fill="{gate_c}"/>'
    if wake:
        p = lambda a: (W_CX + W_RW * math.cos(math.radians(a)), W_CY - W_RW * math.sin(math.radians(a)))
        (x0, y0), (x1, y1) = p(70), p(20)
        body += (f'<path d="M{x0:.1f} {y0:.1f} A{W_RW:.1f} {W_RW:.1f} 0 1 0 {x1:.1f} {y1:.1f}" fill="none" '
                 f'stroke="{ink}" stroke-width="{W_SW:.0f}" stroke-linecap="round"/>')
    return body


def svg(view, body, label, w=None, h=None):
    size = f' width="{w}" height="{h}"' if w else ""
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view}"{size} role="img" aria-label="{label}">'
            f'<title>{label}</title>{body}</svg>\n')


def build():
    files = {}
    d, ww = _outline("insular", font("Manrope-600.ttf"), dotless_i=True)
    dp, wp = _outline("pharos", font("Manrope-500.ttf"))
    for way, (ink, g) in WAYS.items():
        files[f"insular-mark-{way}.svg"] = svg("0 0 136 132", mark(ink, g), "Insular")
        files[f"insular-mark-small-{way}.svg"] = svg("0 0 136 132", mark_small(ink), "Insular")
        files[f"insular-wordmark-{way}.svg"] = svg(f"0 {-W_TOP} {ww} {W_TOP + BELOW}", wordmark_body(ink, g, d), "insular")
        files[f"insular-wordmark-small-{way}.svg"] = svg(
            f"0 {-round(-W_CY + TITTLE)} {ww} {round(-W_CY + TITTLE) + BELOW}", wordmark_body(ink, g, d, wake=False), "insular")
        files[f"pharos-symbol-{way}.svg"] = svg("0 0 136 132", pharos(ink, g), "Insular Pharos")
        files[f"pharos-symbol-small-{way}.svg"] = svg("0 0 136 132", pharos_small(ink), "Insular Pharos")
        # horizontal lockup, in px of the primary lockup: mark 173 x 168, wordmark at 94 px type, 34 px apart;
        # the wordmark's x-height is centred on the mark
        k, gap, mh, mw = 94 / 2000, 34, 168, 173
        base = mh / 2 + 1080 * k / 2
        width = mw + gap + ww * k
        files[f"insular-lockup-horizontal-{way}.svg"] = svg(
            f"0 {min(0, base - W_TOP * k):.1f} {width:.1f} {mh - min(0, base - W_TOP * k):.1f}",
            f'<svg x="0" y="0" width="{mw}" height="{mh}" viewBox="0 0 136 132">{mark(ink, g, "kl")}</svg>'
            f'<g transform="translate({mw + gap} {base:.2f}) scale({k})">{wordmark_body(ink, g, d)}</g>', "Insular")
        # Insular Pharos lockup: symbol, wordmark, a rule, "pharos" (Manrope Medium) in plum or mist
        mod = PLUM if way == "light" else MIST if way == "dark" else ink
        rule = MIST if way == "light" else PLUM if way == "dark" else ink
        k, sw, gap = 50 / 2000, 92, 16
        sh = sw * 132 / 136
        base = sh / 2 + 1080 * k / 2
        x1 = sw + gap
        x2 = x1 + ww * k + gap
        x3 = x2 + 2 + gap
        width = x3 + wp * k
        files[f"insular-pharos-lockup-{way}.svg"] = svg(
            f"0 0 {width:.1f} {sh:.1f}",
            f'<svg x="0" y="0" width="{sw}" height="{sh:.1f}" viewBox="0 0 136 132">{pharos(ink, g, "pl")}</svg>'
            f'<g transform="translate({x1} {base:.2f}) scale({k})">{wordmark_body(ink, g, d)}</g>'
            f'<rect x="{x2:.1f}" y="{base - 44 + 6:.1f}" width="2" height="44" rx="1" fill="{rule}"/>'
            f'<g transform="translate({x3:.1f} {base:.2f}) scale({k})"><path d="{dp}" fill="{mod}"/></g>', "Insular Pharos")
    return files


def contact_sheet(files, path):
    import cairosvg
    import re
    rows, y = [], 20
    for way, bg in (("light", PAPER), ("dark", INK)):
        names = [n for n in sorted(files) if n.endswith(f"-{way}.svg")]
        x, cells = 20, []
        for n in names:
            body = re.sub(r"^<svg[^>]*>", "", files[n].strip())[:-6]
            view = re.search(r'viewBox="([^"]+)"', files[n]).group(1)
            vw, vh = (float(v) for v in view.split()[2:])
            h = 120
            w = h * vw / vh
            cells.append(f'<svg x="{x:.0f}" y="{y}" width="{w:.0f}" height="{h}" viewBox="{view}">{body}</svg>')
            x += w + 30
        rows.append(f'<rect x="0" y="{y - 20}" width="100%" height="160" fill="{bg}"/>' + "".join(cells))
        y += 160
    sheet = (f'<svg xmlns="http://www.w3.org/2000/svg" width="2400" height="{y}"><rect width="100%" height="100%" '
             f'fill="{PAPER}"/>{"".join(rows)}</svg>')
    cairosvg.svg2png(bytestring=sheet.encode(), write_to=str(path))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--png", metavar="FILE", help="also write a contact sheet PNG (needs cairosvg)")
    a = ap.parse_args()
    files = build()
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.svg"):
        if old.name not in files:
            old.unlink()
    for name, text in files.items():
        (OUT / name).write_text(text, encoding="utf-8", newline="\n")
    print(f"{len(files)} SVGs in {OUT}")
    if a.png:
        contact_sheet(files, Path(a.png))


if __name__ == "__main__":
    main()
