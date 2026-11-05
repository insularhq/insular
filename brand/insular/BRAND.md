# Insular brand

Decided in ADR-0161. `build.py` holds the one geometry; every SVG in `svg/` is derived
from it. Never hand-edit an SVG: change the geometry, run
`uv run --with fonttools python brand/insular/build.py`, review the contact sheet (`--png FILE`, needs cairosvg) and
commit both. This folder is the source of truth for the drawings.

## The story
Four islands (sites) that each stand on their own. Routes leave a vessel under way between them, turn once and run
straight at an island; where a route comes ashore sits an orange gate, and the island's wake opens round it. The
vessel is a watchful eye: its pupil is the Chartroom, the out-of-band harbor that watches every crossing. Tagline
"Assess. Assure. Anchor."; strapline "Insular by design" (ADR-0127).

## Mark (136 x 132 units)
- **Islands:** radii 17, 13, 9 and 6.5, placed off every axis.
- **Routes:** stroke 2, round ends; out of the eye orthogonally, one 45 degree turn, then straight at the island's
  centre, so gate, route and wake opening share one axis.
- **Wakes:** radius r + 24% (at least r + 3.2); each opens symmetrically round its route and stops 4 units clear of it.
- **Gates:** orange knots r 3.4 with a 1.8 cut-out, a true knockout (works on any ground and in one colour).
- **The eye:** a vesica 33 by 24 (two arcs); the iris an open wake cut out of the ink, opening at the upper right; an
  orange pupil.
- **Small mark (below 48 px):** no wakes, gates or iris; routes 4.5; the eye keeps a pupil hole.
- **Clear space:** 17 units on every side.

## Wordmark
Manrope SemiBold, lowercase, tracking -1.5%, outlined. The dot of the i is the gate: 1.35 times Manrope's own dot, in
an ink wake (stroke 36, gap 42, open at the upper right). Below 32 px type use the small wordmark (no wake). Plain
type "insular" only where the outlines cannot be used (plain-text mail).

## Pharos (ADR-0115)
A lighthouse in the house style: the lantern is the wordmark's island glyph (disc, open wake, gate) under a 45 degree
roof, on a gallery deck and a solid tapered tower with one level band; every gap 2 units. Below 48 px a separate
drawing without wake, gate and band. The name Pharos never stands alone: the lockup is symbol, insular wordmark, a
rule and "pharos" in Manrope Medium (plum on paper, mist on deep purple). The symbol alone appears only inside the
product (app icon, favicon, pane header). Keep clear of diagonal or red and white bands and of a beam wedge: other
lighthouse marks in this market use them.

## Colour
Deep purple #1F0E36 carries everything; plum #3B1F63 for secondary text; orange #EA6118 marks gates only (signal
#FF7A33 on deep purple), never text; paper #F7F3EE as the ground; mist #B49BE0 for the pharos name on deep purple and the rule
beside it on paper. Colourways in `svg/`: light, dark,
mono (black), mono-white.

## Don't
Close the wakes; colour the islands orange; rotate, stretch or shadow the mark; set it on a busy ground; put a module
symbol inside the house mark or the wordmark.

## Files
`svg/insular-mark-*`, `insular-mark-small-*`, `insular-wordmark-*`, `insular-wordmark-small-*`,
`insular-lockup-horizontal-*`, `pharos-symbol-*`, `pharos-symbol-small-*`, `insular-pharos-lockup-*`. Fonts: Manrope
500 and 600 under the SIL Open Font License 1.1 (https://github.com/google/fonts/blob/main/ofl/manrope/OFL.txt),
fetched by `build.py` pinned by SHA-256 into the ignored `build/fonts/` and used only to outline the wordmarks; the SVGs
carry outlines, never a font.
