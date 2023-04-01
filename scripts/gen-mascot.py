#!/usr/bin/env python3
"""Generates Desi, the SomeDesk mascot, in assets/mascot/ (one SVG per pose), and copies them to
docs/assets/mascot/ for the website.

A placeholder drawing: a chibi girl with mint hair, a dark hoodie with the mark's pointer on it,
and the pointer again as her hair clip. All poses share the head and body defined here; a pose
adds its arms, expression and props. Replace the files (keeping the names) to change the art.

Poses: wave, point, connect (holding a phone), key (holding the recovery key), cheer."""
import pathlib
import shutil

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "mascot"
DOCS = ROOT / "docs" / "assets" / "mascot"

INK = "#1a1d24"  # outlines
SKIN, SKIN_SHADE = "#ffe7dc", "#f6c9b8"
HAIR_LIGHT, HAIR, HAIR_DARK = "#a6efdc", "#6fcfbd", "#3e9fb3"
HOODIE, HOODIE_SHADE = "#2a2f3b", "#1f232c"
ACCENT_LIGHT, ACCENT, ACCENT_DEEP = "#b4f5e4", "#7dd3c0", "#3fa2c4"
BLUSH = "#ff9db0"
POINTER = "M26 22L26 42L31.2 37.3L34.8 45L38.6 43.3L35.1 35.7L42 35.7Z"  # as in gen-brand.py

DEFS = f"""<defs>
  <linearGradient id="hair" x1="0" y1="30" x2="0" y2="150" gradientUnits="userSpaceOnUse">
    <stop offset="0" stop-color="{HAIR_LIGHT}"/><stop offset="0.55" stop-color="{HAIR}"/><stop offset="1" stop-color="{HAIR_DARK}"/>
  </linearGradient>
  <linearGradient id="iris" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="{ACCENT_DEEP}"/><stop offset="0.6" stop-color="{ACCENT}"/><stop offset="1" stop-color="{ACCENT_LIGHT}"/>
  </linearGradient>
  <linearGradient id="accent" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="{ACCENT_LIGHT}"/><stop offset="0.5" stop-color="{ACCENT}"/><stop offset="1" stop-color="{ACCENT_DEEP}"/>
  </linearGradient>
</defs>"""

LINE = f'stroke="{INK}" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"'


def pointer(x: float, y: float, scale: float, rotate: float = 0, fill: str = "url(#accent)", line: float = 2.4) -> str:
    """The mark's pointer, its tip at (x, y), outlined `line` wide."""
    return (
        f'<path d="{POINTER}" transform="translate({x} {y}) rotate({rotate}) scale({scale}) translate(-26 -22)" '
        f'fill="{fill}" stroke="{INK}" stroke-width="{line / scale:.2f}" stroke-linejoin="round"/>'
    )


BACK_HAIR = f"""
  <path d="M100 34C58 34 40 66 42 100C43 124 40 142 52 152C60 158 72 154 74 146L76 110L124 110L126 146C128 154 140 158 148 152C160 142 157 124 158 100C160 66 142 34 100 34Z"
        fill="url(#hair)" {LINE}/>"""

BODY = f"""
  <path d="M84 206L82 238Q82 244 90 244L97 244Q99 244 99 238L100 206Z" fill="{HOODIE_SHADE}" {LINE}/>
  <path d="M116 206L118 238Q118 244 110 244L103 244Q101 244 101 238L100 206Z" fill="{HOODIE_SHADE}" {LINE}/>
  <path d="M80 244Q80 236 90 236L98 236Q102 236 102 242L102 246Q102 250 96 250L84 250Q80 250 80 246Z" fill="#f4f6f8" {LINE}/>
  <path d="M120 244Q120 236 110 236L102 236Q98 236 98 242L98 246Q98 250 104 250L116 250Q120 250 120 246Z" fill="#f4f6f8" {LINE}/>
  <path d="M74 150Q100 138 126 150L136 206Q138 214 128 214L72 214Q62 214 64 206Z" fill="{HOODIE}" {LINE}/>
  <path d="M90 214L92 200L108 200L110 214" fill="none" stroke="{HOODIE_SHADE}" stroke-width="2"/>
  <path d="M86 150Q100 162 114 150" fill="none" stroke="{ACCENT}" stroke-width="2.4" stroke-linecap="round"/>
  <path d="M93 156L91 172M107 156L109 172" stroke="{ACCENT}" stroke-width="2" stroke-linecap="round"/>
  <circle cx="91" cy="174" r="2" fill="{ACCENT_LIGHT}"/><circle cx="109" cy="174" r="2" fill="{ACCENT_LIGHT}"/>
  {pointer(97, 180, 0.45, 0, "url(#accent)", 1)}"""

FACE = f"""
  <ellipse cx="100" cy="98" rx="45" ry="41" fill="{SKIN}" {LINE}/>
"""

BANGS = f"""
  <path d="M52 100C48 60 70 40 100 40C130 40 152 60 148 100C142 86 136 78 128 74C126 84 120 90 112 92C114 82 112 74 108 68C102 80 92 88 80 90C84 82 84 76 82 70C74 78 66 86 52 100Z"
        fill="url(#hair)" {LINE}/>
  <path d="M100 41C97 28 104 18 116 16C108 22 106 30 108 40" fill="url(#hair)" {LINE}/>
  <circle cx="139" cy="66" r="9" fill="{HOODIE}" {LINE}/>
  {pointer(135.5, 59.5, 0.5, 15, ACCENT_LIGHT, 0.8)}"""

EYES_OPEN = f"""
  <g>
    <ellipse cx="80" cy="104" rx="9.5" ry="12" fill="{INK}"/>
    <ellipse cx="80" cy="106" rx="7.5" ry="9.5" fill="url(#iris)"/>
    <ellipse cx="80" cy="107" rx="3.6" ry="4.6" fill="{INK}"/>
    <circle cx="76.5" cy="100" r="3.3" fill="#fff"/><circle cx="83" cy="111" r="1.6" fill="#fff"/>
    <path d="M69 100Q70 90.5 80 90.5Q89 90.5 91 98" fill="none" stroke="{INK}" stroke-width="3.8" stroke-linecap="round"/>
  </g>
  <g>
    <ellipse cx="120" cy="104" rx="9.5" ry="12" fill="{INK}"/>
    <ellipse cx="120" cy="106" rx="7.5" ry="9.5" fill="url(#iris)"/>
    <ellipse cx="120" cy="107" rx="3.6" ry="4.6" fill="{INK}"/>
    <circle cx="116.5" cy="100" r="3.3" fill="#fff"/><circle cx="123" cy="111" r="1.6" fill="#fff"/>
    <path d="M131 100Q130 90.5 120 90.5Q111 90.5 109 98" fill="none" stroke="{INK}" stroke-width="3.8" stroke-linecap="round"/>
  </g>"""

EYES_HAPPY = f"""
  <path d="M71 106Q80 95 89 106M111 106Q120 95 129 106" fill="none" stroke="{INK}" stroke-width="3.4" stroke-linecap="round"/>"""

EYES_WINK = f"""
  <path d="M71 106Q80 95 89 106" fill="none" stroke="{INK}" stroke-width="3.4" stroke-linecap="round"/>
  <g>
    <ellipse cx="120" cy="104" rx="9.5" ry="12" fill="{INK}"/>
    <ellipse cx="120" cy="106" rx="7.5" ry="9.5" fill="url(#iris)"/>
    <ellipse cx="120" cy="107" rx="3.6" ry="4.6" fill="{INK}"/>
    <circle cx="116.5" cy="100" r="3.3" fill="#fff"/><circle cx="123" cy="111" r="1.6" fill="#fff"/>
    <path d="M131 100Q130 90.5 120 90.5Q111 90.5 109 98" fill="none" stroke="{INK}" stroke-width="3.8" stroke-linecap="round"/>
  </g>"""

BLUSH_MARKS = f"""
  <ellipse cx="68" cy="118" rx="7" ry="4" fill="{BLUSH}" opacity="0.55"/>
  <ellipse cx="132" cy="118" rx="7" ry="4" fill="{BLUSH}" opacity="0.55"/>"""

MOUTH_SMILE = f'<path d="M95 121Q100 126 105 121" fill="none" stroke="#9a4b55" stroke-width="2.2" stroke-linecap="round"/>'
MOUTH_OPEN = f'<path d="M94 120Q100 130 106 120Z" fill="#c4545f" stroke="#9a4b55" stroke-width="1.8" stroke-linejoin="round"/>'
MOUTH_O = f'<ellipse cx="100" cy="123" rx="3.2" ry="3.8" fill="#c4545f" stroke="#9a4b55" stroke-width="1.6"/>'


def arm(points: str, hand: tuple[float, float]) -> str:
    """A sleeve along `points` (a path) ending in a hand at `hand`."""
    hx, hy = hand
    return (
        f'<path d="{points}" fill="none" stroke="{INK}" stroke-width="15.5" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<path d="{points}" fill="none" stroke="{HOODIE}" stroke-width="11" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<circle cx="{hx}" cy="{hy}" r="7" fill="{SKIN}" {LINE}/>'
    )


ARM_LEFT_DOWN = arm("M76 156Q66 176 66 196", (66, 200))
ARM_RIGHT_DOWN = arm("M124 156Q134 176 134 196", (134, 200))


def sparkle(x: float, y: float, r: float, color: str = ACCENT_LIGHT) -> str:
    return (
        f'<path d="M{x} {y - r}Q{x + r * 0.18} {y - r * 0.18} {x + r} {y}Q{x + r * 0.18} {y + r * 0.18} {x} {y + r}'
        f'Q{x - r * 0.18} {y + r * 0.18} {x - r} {y}Q{x - r * 0.18} {y - r * 0.18} {x} {y - r}Z" fill="{color}"/>'
    )


def phone(x: float, y: float) -> str:
    """A phone showing a connected screen, its top-left corner at (x, y)."""
    return f"""
  <g transform="translate({x} {y}) rotate(-8)">
    <rect width="30" height="48" rx="6" fill="{HOODIE_SHADE}" {LINE}/>
    <rect x="4" y="6" width="22" height="34" rx="2.5" fill="#0e0f12"/>
    <rect x="7" y="10" width="16" height="10" rx="1.5" fill="{ACCENT}" opacity="0.85"/>
    <rect x="7" y="23" width="16" height="2.5" rx="1.2" fill="{ACCENT_DEEP}"/>
    <rect x="7" y="28" width="10" height="2.5" rx="1.2" fill="{ACCENT_DEEP}" opacity="0.7"/>
    {pointer(16, 14, 0.22)}
  </g>"""


def key(x: float, y: float) -> str:
    return f"""
  <g transform="translate({x} {y}) rotate(-35)">
    <circle cx="0" cy="0" r="11" fill="url(#accent)" {LINE}/>
    <circle cx="0" cy="0" r="4" fill="{SKIN}" stroke="{INK}" stroke-width="2"/>
    <path d="M10 0L40 0L40 8M32 0L32 6" fill="none" stroke="{INK}" stroke-width="9" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M10 0L40 0L40 8M32 0L32 6" fill="none" stroke="{ACCENT}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
  </g>"""


def figure(*, eyes: str, mouth: str, arms_back: str = "", arms_front: str = "", extra_back: str = "", extra: str = "") -> str:
    return "\n".join([extra_back, BACK_HAIR, arms_back, BODY, FACE, eyes, BLUSH_MARKS, mouth, BANGS, arms_front, extra])


POSES = {
    # Hello! One arm waves above the shoulder.
    "wave": figure(
        eyes=EYES_HAPPY,
        mouth=MOUTH_OPEN,
        arms_front=ARM_LEFT_DOWN + arm("M124 156Q148 150 156 122", (157, 116)),
        extra=f'<path d="M168 100Q176 108 172 120M176 94Q188 106 182 124" fill="none" stroke="{ACCENT}" stroke-width="3" stroke-linecap="round"/>',
    ),
    # Look over here: pointing to her right, where the UI is.
    "point": figure(
        eyes=EYES_OPEN,
        mouth=MOUTH_SMILE,
        arms_front=ARM_LEFT_DOWN + arm("M124 158Q150 156 170 150", (172, 149))
        + f'<path d="M177 147L185 144" stroke="{INK}" stroke-width="7.5" stroke-linecap="round"/>'
        + f'<path d="M177 147L185 144" stroke="{SKIN}" stroke-width="3.4" stroke-linecap="round"/>',
        extra=sparkle(192, 124, 7),
    ),
    # Connecting: holding up a phone.
    "connect": figure(
        eyes=EYES_OPEN,
        mouth=MOUTH_O,
        arms_front=ARM_LEFT_DOWN + phone(130, 128) + arm("M124 158Q140 170 140 158", (141, 156)),
        extra=sparkle(176, 120, 6) + sparkle(168, 104, 4, ACCENT),
    ),
    # Keep this safe: holding the recovery key, with a wink.
    "key": figure(
        eyes=EYES_WINK,
        mouth=MOUTH_SMILE,
        arms_front=key(144, 150) + arm("M76 156Q92 176 112 170", (114, 168)) + arm("M124 156Q136 166 136 156", (137, 152)),
        extra=sparkle(176, 132, 6),
    ),
    # All done: both arms up.
    "cheer": figure(
        eyes=EYES_HAPPY,
        mouth=MOUTH_OPEN,
        arms_back=arm("M76 156Q56 140 52 112", (51, 106)) + arm("M124 156Q144 140 148 112", (149, 106)),
        extra=sparkle(36, 84, 8) + sparkle(166, 78, 7, ACCENT) + sparkle(176, 120, 5) + sparkle(28, 126, 4, ACCENT),
    ),
}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)
    for name, body in POSES.items():
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="260" viewBox="0 0 200 260">\n'
            f"<!-- Desi, the SomeDesk mascot ({name}). Generated by scripts/gen-mascot.py. -->\n"
            f"{DEFS}\n{body}\n</svg>\n"
        )
        (OUT / f"{name}.svg").write_text(svg)
        shutil.copy(OUT / f"{name}.svg", DOCS / f"{name}.svg")
    print(f"wrote {len(POSES)} poses to {OUT.relative_to(ROOT)} and {DOCS.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
