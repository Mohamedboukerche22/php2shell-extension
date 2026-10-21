#!/usr/bin/env python3
"""Generate the extension icons (no external assets, pure Pillow).

A dark rounded square with a neon-green terminal chevron ">_" and a cyan
underline, matching the popup theme.

Usage:  python3 tools/make_icons.py
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "icons"
BG = (5, 8, 11, 255)
BORDER = (27, 42, 52, 255)
GREEN = (0, 255, 156, 255)
CYAN = (34, 211, 238, 255)
SHADOW = (0, 255, 156, 70)


def make(size: int) -> Image.Image:
    scale = 4
    s = size * scale
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    radius = int(s * 0.22)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=BG, outline=BORDER, width=max(1, s // 32))

    # faint neon glow behind the glyph
    glow = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.rounded_rectangle([s * 0.06, s * 0.06, s * 0.94, s * 0.94], radius=radius, fill=SHADOW)
    glow = glow.filter(__import__("PIL.ImageFilter", fromlist=["ImageFilter"]).GaussianBlur(radius=s * 0.10))
    img = Image.alpha_composite(img, glow)
    d = ImageDraw.Draw(img)

    lw = max(2, int(s * 0.085))
    x0, x1 = s * 0.26, s * 0.50
    y0, y1 = s * 0.34, s * 0.66

    # ">" chevron
    d.line([(x0, y0), (x1, s * 0.50)], fill=GREEN, width=lw)
    d.line([(x1, s * 0.50), (x0, y1)], fill=GREEN, width=lw)

    # "_" underscore
    ux0, ux1 = s * 0.56, s * 0.76
    uy = s * 0.66
    d.line([(ux0, uy), (ux1, uy)], fill=CYAN, width=lw)

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for size in (16, 32, 48, 128):
        path = OUT / f"icon{size}.png"
        make(size).save(path, "PNG")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
