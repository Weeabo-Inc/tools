#!/usr/bin/env python3
"""Crop + upscale a region of an image (for reading chip markings / silkscreen).

Usage:
    python crop.py <in> <out> <x> <y> <w> <h> [scale] [--rotate180]

Coordinates are in source-image pixels. Scale defaults to 3.
--rotate180 is handy for upside-down FCC photo shots.
"""
import sys

from PIL import Image


def main() -> int:
    if len(sys.argv) < 7:
        print(__doc__)
        return 2
    src, dst = sys.argv[1], sys.argv[2]
    x, y, w, h = (int(v) for v in sys.argv[3:7])
    scale = float(sys.argv[7]) if len(sys.argv) > 7 and not sys.argv[7].startswith("--") else 3.0

    im = Image.open(src).convert("RGB")
    box = (max(0, x), max(0, y), min(im.width, x + w), min(im.height, y + h))
    crop = im.crop(box)
    if "--rotate180" in sys.argv:
        crop = crop.rotate(180)
    new = (max(1, int(crop.width * scale)), max(1, int(crop.height * scale)))
    crop = crop.resize(new, Image.LANCZOS)
    crop.save(dst, quality=95)
    print(f"wrote {dst}  src_box={box} -> {new[0]}x{new[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
