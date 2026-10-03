#!/usr/bin/env python3
"""Build a labelled contact sheet (montage) from a directory of images.

Usage:
    python montage.py <indir> <outfile> [cols] [cell_width]

Handy for triaging dozens of photos (e.g. an FCC teardown PDF) in one look
instead of opening them one by one.
"""
import glob
import os
import sys

from PIL import Image, ImageDraw


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    indir, outfile = sys.argv[1], sys.argv[2]
    cols = int(sys.argv[3]) if len(sys.argv) > 3 else 5
    cell = int(sys.argv[4]) if len(sys.argv) > 4 else 520

    files = sorted(
        f for f in glob.glob(os.path.join(indir, "*"))
        if os.path.splitext(f)[1].lower() in (".jpg", ".jpeg", ".png", ".webp", ".gif")
    )
    if not files:
        print(f"no images in {indir}")
        return 1

    label_h = 26
    rows = (len(files) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * cell, rows * (cell + label_h)), (24, 24, 28))
    draw = ImageDraw.Draw(sheet)

    for idx, path in enumerate(files):
        try:
            im = Image.open(path).convert("RGB")
        except Exception as exc:  # noqa: BLE001
            print(f"skip {path}: {exc}")
            continue
        im.thumbnail((cell - 8, cell - 8), Image.LANCZOS)
        r, c = divmod(idx, cols)
        x = c * cell + (cell - im.width) // 2
        y = r * (cell + label_h) + label_h + (cell - im.height) // 2
        sheet.paste(im, (x, y))
        draw.text((c * cell + 6, r * (cell + label_h) + 7),
                  f"{idx:02d} {os.path.basename(path)}", fill=(235, 235, 235))

    sheet.save(outfile, quality=88)
    print(f"wrote {outfile}  {sheet.width}x{sheet.height}  from {len(files)} image(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
