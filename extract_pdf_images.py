#!/usr/bin/env python3
"""Extract embedded images from a PDF, with graceful backend fallback.

Usage:
    python extract_pdf_images.py <input.pdf> <outdir>

Backends, tried in order:
  1. PyMuPDF (fitz)  - cleanest, handles all filter types
  2. pypdf           - XObject level extraction
  3. raw carving     - locates DCTDecode (JPEG) and PNG payloads by signature
"""
import os
import re
import sys
import zlib


def via_fitz(path, outdir):
    import fitz  # type: ignore
    doc = fitz.open(path)
    n = 0
    for pno in range(len(doc)):
        for img in doc[pno].get_images(full=True):
            xref = img[0]
            base = doc.extract_image(xref)
            ext = base["ext"]
            fn = os.path.join(outdir, f"p{pno+1:02d}_x{xref}.{ext}")
            with open(fn, "wb") as fh:
                fh.write(base["image"])
            n += 1
            print(f"  [fitz] {fn}  {base['width']}x{base['height']} {len(base['image'])} bytes")
    doc.close()
    return n


def via_pypdf(path, outdir):
    from pypdf import PdfReader  # type: ignore
    reader = PdfReader(path)
    n = 0
    for pno, page in enumerate(reader.pages, 1):
        try:
            images = page.images
        except Exception as exc:  # noqa: BLE001
            print(f"  [pypdf] page {pno}: {exc}")
            continue
        for ino, im in enumerate(images, 1):
            name = getattr(im, "name", f"img{ino}")
            data = im.data
            ext = os.path.splitext(name)[1].lstrip(".") or "bin"
            fn = os.path.join(outdir, f"p{pno:02d}_{ino:02d}_{os.path.basename(name)}.{ext}")
            with open(fn, "wb") as fh:
                fh.write(data)
            n += 1
            print(f"  [pypdf] {fn}  {len(data)} bytes")
    return n


def carve(path, outdir):
    """Signature-based carving: good enough for DCTDecode JPEGs and PNGs."""
    raw = open(path, "rb").read()
    n = 0

    # --- JPEGs (DCTDecode streams are stored as complete JFIF/Exif blobs) ---
    for m in re.finditer(b"\xff\xd8\xff", raw):
        start = m.start()
        end = raw.find(b"\xff\xd9", start + 3)
        if end == -1:
            continue
        end += 2
        blob = raw[start:end]
        if len(blob) < 4096:
            continue
        fn = os.path.join(outdir, f"carve_{n:03d}.jpg")
        with open(fn, "wb") as fh:
            fh.write(blob)
        n += 1
        print(f"  [carve] {fn}  {len(blob)} bytes")

    # --- PNGs ---
    for m in re.finditer(b"\x89PNG\r\n\x1a\n", raw):
        start = m.start()
        end = raw.find(b"IEND", start)
        if end == -1:
            continue
        end += 8
        blob = raw[start:end]
        if len(blob) < 4096:
            continue
        fn = os.path.join(outdir, f"carve_{n:03d}.png")
        with open(fn, "wb") as fh:
            fh.write(blob)
        n += 1
        print(f"  [carve] {fn}  {len(blob)} bytes")

    # --- FlateDecode image XObjects (no predictor handling; report only) ---
    for m in re.finditer(rb"/Subtype\s*/Image", raw):
        head = raw[max(0, m.start() - 1200):m.start()]
        w = re.findall(rb"/Width\s+(\d+)", head)
        h = re.findall(rb"/Height\s+(\d+)", head)
        flt = re.findall(rb"/Filter\s*/(\w+)", head)
        print(f"  [info] image XObject near {m.start()}: width={w[-1:] } height={h[-1:]} filter={flt[-1:]}")
    return n


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    path, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)

    for name, fn in (("PyMuPDF/fitz", via_fitz), ("pypdf", via_pypdf)):
        try:
            total = fn(path, outdir)
            print(f"BACKEND {name}: extracted {total} image(s)")
            if total:
                return 0
        except ImportError:
            print(f"BACKEND {name}: not installed")
        except Exception as exc:  # noqa: BLE001
            print(f"BACKEND {name}: failed -> {exc!r}")

    print("BACKEND raw carving")
    total = carve(path, outdir)
    print(f"BACKEND raw carving: extracted {total} image(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
