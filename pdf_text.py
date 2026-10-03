#!/usr/bin/env python3
"""Crude PDF text/strings extractor (no third-party deps).

Usage:
    python pdf_text.py <file.pdf> [min_run_length]

Decompresses every FlateDecode stream and prints runs of printable ASCII.
Good enough to recover device descriptions, firmware versions, model numbers,
and antenna tables from FCC test reports.
"""
import re
import sys
import zlib


def strings_from(data: bytes, minrun: int) -> list:
    return [m.group().decode("latin-1") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minrun, data)]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    minrun = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    raw = open(path, "rb").read()
    print(f"### {path}  ({len(raw)} bytes)")

    seen = set()
    n_streams = 0
    for m in re.finditer(rb"stream\r?\n", raw):
        start = m.end()
        end = raw.find(b"endstream", start)
        if end == -1:
            continue
        chunk = raw[start:end]
        dec = None
        for candidate in (chunk, chunk.rstrip(b"\r\n")):
            try:
                dec = zlib.decompress(candidate)
                break
            except zlib.error:
                continue
        if dec is None:
            continue
        n_streams += 1
        for s in strings_from(dec, minrun):
            s = s.strip()
            if len(s) >= minrun and s not in seen:
                seen.add(s)
                print(s)

    # Also pick up uncompressed strings (metadata, object dictionaries)
    for s in strings_from(raw, max(minrun, 20)):
        s = s.strip()
        if s not in seen:
            seen.add(s)
            print(s)
    print(f"### decompressed {n_streams} stream(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
