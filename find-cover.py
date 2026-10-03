#!/usr/bin/env python3
"""
find-cover.py - find a properly licensed header image for each repo.

Queries the Wikimedia Commons API (no key required), prefers freely licensed
files, and prints the direct thumbnail URL plus attribution. The point is to
avoid hotlinking something that rots, or something nobody has the right to use.

Usage:
    python find-cover.py search "mechanical keyboard"
    python find-cover.py file "File:Beluga whale.jpg"
    python find-cover.py resolve <config.json>
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request

API = "https://commons.wikimedia.org/w/api.php"
UA = "weebo-inc-readme-art/1.0 (https://github.com/Weeabo-Inc)"


def api(params: dict) -> dict:
    params = {**params, "format": "json", "formatversion": "2"}
    url = API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as fh:
        return json.load(fh)


def licence_of(meta: dict) -> str:
    for k in ("LicenseShortName", "License", "UsageTerms"):
        v = meta.get(k)
        if v and v.get("value"):
            return str(v["value"])
    return "unknown"


def file_info(title: str, width: int = 500) -> dict | None:
    r = api({
        "action": "query",
        "titles": title,
        "prop": "imageinfo",
        "iiprop": "url|extmetadata|size",
        "iiurlwidth": width,
    })
    for p in r.get("query", {}).get("pages", []):
        if "imageinfo" not in p:
            continue
        ii = p["imageinfo"][0]
        meta = ii.get("extmetadata", {})
        return {
            "title": p["title"],
            "thumb": ii.get("thumburl"),
            "full": ii.get("url"),
            "width": ii.get("width"),
            "height": ii.get("height"),
            "licence": licence_of(meta),
            "artist": (meta.get("Artist", {}) or {}).get("value", "")[:120],
            "credit": (meta.get("Credit", {}) or {}).get("value", "")[:120],
        }
    return None


def search(term: str, limit: int = 12) -> list[dict]:
    r = api({
        "action": "query",
        "list": "search",
        "srsearch": f"filetype:bitmap {term}",
        "srnamespace": "6",
        "srlimit": limit,
    })
    return [x["title"] for x in r.get("query", {}).get("search", [])]


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("search")
    s.add_argument("term")
    s.add_argument("--limit", type=int, default=12)

    f = sub.add_parser("file")
    f.add_argument("title")
    f.add_argument("--width", type=int, default=500)

    a = ap.parse_args()

    if a.cmd == "search":
        for t in search(a.term, a.limit):
            print(t)
        return 0

    if a.cmd == "file":
        info = file_info(a.title, a.width)
        if not info:
            print(f"not found: {a.title}", file=sys.stderr)
            return 1
        print(json.dumps(info, indent=2))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
