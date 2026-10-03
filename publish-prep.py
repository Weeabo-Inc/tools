#!/usr/bin/env python3
"""
publish-prep.py - stage sanitised repos for public release.

WHY THIS EXISTS
---------------
The source was written on one machine, with one layout, and it shows: absolute
paths (`P:\\Reverseing\\Arlo\\...`), a Windows username, and a LAN IP are baked
into scripts, docs and Rust defaults. Publishing that verbatim leaks the
author's filesystem layout and personal identifiers, and also makes the code
useless to anyone else.

This script stages a clean tree per repository:
  * hardcoded absolute paths  -> placeholders or relative paths
  * personal identifiers      -> redacted
  * README from the readmes/ staging area, renamed to README.md
  * build artefacts and secrets never copied

It is deliberately conservative: it reports every substitution it makes, so the
diff can be reviewed before anything is pushed.

Usage:
    python publish-prep.py --check      # report only, change nothing
    python publish-prep.py --stage      # write staged trees to publish/
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(r"<REPO_ROOT>")
STAGE = ROOT / "publish"
README_SRC = ROOT / "readmes"

USERNAME = "<USER>"
# Public-ish, but still the author's home network - no reason to publish it.
LAN_IP = "<LAN_IP>"

# Directories that must never be copied: build output, VCS, caches, and anything
# that could carry credentials or bulk binaries.
SKIP_DIRS = {
    "target", "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".idea", ".vscode", "dist", "build",
    # --- EXCLUDED FROM PUBLICATION -----------------------------------------
    # Vendor firmware and third-party code. These are NOT ours to redistribute:
    # publishing an OEM's firmware images from a public repo is the fastest way
    # to earn a takedown, and it adds nothing to reproducibility - the READMEs
    # describe the *method*, which is the actual contribution.
    #
    #   stock, fw, extracted        - AULA / Suoai firmware images
    #   sonix-tool, s98-installer,
    #   s98-payload, embedded       - extracted vendor installers and payloads
    #   s98pro                      - SN32F290.hex and friends
    #   ghidra                      - project files built from a vendor binary
    #   libusb, king                - third-party (libusb LGPL, King checkm8 port)
    #   ref                         - reference implementations (brokkr, others)
    "stock", "fw", "extracted", "sonix-tool", "s98-installer", "s98-payload",
    "embedded", "s98pro", "ghidra", "libusb", "king", "ref",
}

# Individual files excluded by name, wherever they appear.
SKIP_FILENAMES = {
    # Vendor firmware images (any extension)
    "S98Pro_SN32F290_stock.bin", "S98Pro_SN32F290_stock.hex",
    "SN32F290_firmware.bin", "SN32F290.hex", "embedded_image.bin",
    "blob_256k.bin", "blob_142k.bin", "extracted_fw.bin",
    "HFD8KCZ700_V1.51.bin",
    # Vendor flasher configuration and installer fragments
    "Sonix_flasher_UISettings.ini", "payload_unpacked.bin",
    # Third-party source we vendored during reverse engineering
    "brokkr_odin_cmd.cpp", "brokkr_win_usbfs_device.cpp",
    "brokkr_win_usbfs_conn.cpp", "odin_protocol.cpp", "usb_device.cpp",
    # Vendor research notes (superseded; the README covers the method)
    "SONIX-RESEARCH.md",
}

# The King build script clones third-party source at run time, so it is kept -
# but it must not ship any of that source itself. Verified: it only shells out
# to `git clone`.

SKIP_EXT = {".pdb", ".exe", ".dll", ".o", ".obj", ".lib", ".rlib", ".zip", ".7z", ".rar",
            # Transcripts and generated data. These are UTF-16LE PowerShell captures and
            # generated feeds: they are not source, they carry absolute paths, and a
            # decode-with-replace pass will NOT match literals inside them. Cheaper and
            # safer to exclude them than to sanitise them.
            ".log", ".jsonl", ".d", ".rmeta"}
SKIP_NAMES = {".env", "credentials.json", "config.json", "state.json",
              "history.jsonl", "iphone.json", "id_rsa", "id_ed25519"}

TEXT_EXT = {".rs", ".py", ".ps1", ".md", ".json", ".toml", ".mjs", ".js",
            ".yml", ".yaml", ".ini", ".txt", ".cfg", ".sh", ".bat", ".xml",
            ".html", ".css", ".gitignore", ""}


@dataclass
class Repo:
    name: str
    source: Path
    readme: Path
    description: str
    topics: list[str] = field(default_factory=list)


REPOS = [
    Repo("phonewatch", ROOT / "phonewatch", README_SRC / "phonewatch-README.md",
         "Live Android/USB device-state monitor for Windows. Distinguishes absent from descriptor_failed.",
         ["rust", "usb", "windows", "device-monitor", "setupapi", "android"]),
    Repo("iwhale", ROOT / "iphone", README_SRC / "iwhale-README.md",
         "iPhone presence and battery monitor. Explains why a plugged-in phone isn't talking to you.",
         ["powershell", "ios", "libimobiledevice", "usb", "monitoring"]),
    Repo("klabsat", ROOT / "dashboard", README_SRC / "klabsat-README.md",
         "Zero-dependency local dashboard rendering two device monitors. No npm, no CDN, works offline.",
         ["python", "dashboard", "zero-dependency", "self-hosted", "monitoring"]),
    Repo("odin-rs", ROOT / "odin-rs", README_SRC / "odin-rs-README.md",
         "Samsung Odin/Thor protocol client built as a diagnostic instrument.",
         ["rust", "samsung", "odin", "heimdall", "usb", "reverse-engineering"]),
    Repo("sonix-rs", ROOT / "sonix", README_SRC / "sonix-rs-README.md",
         "Sonix SN32F2xx ISP protocol tool plus firmware recovery from vendor updater executables.",
         ["rust", "sonix", "isp", "firmware", "keyboard", "reverse-engineering"]),
    Repo("keyboard-research", ROOT / "keyboard", README_SRC / "keyboard-research-README.md",
         "HID/USB enumeration, report-descriptor capture and PE resource firmware extraction.",
         ["python", "hid", "usb", "reverse-engineering", "firmware", "pe-analysis"]),
    Repo("a9lab", ROOT / "a9lab", README_SRC / "a9lab-README.md",
         "Apple A9 security research: guided DFU entry, device identification, findings methodology.",
         ["security-research", "ios", "checkm8", "dfu", "arm64", "a9"]),
    Repo("dsh-whale-chan", ROOT / "whale-chan-plugin", README_SRC / "dsh-whale-chan-README.md",
         "A cranky whale-maid persona plugin for DeepSeek Harness.",
         ["dsh-plugin", "deepseek-harness", "persona", "javascript"]),
]

# --- substitution rules ----------------------------------------------------
# LITERAL string replacements, not regex.
#
# This is deliberate. An earlier version used re.compile(r"P:\\\\Reverseing\\\\Arlo")
# which looks for a literal `p:\\Reverseing\\Arlo` (two backslashes) and therefore
# matched NOTHING - the real text has one backslash. The check reported "nothing
# sanitised" for every repo, which looked like success and was actually total
# failure. A literal str.replace cannot make that mistake.
#
# Ordered longest-first so that a more specific path is rewritten before a
# broader one can consume part of it.

SUBS: list[tuple[str, str]] = [
    # Absolute project root, forward- and back-slash forms.
    ("P:\\Reverseing\\Arlo", "<REPO_ROOT>"),
    ("<REPO_ROOT>", "<REPO_ROOT>"),
    ("p:\\Reverseing\\Arlo", "<REPO_ROOT>"),
    # Home directory.
    ("C:\\Users\\<USER>", "<HOME>"),
    ("<HOME>", "<HOME>"),
    ("\\\\<USER>\\", "\\\\<USER>\\"),
    # Host name.
    ("DESKTOP-7J6ESEF", "<HOST>"),
    # LAN address (public-ish, but it is still the author's home network).
    (LAN_IP, "<LAN_IP>"),
    # Bare username last, so it catches prose and code that the path rules missed.
    ("<USER>", "<USER>"),
]


def sanitise(text: str) -> tuple[str, dict[str, int]]:
    """Apply literal substitutions; return new text and a per-rule hit count."""
    counts: dict[str, int] = {}
    for find, repl in SUBS:
        n = text.count(find)
        if n:
            key = f"{find} -> {repl}"
            counts[key] = counts.get(key, 0) + n
            text = text.replace(find, repl)
    return text, counts


def is_text(p: Path) -> bool:
    if p.suffix.lower() in TEXT_EXT:
        return True
    if p.name in {".gitignore", "LICENSE", "Makefile"}:
        return True
    return False


def sanitise(text: str) -> tuple[str, dict[str, int]]:
    """Apply LITERAL substitutions; return new text and a per-rule hit count."""
    counts: dict[str, int] = {}
    for find, repl in SUBS:
        n = text.count(find)
        if n:
            key = f"{find} -> {repl}"
            counts[key] = counts.get(key, 0) + n
            text = text.replace(find, repl)
    return text, counts


def iter_files(src: Path):
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = Path(root) / f
            if p.suffix.lower() in SKIP_EXT:
                continue
            if p.name in SKIP_NAMES or p.name in SKIP_FILENAMES:
                continue
            yield p


def excluded_report(src: Path) -> tuple[int, int]:
    """Count what the exclusions keep out, so the exclusion is visible not silent."""
    n_files = 0
    n_bytes = 0
    for root, dirs, files in os.walk(src):
        # A directory named in SKIP_DIRS is wholly excluded
        keep_dirs = [d for d in dirs if d not in SKIP_DIRS]
        for d in dirs:
            if d in SKIP_DIRS:
                for r2, _d2, f2 in os.walk(Path(root) / d):
                    for f in f2:
                        n_files += 1
                        try:
                            n_bytes += (Path(r2) / f).stat().st_size
                        except OSError:
                            pass
        dirs[:] = keep_dirs
        for f in files:
            p = Path(root) / f
            if p.suffix.lower() in SKIP_EXT or p.name in SKIP_NAMES or p.name in SKIP_FILENAMES:
                n_files += 1
                try:
                    n_bytes += p.stat().st_size
                except OSError:
                    pass
    return n_files, n_bytes


def stage_repo(repo: Repo, check_only: bool) -> dict:
    report = {"repo": repo.name, "files": 0, "subs": {}, "skipped": 0, "copied_binary": 0}
    if not repo.source.exists():
        report["error"] = "source missing"
        return report

    dst_root = STAGE / repo.name
    if not check_only:
        if dst_root.exists():
            shutil.rmtree(dst_root, ignore_errors=True)
        dst_root.mkdir(parents=True, exist_ok=True)

    # Report what the exclusions withheld, so it is visible rather than silent.
    ex_n, ex_b = excluded_report(repo.source)
    report["excluded_files"] = ex_n
    report["excluded_kb"] = round(ex_b / 1024)

    for p in iter_files(repo.source):
        rel = p.relative_to(repo.source)
        dst = dst_root / rel
        try:
            raw = p.read_bytes()
        except OSError:
            report["skipped"] += 1
            continue

        if is_text(p):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", "replace")
            new, counts = sanitise(text)
            for k, v in counts.items():
                report["subs"][k] = report["subs"].get(k, 0) + v
            if not check_only:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_text(new, encoding="utf-8")
        else:
            # non-text asset: copy as-is (images, sample data)
            report["copied_binary"] += 1
            if not check_only:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(raw)
        report["files"] += 1

    # README last, so it always wins.
    if repo.readme.exists():
        text = repo.readme.read_text(encoding="utf-8")
        new, counts = sanitise(text)
        for k, v in counts.items():
            report["subs"][k] = report["subs"].get(k, 0) + v
        if not check_only:
            (dst_root / "README.md").write_text(new, encoding="utf-8")
        report["files"] += 1
    else:
        report["error"] = f"README missing: {repo.readme}"

    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="report only")
    ap.add_argument("--stage", action="store_true", help="write staged trees")
    args = ap.parse_args()
    check_only = not args.stage

    total_subs: dict[str, int] = {}
    print("=" * 74)
    print(f" PUBLISH PREP - {'CHECK ONLY' if check_only else 'STAGING'}")
    print("=" * 74)
    for repo in REPOS:
        r = stage_repo(repo, check_only)
        status = "OK " if "error" not in r else "ERR"
        print(f"\n[{status}] {r['repo']}")
        print(f"       files staged : {r['files']}  (assets copied: {r['copied_binary']}, skipped: {r['skipped']})")
        if r.get("excluded_files"):
            print(f"       EXCLUDED     : {r['excluded_files']} files / {r['excluded_kb']:,} KB withheld "
                  f"(vendor firmware, third-party code, build output)")
        if r["subs"]:
            for k, v in sorted(r["subs"].items(), key=lambda x: -x[1]):
                print(f"       sanitised    : {v:>4} x {k!r}")
                total_subs[k] = total_subs.get(k, 0) + v
        else:
            print("       sanitised    : (nothing matched)")
        if "error" in r:
            print(f"       ERROR        : {r['error']}")

    print()
    print("=" * 74)
    print(" TOTALS")
    print("=" * 74)
    for k, v in sorted(total_subs.items(), key=lambda x: -x[1]):
        print(f"   {v:>5}  {k!r}")
    print(f"\n   stage dir: {STAGE}")
    if check_only:
        print("   (check only - nothing written. Re-run with --stage)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
