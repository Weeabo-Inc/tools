#!/usr/bin/env python3
"""
publish-tonight.py - stage and push tonight's keyboard work.

Three destinations:
  NEW      Weeabo-Inc/s98rs               the firmware project (PAC + fw + usb driver + tools)
  UPDATE   Weeabo-Inc/sonix-rs            the flash tool, now with flash-write and capture
  UPDATE   Weeabo-Inc/keyboard-research   the new reverse-engineering documents

WHAT IS DELIBERATELY EXCLUDED
-----------------------------
research/ contains ~1.5 GB of cloned third-party trees, none of which may be
republished:
    qmk_firmware               GPL-2.0
    SonixFlasherC              GPL-3.0
    ChibiOS-Contrib            Apache-2.0, but a clone - link, do not vendor
    sonix-keyboard-bootloader  NO LICENCE AT ALL - all rights reserved
    mkdb, refs, pac-crate      bulk data and build artefacts (1.3 GB)

Only our own documents and scripts from research/ are published, plus the vendor
SVD. The SVD is a CMSIS register description - documentation of the chip's
interface, distributed by vendors for development - not firmware or code.

Usage:
    python publish-tonight.py --check
    python publish-tonight.py --stage
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(r"<REPO_ROOT>")
STAGE = ROOT / "publish2"

# Extensions that must never be copied (build output, binaries, caches).
SKIP_EXT = {
    ".rlib", ".rmeta", ".o", ".obj", ".lib", ".a", ".exe", ".dll", ".pdb",
    ".d", ".zip", ".7z", ".rar", ".log", ".jsonl", ".bin", ".hex", ".pcap",
}
# Directories that must never be walked into.
SKIP_DIRS = {
    "target", "node_modules", ".git", "__pycache__", ".venv", "venv",
    ".idea", ".vscode", "dist", "build", "registry", "cache", "incremental",
}
SKIP_NAMES = {".env", "config.json", "state.json", "history.jsonl", "iphone.json"}

# Literal substitutions. Plain str.replace - see publish-prep.py for why regex
# was a mistake there.
SUBS = [
    ("P:\\Reverseing\\Arlo", "<REPO_ROOT>"),
    ("<REPO_ROOT>", "<REPO_ROOT>"),
    ("C:\\Users\\<USER>", "<HOME>"),
    ("<HOME>", "<HOME>"),
    ("<USER>", "<USER>"),
    ("<LAN_IP>", "<LAN_IP>"),
]

TEXT_EXT = {".rs", ".py", ".toml", ".md", ".ps1", ".mjs", ".js", ".yml", ".yaml",
            ".txt", ".ini", ".svd", ".json", ".cfg", ".sh", ".bat", ""}


def sanitise(text: str) -> tuple[str, dict[str, int]]:
    counts: dict[str, int] = {}
    for find, repl in SUBS:
        n = text.count(find)
        if n:
            counts[find] = counts.get(find, 0) + n
            text = text.replace(find, repl)
    return text, counts


def copy_tree(src: Path, dst: Path, report: dict, allow: set[str] | None = None):
    """Copy src into dst, sanitising text and skipping excluded paths."""
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            p = Path(root) / f
            if p.suffix.lower() in SKIP_EXT or p.name in SKIP_NAMES:
                continue
            rel = p.relative_to(src)
            if allow is not None and rel.parts and rel.parts[0] not in allow:
                continue
            try:
                raw = p.read_bytes()
            except OSError:
                continue
            out = dst / rel
            if p.suffix.lower() in TEXT_EXT:
                text = raw.decode("utf-8", "replace")
                new, counts = sanitise(text)
                for k, v in counts.items():
                    report["subs"][k] = report["subs"].get(k, 0) + v
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(new, encoding="utf-8")
            else:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(raw)
            report["files"] += 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", action="store_true")
    a = ap.parse_args()
    check = not a.stage

    if not check:
        STAGE.mkdir(parents=True, exist_ok=True)

    plans = [
        # (repo name, [(source dir, allowed top-level entries or None)], readme source)
        ("s98rs",
         [(ROOT / "s98rs", {"pac", "fw", "usb", "tools", "ARCHITECTURE.md"})],
         None),
        ("sonix-rs",
         [(ROOT / "sonix", {"src", "Cargo.toml", "Cargo.lock", "PROTOCOL.md"})],
         ROOT / "readmes" / "sonix-rs-README.md"),
        ("keyboard-research",
         [(ROOT / "research", None)],   # filtered by an explicit name list below
         None),
    ]

    # For keyboard-research, publish ONLY these files.
    research_allow = {
        "COMPANION-BUS.md", "MATRIX-PINS.md", "VENDOR-FLASH-SEQUENCE.md",
        "FLASH-CODE-REVIEW.md", "SN32F290-FIRMWARE-FEASIBILITY.md",
        "USB-DRIVER-NOTES.md", "A9-CHECKM8-PAYLOAD.md",
        "SN32F290.svd", "SN32F290.patched.svd",
        "patch-svd.py", "fix-pac.py", "verify-isp.py", "dis.py",
        "decode-jump.py", "find-magic-ref.py", "fw-scan.py",
    }

    grand: dict[str, int] = {}
    for name, sources, readme in plans:
        rep = {"files": 0, "subs": {}}
        dst = STAGE / name
        if not check and dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
        if not check:
            dst.mkdir(parents=True, exist_ok=True)

        for src, allow in sources:
            if not src.exists():
                continue
            if name == "keyboard-research":
                # flat copy of allowed files only
                for f in src.iterdir():
                    if f.is_file() and f.name in research_allow:
                        text = f.read_text(encoding="utf-8", errors="replace")
                        new, counts = sanitise(text)
                        for k, v in counts.items():
                            rep["subs"][k] = rep["subs"].get(k, 0) + v
                        if not check:
                            (dst / f.name).write_text(new, encoding="utf-8")
                        rep["files"] += 1
                # plus our tools dir
                if (src / "tools").is_dir() and not check:
                    copy_tree(src / "tools", dst / "tools", rep)
            else:
                copy_tree(src, dst, rep, allow)

        if readme and readme.exists() and not check:
            text = readme.read_text(encoding="utf-8")
            new, counts = sanitise(text)
            for k, v in counts.items():
                rep["subs"][k] = rep["subs"].get(k, 0) + v
            (dst / "README.md").write_text(new, encoding="utf-8")

        print(f"\n[{ 'OK ' if rep['files'] else 'ERR'}] {name}")
        print(f"       files     : {rep['files']}")
        for k, v in sorted(rep["subs"].items(), key=lambda x: -x[1]):
            print(f"       sanitised : {v:>4} x {k!r}")
            grand[k] = grand.get(k, 0) + v

    print("\n" + "=" * 66)
    print(" TOTALS")
    for k, v in sorted(grand.items(), key=lambda x: -x[1]):
        print(f"   {v:>5}  {k!r}")
    print(f"\n   stage: {STAGE}")
    if check:
        print("   (check only - re-run with --stage)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
