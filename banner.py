#!/usr/bin/env python3
"""Tiny banner grabber / single-shot protocol prober.

Usage:
    python banner.py <host> <port> [mode] [timeout]

Modes:
    none             just read whatever the service sends first (default)
    rtsp-options     send RTSP OPTIONS
    rtsp-describe    send RTSP DESCRIBE for a few common paths
    http-get         send a minimal HTTP/1.0 GET /
    hex              print the raw bytes as hex + ascii

Prints both a repr() and a hexdump of everything received.
"""
import socket
import sys


def hexdump(data: bytes, width: int = 16) -> str:
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(lines)


def build(mode: str, host: str, port: int) -> list:
    if mode == "rtsp-options":
        return [(
            f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: probe\r\n\r\n"
        ).encode()]
    if mode == "rtsp-describe":
        payloads = []
        for path in ("", "live", "stream", "cam", "arlo", "video", "11", "12"):
            payloads.append((
                f"DESCRIBE rtsp://{host}:{port}/{path} RTSP/1.0\r\n"
                f"CSeq: 2\r\n"
                f"Accept: application/sdp\r\n"
                f"User-Agent: probe\r\n\r\n"
            ).encode())
        return payloads
    if mode == "http-get":
        return [(
            f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: probe\r\n\r\n"
        ).encode()]
    return [None]


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    host, port = sys.argv[1], int(sys.argv[2])
    mode = sys.argv[3] if len(sys.argv) > 3 else "none"
    timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 4.0

    for payload in build(mode, host, port):
        print(f"=== {host}:{port} mode={mode} ===")
        if payload:
            print(f"--- sent {len(payload)} bytes ---")
        try:
            with socket.create_connection((host, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if payload:
                    s.sendall(payload)
                chunks = []
                while True:
                    try:
                        b = s.recv(4096)
                    except socket.timeout:
                        break
                    if not b:
                        break
                    chunks.append(b)
                    if sum(len(c) for c in chunks) > 65536:
                        break
        except Exception as exc:
            print(f"ERROR: {exc!r}")
            continue
        data = b"".join(chunks)
        print(f"--- received {len(data)} bytes ---")
        print(f"repr: {data[:2000]!r}")
        print(hexdump(data[:2000]))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
