#!/usr/bin/env python3
"""Targeted mDNS query tool.

Usage:
    python mdns_query.py <name> [qtype ...] [--iface IP] [--timeout SEC]

qtype may be a number or one of: A AAAA PTR TXT SRV ANY HINFO
Defaults to ANY TXT SRV PTR.

Examples:
    python mdns_query.py _arlo-video._tcp.local
    python mdns_query.py VMB4540.local ANY TXT
"""
import socket
import struct
import sys
import time

MDNS = ("224.0.0.251", 5353)
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "HINFO": 13, "TXT": 16,
         "AAAA": 28, "SRV": 33, "ANY": 255}
NAMES = {v: k for k, v in TYPES.items()}


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            b = label.encode()
            out += bytes([len(b)]) + b
    return out + b"\x00"


def read_name(data: bytes, off: int):
    labels, jumped, end, hops = [], False, off, 0
    while off < len(data) and hops < 60:
        hops += 1
        ln = data[off]
        if ln == 0:
            off += 1
            if not jumped:
                end = off
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", data[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
                jumped = True
            off = ptr
            continue
        labels.append(data[off + 1:off + 1 + ln].decode("utf-8", "replace"))
        off += 1 + ln
        if not jumped:
            end = off
    return ".".join(labels), end


def parse(data: bytes, sender: str):
    out = []
    if len(data) < 12:
        return out
    _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = read_name(data, off)
        off += 4
    for _ in range(an + ns + ar):
        if off >= len(data):
            break
        name, off = read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        val = None
        try:
            if rtype == 1 and rdlen == 4:
                val = socket.inet_ntoa(rd)
            elif rtype == 28 and rdlen == 16:
                val = socket.inet_ntop(socket.AF_INET6, rd)
            elif rtype in (12, 2, 5):
                val, _ = read_name(data, off)
            elif rtype == 16:
                parts, p = [], 0
                while p < len(rd):
                    ln = rd[p]
                    parts.append(rd[p + 1:p + 1 + ln].decode("utf-8", "replace"))
                    p += 1 + ln
                val = " | ".join(parts)
            elif rtype == 33 and rdlen >= 6:
                pri, weight, port = struct.unpack(">HHH", rd[:6])
                target, _ = read_name(data, off + 6)
                val = f"{target}:{port} prio={pri} weight={weight}"
            elif rtype == 13:
                cpu_len = rd[0]
                cpu = rd[1:1 + cpu_len].decode("utf-8", "replace")
                os_len = rd[1 + cpu_len]
                ops = rd[2 + cpu_len:2 + cpu_len + os_len].decode("utf-8", "replace")
                val = f"cpu={cpu!r} os={ops!r}"
            else:
                val = rd.hex()
        except Exception as exc:  # noqa: BLE001
            val = f"<parse error {exc!r}>"
        out.append((sender, NAMES.get(rtype, str(rtype)), name, ttl, val))
        off += rdlen
    return out


def main() -> int:
    argv = sys.argv[1:]
    iface, timeout = None, 5.0
    if "--iface" in argv:
        i = argv.index("--iface")
        iface = argv[i + 1]
        del argv[i:i + 2]
    if "--timeout" in argv:
        i = argv.index("--timeout")
        timeout = float(argv[i + 1])
        del argv[i:i + 2]
    if not argv:
        print(__doc__)
        return 2
    name = argv[0]
    qtypes = argv[1:] or ["ANY", "TXT", "SRV", "PTR"]
    qnums = [TYPES.get(q.upper(), int(q) if q.isdigit() else 255) for q in qtypes]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    if iface:
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface))
        except OSError as exc:
            print(f"[warn] iface bind: {exc}")
    s.bind(("", 0))
    s.settimeout(1.0)

    print(f"=== mDNS: {name} {qtypes} ===")
    for q in qnums:
        pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + encode_name(name) + struct.pack(">HH", q, 1)
        s.sendto(pkt, MDNS)

    seen, deadline = set(), time.time() + timeout
    while time.time() < deadline:
        try:
            data, sender = s.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        for src, rtype, rname, ttl, val in parse(data, sender[0]):
            key = (rtype, rname, val)
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{src}] {rtype:5} ttl={ttl:<6} {rname:45} = {val}")
    if not seen:
        print("  (no answers)")
    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
