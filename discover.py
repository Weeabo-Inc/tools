#!/usr/bin/env python3
"""LAN discovery probe: mDNS (5353) + SSDP (1900) + common UDP responders.

Usage:
    python discover.py [interface_ip] [timeout_seconds]

Sends:
  * mDNS ANY query for the given names plus a PTR query for
    _services._dns-sd._udp.local so we learn what services the device advertises.
  * SSDP M-SEARCH (ssdp:all and upnp:rootdevice) to 239.255.255.250:1900.

Prints decoded DNS answers (A / AAAA / PTR / TXT / SRV) and raw SSDP replies.
"""
import socket
import struct
import sys
import time

MDNS_ADDR = ("224.0.0.251", 5353)
SSDP_ADDR = ("239.255.255.250", 1900)


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            b = label.encode()
            out += bytes([len(b)]) + b
    return out + b"\x00"


def build_query(name: str, qtype: int) -> bytes:
    # ID 0, flags 0, 1 question, 0 answers
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", qtype, 1)  # class IN


def read_name(data: bytes, off: int) -> tuple:
    labels = []
    jumped = False
    end = off
    hops = 0
    while off < len(data) and hops < 50:
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


TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def parse_response(data: bytes, sender) -> list:
    findings = []
    if len(data) < 12:
        return findings
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
        rdata = data[off:off + rdlen]
        val = None
        try:
            if rtype == 1 and rdlen == 4:
                val = socket.inet_ntoa(rdata)
            elif rtype == 28 and rdlen == 16:
                val = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == 12:
                val, _ = read_name(data, off)
            elif rtype == 16:
                parts, p = [], 0
                while p < len(rdata):
                    ln = rdata[p]
                    parts.append(rdata[p + 1:p + 1 + ln].decode("utf-8", "replace"))
                    p += 1 + ln
                val = " | ".join(parts)
            elif rtype == 33 and rdlen >= 6:
                pri, weight, port = struct.unpack(">HHH", rdata[:6])
                target, _ = read_name(data, off + 6)
                val = f"{target}:{port} (prio {pri} weight {weight})"
        except Exception as exc:  # noqa: BLE001
            val = f"<parse error {exc!r}>"
        findings.append((sender, TYPES.get(rtype, rtype), name, val))
        off += rdlen
    return findings


def main() -> int:
    iface = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 6.0

    seen = set()

    # ---------- mDNS ----------
    mdns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    mdns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if iface != "0.0.0.0":
            mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface))
    except OSError as exc:
        print(f"[mdns] multicast setup warning: {exc}")
    mdns.bind(("", 0))
    mdns.settimeout(1.0)

    queries = [
        ("VMB4540.local", 255),
        ("VMB4540.local", 16),
        ("_services._dns-sd._udp.local", 12),
        ("_http._tcp.local", 12),
        ("_rtsp._tcp.local", 12),
        ("_arlo._tcp.local", 12),
        ("local", 12),
    ]
    print("=== mDNS queries ===")
    for name, qtype in queries:
        try:
            mdns.sendto(build_query(name, qtype), MDNS_ADDR)
            print(f"  -> {name} type={TYPES.get(qtype, qtype)}")
        except OSError as exc:
            print(f"  -> {name} send failed: {exc}")

    print("\n=== mDNS answers ===")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, sender = mdns.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        for rec in parse_response(data, sender[0]):
            key = (rec[1], rec[2], rec[3])
            if key in seen:
                continue
            seen.add(key)
            print(f"  [{rec[0]}] {rec[1]:5} {rec[2]:45} = {rec[3]}")
    mdns.close()

    # ---------- SSDP ----------
    print("\n=== SSDP M-SEARCH ===")
    ssdp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    ssdp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssdp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    if iface != "0.0.0.0":
        try:
            ssdp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface))
        except OSError:
            pass
    ssdp.bind(("", 0))
    ssdp.settimeout(1.0)
    for st in ("ssdp:all", "upnp:rootdevice", "urn:schemas-upnp-org:device:Basic:1"):
        msg = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 3\r\n"
            f"ST: {st}\r\n\r\n"
        ).encode()
        try:
            ssdp.sendto(msg, SSDP_ADDR)
        except OSError as exc:
            print(f"  -> {st} send failed: {exc}")
    ssdp_deadline = time.time() + timeout
    while time.time() < ssdp_deadline:
        try:
            data, sender = ssdp.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        print(f"  --- reply from {sender[0]}:{sender[1]} ---")
        print("  " + data.decode("utf-8", "replace").replace("\r\n", "\n  ").strip())
    ssdp.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
