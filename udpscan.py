#!/usr/bin/env python3
"""UDP port scanner that infers state from ICMP port-unreachable feedback.

Usage:
    python udpscan.py <host> [timeout] [port ...]

On Windows a connected UDP socket surfaces an inbound ICMP port-unreachable as
ConnectionResetError on the next recv(), which is how "closed" is detected here:

    open            a UDP payload came back
    closed          ICMP port unreachable (WSAECONNRESET)
    open|filtered   no reply at all within the timeout (silently dropped)

Defaults to a curated list of ports seen on embedded Linux/IoT devices.
"""
import socket
import sys

DEFAULT_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520,
    547, 623, 1900, 3478, 4500, 5353, 5683, 6667, 8888, 47808,
]


def probe(host: str, port: int, timeout: float):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        try:
            s.send(b"\x00" * 8)
        except OSError as exc:
            return "send_error", str(exc)
        try:
            data = s.recv(2048)
            return "open", data
        except ConnectionResetError:
            return "closed", None
        except socket.timeout:
            return "open|filtered", None
        except OSError as exc:
            return "error", str(exc)
    finally:
        s.close()


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    host = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
    ports = [int(p) for p in sys.argv[3:]] or DEFAULT_PORTS

    print(f"=== UDP scan {host} (timeout {timeout}s, {len(ports)} ports) ===")
    counts = {}
    for port in ports:
        state, detail = probe(host, port, timeout)
        counts[state] = counts.get(state, 0) + 1
        if state == "open":
            print(f"  udp/{port:<6} OPEN      reply={detail[:80]!r}")
        elif state in ("send_error", "error"):
            print(f"  udp/{port:<6} {state.upper():<9} {detail}")
        else:
            print(f"  udp/{port:<6} {state.upper()}")
    print("\n=== summary ===")
    for k, v in sorted(counts.items()):
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
