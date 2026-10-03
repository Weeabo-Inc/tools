#!/usr/bin/env python3
"""Minimal asyncio TCP port scanner.

Usage:
    python tcpscan.py <host> [start] [end] [concurrency] [timeout]

Examples:
    python tcpscan.py 192.168.1.110
    python tcpscan.py 192.168.1.110 1 65535 1000 1.2
"""
import asyncio
import sys
import time


async def probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore, out: list):
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout
            )
        except (OSError, asyncio.TimeoutError):
            return
        out.append(port)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    host = sys.argv[1]
    start = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    end = int(sys.argv[3]) if len(sys.argv) > 3 else 65535
    conc = int(sys.argv[4]) if len(sys.argv) > 4 else 1000
    timeout = float(sys.argv[5]) if len(sys.argv) > 5 else 1.2

    sem = asyncio.Semaphore(conc)
    open_ports: list = []
    t0 = time.time()

    tasks = [
        asyncio.create_task(probe(host, p, timeout, sem, open_ports))
        for p in range(start, end + 1)
    ]
    await asyncio.gather(*tasks)

    open_ports.sort()
    print(f"HOST {host}  range {start}-{end}  concurrency {conc}  timeout {timeout}s")
    print(f"ELAPSED {time.time() - t0:.1f}s")
    print(f"OPEN ({len(open_ports)}): {', '.join(str(p) for p in open_ports) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
