#!/usr/bin/env python3
"""TLS prober: does the target speak TLS, and what identity does it present?

Usage:
    python tls_probe.py <host> <port> [rtsp_path]

Attempts a TLS handshake (cert verification disabled - this is a lab probe),
prints protocol/cipher/certificate details, then optionally sends an RTSP
OPTIONS over the established TLS channel and prints the reply.
"""
import os
import socket
import ssl
import sys
import tempfile


def decode_cert(der: bytes):
    pem = ssl.DER_cert_to_PEM_cert(der)
    tmp = os.path.join(tempfile.gettempdir(), "peer_cert.pem")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(pem)
    try:
        return ssl._ssl._test_decode_cert(tmp)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        return {"decode_error": repr(exc), "pem_path": tmp}


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    host, port = sys.argv[1], int(sys.argv[2])

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError as exc:
        print(f"[warn] set_ciphers: {exc}")
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:  # noqa: BLE001
        pass

    raw = socket.create_connection((host, port), timeout=8)
    raw.settimeout(10)
    print(f"=== TLS probe {host}:{port} ===")
    try:
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except Exception as exc:  # noqa: BLE001
        print(f"TLS handshake FAILED: {exc!r}")
        raw.close()
        return 1

    print(f"TLS OK  version={tls.version()}  cipher={tls.cipher()}")
    der = tls.getpeercert(binary_form=True)
    if der:
        info = decode_cert(der)
        for key in ("subject", "issuer", "subjectAltName", "notBefore", "notAfter", "version"):
            if key in info:
                print(f"  cert.{key} = {info[key]}")
        print(f"  cert.der_len = {len(der)}")
    else:
        print("  no peer certificate presented")

    payload = (
        f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: probe\r\n\r\n"
    ).encode()
    try:
        tls.sendall(payload)
        print(f"--- sent {len(payload)} bytes RTSP OPTIONS over TLS ---")
        chunks = []
        while True:
            try:
                b = tls.recv(4096)
            except (socket.timeout, ssl.SSLError) as exc:
                print(f"  recv stopped: {exc!r}")
                break
            if not b:
                break
            chunks.append(b)
            if sum(len(c) for c in chunks) > 32768:
                break
        data = b"".join(chunks)
        print(f"--- received {len(data)} bytes ---")
        print(data.decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        print(f"RTSP over TLS failed: {exc!r}")
    finally:
        tls.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
