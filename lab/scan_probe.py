"""Send IKEv2 IKE_SA_INIT probes with fresh initiator SPIs (stdlib only; runs inside the lab container).

    python3 scan_probe.py <responder-ip> <count> <interval-seconds>

Every probe is a well-formed IKE_SA_INIT (AES-CBC-256, HMAC-SHA2-256, MODP-2048) with random SPI, KE and nonce.
Against a host with no IKE daemon it is never answered, which is the half-open pattern the analyzer looks for.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import time


def _transform(more: bool, ttype: int, tid: int, keylen: int | None = None) -> bytes:
    attr = struct.pack("!HH", 0x800E, keylen) if keylen else b""
    return struct.pack("!BBHBBH", 3 if more else 0, 0, 8 + len(attr), ttype, 0, tid) + attr


def ike_sa_init(ispi: bytes, ke: bytes, nonce: bytes) -> bytes:
    transforms = _transform(True, 1, 12, 256) + _transform(True, 2, 5) + _transform(True, 3, 12) + _transform(False, 4, 14)
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4) + transforms
    sa = struct.pack("!BBH", 34, 0, 4 + len(proposal)) + proposal
    kex = struct.pack("!BBHHH", 40, 0, 8 + len(ke), 14, 0) + ke
    non = struct.pack("!BBH", 0, 0, 4 + len(nonce)) + nonce
    body = sa + kex + non
    return ispi + b"\x00" * 8 + struct.pack("!BBBBII", 33, 0x20, 34, 0x08, 0, 28 + len(body)) + body


def main() -> None:
    target, count, interval = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 500))  # IKE expects 500 -> 500; charon is not running on this container in the scan scenario
    for _ in range(count):
        s.sendto(ike_sa_init(os.urandom(8), os.urandom(256), os.urandom(32)), (target, 500))
        time.sleep(interval)


if __name__ == "__main__":
    main()
