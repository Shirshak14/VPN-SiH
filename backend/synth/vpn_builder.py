"""Byte-exact OpenVPN and WireGuard packets for tests that need a situation the real lab cannot produce on demand
(a 1024-bit DH prime on the wire, a NULL cipher suite, a TLS alert, a replayed WireGuard counter ...).

The layouts follow the same references as the parsers (OpenVPN `ssl_pkt.h`, the WireGuard whitepaper, RFC 5246/8446) but
are written independently of them, so a test that builds a packet here and parses it there checks both.
"""
from __future__ import annotations

import os
import struct

from . import builder as B

# ----------------------------------------------------------------------------- TLS
def tls_record(rtype: int, body: bytes, ver: int = 0x0303) -> bytes:
    return bytes([rtype]) + ver.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


def hs(mtype: int, body: bytes) -> bytes:
    return bytes([mtype]) + len(body).to_bytes(3, "big") + body


def _ext(t: int, data: bytes) -> bytes:
    return t.to_bytes(2, "big") + len(data).to_bytes(2, "big") + data


def client_hello(versions: tuple[int, ...] = (0x0304, 0x0303), suites: tuple[int, ...] = (0x1302, 0xC02F), groups: tuple[int, ...] = (29,),
                 legacy: int = 0x0303) -> bytes:
    sv = bytes([2 * len(versions)]) + b"".join(v.to_bytes(2, "big") for v in versions)
    sg = (2 * len(groups)).to_bytes(2, "big") + b"".join(g.to_bytes(2, "big") for g in groups)
    exts = _ext(0x002B, sv) + _ext(0x000A, sg)
    cs = b"".join(s.to_bytes(2, "big") for s in suites)
    body = legacy.to_bytes(2, "big") + os.urandom(32) + b"\x00" + len(cs).to_bytes(2, "big") + cs + b"\x01\x00" + len(exts).to_bytes(2, "big") + exts
    return tls_record(22, hs(1, body), 0x0301)


def server_hello(suite: int, version: int = 0x0303, group: int | None = None) -> bytes:
    exts = b""
    legacy = version
    if version == 0x0304:
        legacy = 0x0303
        exts = _ext(0x002B, version.to_bytes(2, "big")) + _ext(0x0033, (group or 29).to_bytes(2, "big") + b"\x00\x20" + os.urandom(32))
    body = legacy.to_bytes(2, "big") + os.urandom(32) + b"\x00" + suite.to_bytes(2, "big") + b"\x00" + len(exts).to_bytes(2, "big") + exts
    return tls_record(22, hs(2, body))


def server_kx_dhe(bits: int) -> bytes:
    p = b"\xff" * (bits // 8)
    body = len(p).to_bytes(2, "big") + p + b"\x00\x01\x02" + b"\x00\x04" + os.urandom(4) + b"\x00" * 8
    return tls_record(22, hs(12, body))


def server_kx_ecdhe(curve: int = 29) -> bytes:
    return tls_record(22, hs(12, b"\x03" + curve.to_bytes(2, "big") + b"\x20" + os.urandom(32) + b"\x00" * 8))


def certificate_msg(ders: list[bytes]) -> bytes:
    chain = b"".join(len(d).to_bytes(3, "big") + d for d in ders)
    return tls_record(22, hs(11, len(chain).to_bytes(3, "big") + chain))


def alert(desc: int, level: int = 2) -> bytes:
    return tls_record(21, bytes([level, desc]))


# ----------------------------------------------------------------------------- OpenVPN
HMAC_LEN = {"sha1": 20, "sha256": 32, "sha512": 64}


def _wrap(wrap: str, hlen: int) -> bytes:
    return os.urandom(hlen) + struct.pack("!II", 1, 1_760_000_000) if wrap == "tls-auth" else b""


def ovpn_client_reset(sid: bytes, wrap: str = "none", hmac: str = "sha1") -> bytes:
    if wrap == "none":
        return bytes([7 << 3]) + sid + b"\x00" + b"\x00\x00\x00\x00"
    if wrap == "tls-auth":
        return bytes([7 << 3]) + sid + _wrap("tls-auth", HMAC_LEN[hmac]) + b"\x00" + b"\x00\x00\x00\x00"
    if wrap == "tls-crypt":
        return bytes([7 << 3]) + sid + struct.pack("!II", 1, 1_760_000_000) + os.urandom(32) + os.urandom(5)
    if wrap == "tls-crypt-v2":
        return bytes([10 << 3]) + sid + struct.pack("!II", 1, 1_760_000_000) + os.urandom(32) + os.urandom(5) + os.urandom(300)
    raise ValueError(wrap)


def ovpn_server_reset(sid: bytes, client_sid: bytes, wrap: str = "none", hmac: str = "sha1") -> bytes:
    if wrap == "none":
        return bytes([8 << 3]) + sid + b"\x01" + b"\x00\x00\x00\x00" + client_sid + b"\x00\x00\x00\x00"
    if wrap == "tls-auth":
        return bytes([8 << 3]) + sid + _wrap("tls-auth", HMAC_LEN[hmac]) + b"\x01" + b"\x00\x00\x00\x00" + client_sid + b"\x00\x00\x00\x00"
    return bytes([8 << 3]) + sid + struct.pack("!II", 1, 1_760_000_000) + os.urandom(32) + os.urandom(17)


def ovpn_control(sid: bytes, pid: int, payload: bytes, remote_sid: bytes | None = None, ack: int | None = 0, kid: int = 0,
                 wrap: str = "none", hmac: str = "sha1") -> bytes:
    out = bytes([4 << 3 | kid]) + sid + _wrap(wrap, HMAC_LEN[hmac])
    if ack is None:
        out += b"\x00"
    else:
        out += b"\x01" + struct.pack("!I", ack) + (remote_sid or b"\x00" * 8)
    return out + struct.pack("!I", pid) + payload


def ovpn_data(kid: int = 0, n: int = 60) -> bytes:
    return bytes([9 << 3 | kid]) + b"\x00\x00\x00" + os.urandom(n)


def ovpn_session(t0: float, client: tuple[str, int], server: tuple[str, int], client_tls: list[bytes], server_tls: list[bytes],
                 wrap: str = "none", hmac: str = "sha1", data: tuple[int, int] = (3, 3), data_span_s: float = 0.0, answered: bool = True,
                 kid: int = 0) -> list[tuple[float, str, int, str, int, bytes]]:
    """A client/server exchange as (ts, src, sport, dst, dport, payload). `client_tls`/`server_tls` are TLS records, one per control packet."""
    csid, ssid = os.urandom(8), os.urandom(8)
    (cip, cport), (sip, sport) = client, server
    pk = [(t0, cip, cport, sip, sport, ovpn_client_reset(csid, wrap, hmac))]
    if not answered:
        return pk
    pk.append((t0 + 0.01, sip, sport, cip, cport, ovpn_server_reset(ssid, csid, wrap, hmac)))
    t = t0 + 0.02
    for i, rec in enumerate(client_tls, 1):
        pk.append((t, cip, cport, sip, sport, ovpn_control(csid, i, rec, ssid, 0, kid, wrap, hmac)))
        t += 0.01
    for i, rec in enumerate(server_tls, 1):
        pk.append((t, sip, sport, cip, cport, ovpn_control(ssid, i, rec, csid, 0, kid, wrap, hmac)))
        t += 0.01
    for i in range(data[0]):
        pk.append((t + data_span_s * i / max(1, data[0] - 1), cip, cport, sip, sport, ovpn_data(kid)))
    for i in range(data[1]):
        pk.append((t + 0.005 + data_span_s * i / max(1, data[1] - 1), sip, sport, cip, cport, ovpn_data(kid)))
    return pk


# ----------------------------------------------------------------------------- WireGuard
def wg_init(sender: int, mac2: bool = False) -> bytes:
    return b"\x01\x00\x00\x00" + struct.pack("<I", sender) + os.urandom(32 + 48 + 28 + 16) + (os.urandom(16) if mac2 else b"\x00" * 16)


def wg_resp(sender: int, receiver: int) -> bytes:
    return b"\x02\x00\x00\x00" + struct.pack("<II", sender, receiver) + os.urandom(32 + 16 + 16 + 16)


def wg_cookie(receiver: int) -> bytes:
    return b"\x03\x00\x00\x00" + struct.pack("<I", receiver) + os.urandom(24 + 32)


def wg_data(receiver: int, counter: int, size: int = 32) -> bytes:
    """`size` is the whole datagram: 16-byte header + padded payload + 16-byte tag (32 = keepalive)."""
    return b"\x04\x00\x00\x00" + struct.pack("<IQ", receiver, counter) + os.urandom(size - 16)


# ----------------------------------------------------------------------------- pcap
def udp_pcap(path: str, packets: list[tuple[float, str, int, str, int, bytes]]) -> str:
    frames = []
    for i, (ts, src, sport, dst, dport, data) in enumerate(packets):
        fr = B.ethernet(B.ipv4_udp_frame(src, dst, sport, dport, data, 100 + i), b"\x02" * 6, b"\x04" * 6)
        frames.append((ts, fr))
    B.write_pcap(str(path), frames)
    return str(path)
