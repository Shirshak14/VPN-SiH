"""PCAP/PCAPNG ingestion: link layer -> IP (with IPv4 reassembly) -> UDP/ESP/AH -> IKE.

Scapy's raw readers are used only to iterate frames (fast, no per-packet dissection); protocol
decoding is done here so throughput is predictable and behaviour is explicit.
"""
from __future__ import annotations

import ipaddress
import struct
import time
from pathlib import Path

from scapy.utils import RawPcapNgReader, RawPcapReader

from . import constants as C
from .ike import parse_ike
from .models import CaptureStats, EspPacket, IkeMessage, IkeParseError, ParsedCapture

LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_RAW2, LINK_SLL2 = 1, 101, 113, 12, 276
_IP_PROTO_ESP, _IP_PROTO_AH, _IP_PROTO_UDP = 50, 51, 17
_V6_EXT = {0, 43, 60}  # hop-by-hop, routing, destination options (simple chain skipping)
_MAX_FRAGMENT_BUFFERS = 4096


class _Defrag:
    """Minimal IPv4 reassembly keyed by (src, dst, id, proto). Enough for large IKE messages."""

    def __init__(self) -> None:
        self._bufs: dict[tuple, dict] = {}

    def add(self, key: tuple, offset: int, more: bool, payload: bytes) -> bytes | None:
        if len(self._bufs) >= _MAX_FRAGMENT_BUFFERS:
            self._bufs.clear()
        b = self._bufs.setdefault(key, {"frags": {}, "total": None})
        b["frags"][offset] = payload
        if not more:
            b["total"] = offset + len(payload)
        if b["total"] is None:
            return None
        out, pos = bytearray(), 0
        for off in sorted(b["frags"]):
            if off != pos:
                return None
            out += b["frags"][off]
            pos = off + len(b["frags"][off])
        if pos != b["total"]:
            return None
        del self._bufs[key]
        return bytes(out)


def _open(path: str):
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":
        return RawPcapNgReader(path)
    return RawPcapReader(path)


def _link_payload(frame: bytes, linktype: int) -> tuple[int, bytes] | None:
    """Return (ip_version, l3_bytes) or None if the frame has no IP payload."""
    if linktype == LINK_ETHERNET:
        if len(frame) < 14:
            return None
        et, off = struct.unpack_from("!H", frame, 12)[0], 14
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:  # VLAN tags
            et = struct.unpack_from("!H", frame, off + 2)[0]
            off += 4
    elif linktype == LINK_SLL:
        if len(frame) < 16:
            return None
        et, off = struct.unpack_from("!H", frame, 14)[0], 16
    elif linktype == LINK_SLL2:
        if len(frame) < 20:
            return None
        et, off = struct.unpack_from("!H", frame, 0)[0], 20
    elif linktype in (LINK_RAW, LINK_RAW2):
        v = frame[0] >> 4 if frame else 0
        return (v, frame) if v in (4, 6) else None
    else:
        return None
    if et == 0x0800:
        return 4, frame[off:]
    if et == 0x86DD:
        return 6, frame[off:]
    return None


def parse_pcap(path: str | Path, *, keys=None) -> ParsedCapture:
    """Parse a PCAP/PCAPNG and return all IKE messages and ESP/AH packets found.

    `keys` (optional) is an iterable of `IkeSaKeys` used to open IKEv2 encrypted payloads.
    """
    path = str(path)
    stats = CaptureStats()
    ike: list[IkeMessage] = []
    esp: list[EspPacket] = []
    defrag = _Defrag()
    t0 = time.perf_counter()

    reader = _open(path)
    linktype = getattr(reader, "linktype", LINK_ETHERNET)
    try:
        for idx, (frame, meta) in enumerate(reader, start=1):
            stats.packets += 1
            ts = _timestamp(meta, reader)
            if stats.first_ts == 0.0:
                stats.first_ts = ts
            stats.last_ts = ts
            lt = _meta_linktype(meta, linktype)
            l3 = _link_payload(frame, lt)
            if l3 is None:
                stats.non_ip += 1
                continue
            try:
                _handle_ip(l3[0], l3[1], idx, ts, ike, esp, stats, defrag)
            except IkeParseError as e:
                stats.ike_malformed += 1
                stats.errors.append(f"frame {idx}: {e}")
    finally:
        reader.close()

    stats.parse_seconds = time.perf_counter() - t0
    stats.ike_messages = len(ike)
    stats.esp_packets = sum(1 for e in esp if e.proto == _IP_PROTO_ESP)
    stats.ah_packets = sum(1 for e in esp if e.proto == _IP_PROTO_AH)
    cap = ParsedCapture(path=path, ike=ike, esp=esp, stats=stats)
    if keys:
        from .decrypt import apply_keys  # local import: optional dependency on `cryptography`
        apply_keys(cap, keys)
    return cap


def _meta_linktype(meta, default: int) -> int:
    # RawPcapNgReader metadata carries the per-interface linktype in its first field.
    if hasattr(meta, "linktype") and meta.linktype is not None:
        return int(meta.linktype)
    return default


def _timestamp(meta, reader) -> float:
    if hasattr(meta, "tshigh"):  # pcapng
        raw = (int(meta.tshigh) << 32) | int(meta.tslow)
        resol = getattr(meta, "tsresol", 1_000_000) or 1_000_000
        return raw / resol
    sec, usec = meta.sec, meta.usec
    nano = getattr(reader, "nano", False)
    return sec + usec / (1e9 if nano else 1e6)


def _handle_ip(version: int, l3: bytes, frame_no: int, ts: float, ike, esp, stats, defrag: _Defrag) -> None:
    if version == 4:
        if len(l3) < 20:
            return
        ihl = (l3[0] & 0x0F) * 4
        total = struct.unpack_from("!H", l3, 2)[0]
        ident, ff = struct.unpack_from("!HH", l3, 4)
        proto = l3[9]
        src = str(ipaddress.IPv4Address(l3[12:16]))
        dst = str(ipaddress.IPv4Address(l3[16:20]))
        payload = l3[ihl:total] if total >= ihl else l3[ihl:]
        more, foff = bool(ff & 0x2000), (ff & 0x1FFF) * 8
        if more or foff:
            whole = defrag.add((src, dst, ident, proto), foff, more, payload)
            if whole is None:
                return
            stats.ip_fragments_reassembled += 1
            payload = whole
    else:
        if len(l3) < 40:
            return
        proto = l3[6]
        src = str(ipaddress.IPv6Address(l3[8:24]))
        dst = str(ipaddress.IPv6Address(l3[24:40]))
        payload, off = l3[40:], 0
        while proto in _V6_EXT and len(payload) >= off + 8:
            nxt, hlen = payload[off], (payload[off + 1] + 1) * 8
            proto, off = nxt, off + hlen
        payload = payload[off:]

    if proto == _IP_PROTO_ESP and len(payload) >= 8:
        spi, seq = struct.unpack_from("!II", payload)
        esp.append(EspPacket(frame_no, ts, src, dst, _IP_PROTO_ESP, spi, seq, len(payload)))
    elif proto == _IP_PROTO_AH and len(payload) >= 12:
        spi, seq = struct.unpack_from("!II", payload, 4)
        esp.append(EspPacket(frame_no, ts, src, dst, _IP_PROTO_AH, spi, seq, len(payload)))
    elif proto == _IP_PROTO_UDP and len(payload) >= 8:
        sport, dport, ulen = struct.unpack_from("!HHH", payload)
        data = payload[8:ulen] if 8 <= ulen <= len(payload) else payload[8:]
        _handle_udp(src, dst, sport, dport, data, frame_no, ts, ike, esp, stats)


def _handle_udp(src, dst, sport, dport, data: bytes, frame_no, ts, ike, esp, stats) -> None:
    if C.IKE_PORT in (sport, dport):
        ike.append(parse_ike(data, frame=frame_no, ts=ts, src=src, dst=dst, sport=sport, dport=dport))
    elif C.NATT_PORT in (sport, dport):
        if data == b"\xff":  # NAT-T keepalive (RFC 3948 2.2)
            stats.natt_keepalives += 1
        elif data[:4] == b"\x00\x00\x00\x00":  # non-ESP marker -> IKE
            ike.append(parse_ike(data[4:], frame=frame_no, ts=ts, src=src, dst=dst, sport=sport,
                                 dport=dport, natt_marker=True))
        elif len(data) >= 8:  # ESP-in-UDP
            spi, seq = struct.unpack_from("!II", data)
            esp.append(EspPacket(frame_no, ts, src, dst, _IP_PROTO_ESP, spi, seq, len(data), udp_encap=True))
    else:
        stats.other_udp += 1
