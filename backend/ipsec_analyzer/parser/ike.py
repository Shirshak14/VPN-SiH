"""IKEv1 (RFC 2408/2409/2407) and IKEv2 (RFC 7296) message decoder.

Deliberately hand-written on `struct` rather than delegating to Scapy's ISAKMP layer:
every field offset below is traceable to an RFC section, malformed input raises
`IkeParseError` instead of silently mis-parsing, and no TShark dependency is needed.
"""
from __future__ import annotations

import hashlib
import struct

from . import constants as C
from .models import (
    IkeMessage, IkeParseError, Notify, PayloadSet, Proposal, Transform, V1Proposal, V1Transform,
)

HEADER_LEN = 28
_HDR = struct.Struct("!8s8sBBBBII")
_GEN = struct.Struct("!BBH")


def parse_ike(data: bytes, *, frame: int, ts: float, src: str, dst: str, sport: int, dport: int,
              natt_marker: bool = False) -> IkeMessage:
    """Decode one IKE datagram (UDP payload with any NAT-T marker already removed)."""
    if len(data) < HEADER_LEN:
        raise IkeParseError(f"datagram too short for IKE header ({len(data)} bytes)")
    ispi, rspi, next_payload, ver, exch, flags, msg_id, length = _HDR.unpack_from(data)
    major = ver >> 4
    if major not in (1, 2):
        raise IkeParseError(f"unsupported IKE major version {major}")
    if length < HEADER_LEN:
        raise IkeParseError(f"IKE length field {length} smaller than header")
    if length > len(data):
        raise IkeParseError(f"IKE length {length} exceeds datagram size {len(data)} (truncated/fragmented)")
    if major == 1 and exch not in C.V1_EXCHANGE and not (128 <= exch <= 255):
        raise IkeParseError(f"unknown IKEv1 exchange type {exch}")
    if major == 2 and exch not in C.V2_EXCHANGE:
        raise IkeParseError(f"unknown IKEv2 exchange type {exch}")

    body = data[HEADER_LEN:length]
    msg = IkeMessage(
        frame=frame, ts=ts, src=src, dst=dst, sport=sport, dport=dport, udp_len=len(data),
        natt_marker=natt_marker, ispi=ispi, rspi=rspi, version=major, exch=exch, flags=flags,
        msg_id=msg_id, length=length, next_payload=next_payload,
        digest=hashlib.sha1(data[:length]).digest(), raw=data[:length],
    )
    if major == 2:
        _parse_v2(msg, next_payload, body)
    else:
        _parse_v1(msg, next_payload, body)
    return msg


# --------------------------------------------------------------------------------------
# Generic payload walker
# --------------------------------------------------------------------------------------
def _walk(first: int, buf: bytes):
    """Yield (payload_type, critical, body) for a chain of generic payload headers."""
    off, cur = 0, first
    while cur != C.PAYLOAD_NONE:
        if off + 4 > len(buf):
            raise IkeParseError("payload header runs past end of message")
        nxt, crit, plen = _GEN.unpack_from(buf, off)
        if plen < 4 or off + plen > len(buf):
            raise IkeParseError(f"bad payload length {plen} for type {cur}")
        yield cur, bool(crit & 0x80), buf[off + 4: off + plen], nxt
        off += plen
        cur = nxt


# --------------------------------------------------------------------------------------
# IKEv2
# --------------------------------------------------------------------------------------
def parse_v2_payloads(first: int, buf: bytes) -> PayloadSet:
    """Decode a chain of IKEv2 payloads (used for decrypted inner payloads)."""
    return _decode_v2((t, b) for t, _c, b, _n in _walk(first, buf))


def _decode_v2(items) -> PayloadSet:
    ps = PayloadSet()
    for ptype, body in items:
        ps.types.append(ptype)
        if ptype == C.V2_SA:
            ps.proposals.extend(_v2_proposals(body))
        elif ptype == C.V2_KE:
            if len(body) < 4:
                raise IkeParseError("KE payload too short")
            ps.ke_group = struct.unpack_from("!H", body)[0]
            ps.ke_len = len(body) - 4
        elif ptype == C.V2_NONCE:
            ps.nonce_len = len(body)
        elif ptype == C.V2_NOTIFY:
            ps.notifies.append(_v2_notify(body))
        elif ptype in (C.V2_IDI, C.V2_IDR):
            if body:
                ps.id_types.append((ptype, body[0]))
        elif ptype == C.V2_AUTH_P:
            if body:
                ps.auth_method = body[0]
                ps.auth_data = bytes(body[4:])
        elif ptype in (C.V2_TSI, C.V2_TSR):
            ps.ts_count += 1
        elif ptype in (37, 38):
            ps.cert_count += 1
        elif ptype == 42 and body:  # Delete
            ps.delete_protocols.append(body[0])
    return ps


def _parse_v2(msg: IkeMessage, first: int, body: bytes) -> None:
    # Walk manually so we can stop at the encrypted payload (SK / SKF).
    off, cur = 0, first
    clear_chain: list[tuple[int, bytes]] = []
    saw_encrypted: list[int] = []
    while cur != C.PAYLOAD_NONE:
        if off + 4 > len(body):
            raise IkeParseError("IKEv2 payload header runs past end of message")
        nxt, _crit, plen = _GEN.unpack_from(body, off)
        if plen < 4 or off + plen > len(body):
            raise IkeParseError(f"bad IKEv2 payload length {plen} for type {cur}")
        pbody = body[off + 4: off + plen]
        if cur == C.V2_SK:
            msg.enc_body, msg.enc_first_payload = pbody, nxt
            saw_encrypted.append(cur)
            break
        if cur == C.V2_SKF:
            if len(pbody) < 4:
                raise IkeParseError("SKF payload too short")
            msg.frag_num, msg.frag_total = struct.unpack_from("!HH", pbody)
            msg.enc_body, msg.enc_first_payload = pbody[4:], nxt
            saw_encrypted.append(cur)
            break
        clear_chain.append((cur, pbody))
        off += plen
        cur = nxt
    msg.clear = _decode_v2(clear_chain)
    msg.clear.types.extend(saw_encrypted)


def _v2_proposals(body: bytes) -> list[Proposal]:
    out: list[Proposal] = []
    off = 0
    while off < len(body):
        if off + 8 > len(body):
            raise IkeParseError("proposal header truncated")
        last, _r, plen, num, proto, spisz, ntrans = struct.unpack_from("!BBHBBBB", body, off)
        if plen < 8 or off + plen > len(body):
            raise IkeParseError(f"bad proposal length {plen}")
        p = Proposal(number=num, protocol=proto, spi=body[off + 8: off + 8 + spisz])
        toff, tend = off + 8 + spisz, off + plen
        for _ in range(ntrans):
            if toff + 8 > tend:
                raise IkeParseError("transform header truncated")
            _l, _r2, tlen, ttype, _r3, tid = struct.unpack_from("!BBHBBH", body, toff)
            if tlen < 8 or toff + tlen > tend:
                raise IkeParseError(f"bad transform length {tlen}")
            key_len = None
            aoff = toff + 8
            while aoff + 4 <= toff + tlen:  # attributes: only Key Length (0x800E) is defined
                atype, aval = struct.unpack_from("!HH", body, aoff)
                if atype == 0x800E:
                    key_len = aval
                aoff += 4
            p.transforms.append(Transform(ttype, tid, key_len))
            toff += tlen
        out.append(p)
        off += plen
        if last == 0:
            break
    return out


def _v2_notify(body: bytes) -> Notify:
    if len(body) < 4:
        raise IkeParseError("Notify payload too short")
    proto, spisz, ntype = struct.unpack_from("!BBH", body)
    if 4 + spisz > len(body):
        raise IkeParseError("Notify SPI runs past payload")
    return Notify(proto, body[4: 4 + spisz], ntype, body[4 + spisz:])


# --------------------------------------------------------------------------------------
# IKEv1
# --------------------------------------------------------------------------------------
def _parse_v1(msg: IkeMessage, first: int, body: bytes) -> None:
    if msg.flags & C.V1_FLAG_ENCRYPT:
        # Everything after the header is encrypted (Main Mode msgs 5-6, Quick Mode, Informational
        # after phase 1). Payload contents are opaque without SKEYID_e.
        msg.encrypted_v1 = True
        msg.enc_body, msg.enc_first_payload = body, first
        return
    ps = PayloadSet()
    try:
        for ptype, _crit, pbody, _nxt in _walk(first, body):
            ps.types.append(ptype)
            if ptype == C.V1_SA:
                ps.v1_proposals.extend(_v1_sa(pbody))
            elif ptype == C.V1_KE:
                ps.ke_len = len(pbody)
            elif ptype == C.V1_NONCE:
                ps.nonce_len = len(pbody)
            elif ptype == C.V1_NOTIFY:
                ps.notifies.append(_v1_notify(pbody))
            elif ptype == C.V1_ID and len(pbody) >= 1:
                ps.id_types.append((ptype, pbody[0]))
            elif ptype == C.V1_VID:
                ps.vendor_ids.append(bytes(pbody))
            elif ptype in (C.V1_HASH, 9):
                ps.has_hash = True
            elif ptype in C.V1_NATD:
                ps.nat_d_count += 1
            elif ptype in (6, 7):
                ps.cert_count += 1
    except struct.error as e:  # pragma: no cover - defensive
        raise IkeParseError(f"IKEv1 struct error: {e}") from e
    msg.clear = ps


def _v1_sa(body: bytes) -> list[V1Proposal]:
    if len(body) < 8:
        raise IkeParseError("IKEv1 SA payload too short")
    off, out = 8, []  # skip DOI(4) + Situation(4)
    while off < len(body):
        if off + 8 > len(body):
            raise IkeParseError("IKEv1 proposal header truncated")
        nxt, _r, plen, num, proto, spisz, ntrans = struct.unpack_from("!BBHBBBB", body, off)
        if plen < 8 or off + plen > len(body):
            raise IkeParseError(f"bad IKEv1 proposal length {plen}")
        p = V1Proposal(num, proto, body[off + 8: off + 8 + spisz])
        toff, tend = off + 8 + spisz, off + plen
        for _ in range(ntrans):
            if toff + 8 > tend:
                raise IkeParseError("IKEv1 transform header truncated")
            _n, _r2, tlen, tnum, tid, _r3 = struct.unpack_from("!BBHBBH", body, toff)
            if tlen < 8 or toff + tlen > tend:
                raise IkeParseError(f"bad IKEv1 transform length {tlen}")
            p.transforms.append(V1Transform(tnum, tid, _v1_attrs(body[toff + 8: toff + tlen])))
            toff += tlen
        out.append(p)
        off += plen
        if nxt == 0:
            break
    return out


def _v1_attrs(buf: bytes) -> dict[int, int]:
    attrs: dict[int, int] = {}
    off = 0
    while off + 4 <= len(buf):
        t, v = struct.unpack_from("!HH", buf, off)
        if t & 0x8000:  # TV format: value is the 16-bit field
            attrs[t & 0x7FFF] = v
            off += 4
        else:  # TLV format: v is the length
            if off + 4 + v > len(buf):
                raise IkeParseError("IKEv1 TLV attribute overruns transform")
            attrs[t] = int.from_bytes(buf[off + 4: off + 4 + v], "big")
            off += 4 + v
    return attrs


def _v1_notify(body: bytes) -> Notify:
    if len(body) < 8:
        raise IkeParseError("IKEv1 Notify payload too short")
    _doi, proto, spisz, ntype = struct.unpack_from("!IBBH", body)
    return Notify(proto, body[8: 8 + spisz], ntype, body[8 + spisz:])
