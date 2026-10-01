"""Byte-level IKE/ESP message encoder used to build *synthetic* captures.

Everything produced here is labelled `synthetic` in the manifest. The encoder is written from
RFC 7296 / RFC 2409 layouts and real cryptography is applied to encrypted payloads
(AES-CBC/GCM, 3DES/DES with HMAC ICVs) so the analyzer's decryptor is exercised on genuine
ciphertext. Because the encoder and the decoder are both ours, decoder correctness is validated
separately on third-party Wireshark captures (see tests/test_public_captures.py).
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import struct
from dataclasses import dataclass
from random import Random

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ipsec_analyzer.parser import constants as C

_ENCR_ID = {v: k for k, v in C.ENCR.items()}
_PRF_ID = {v: k for k, v in C.PRF.items()}
_INTEG_ID = {v: k for k, v in C.INTEG.items()}
_DH_ID = {v: k for k, v in C.DH_GROUP.items()}
_V1_ENC_ID = {v: k for k, v in C.V1_ENC.items()}
_V1_HASH_ID = {v: k for k, v in C.V1_HASH_ALGORITHMS.items()}
_V1_AUTH_ID = {v: k for k, v in C.V1_AUTH.items()}

_HASH = {"HMAC_MD5_96": (hashlib.md5, 12, 16), "HMAC_SHA1_96": (hashlib.sha1, 12, 20),
         "HMAC_SHA2_256_128": (hashlib.sha256, 16, 32), "HMAC_SHA2_384_192": (hashlib.sha384, 24, 48),
         "HMAC_SHA2_512_256": (hashlib.sha512, 32, 64)}


@dataclass(frozen=True)
class SuiteSpec:
    encr: str  # IANA name, e.g. "AES_CBC", "AES_GCM_16", "3DES", "DES", "NULL"
    bits: int | None = None
    integ: str | None = None  # None for AEAD
    prf: str | None = None
    dh: str | None = None

    @property
    def aead(self) -> bool:
        return _ENCR_ID.get(self.encr, 0) in C.AEAD_ENCR

    def label(self) -> str:
        return "/".join(x for x in (f"{self.encr}{'-' + str(self.bits) if self.bits else ''}",
                                    self.integ or self.prf, self.dh) if x)


# ------------------------------------------------------------------------- payloads
def _gen(next_type: int, body: bytes) -> bytes:
    return struct.pack("!BBH", next_type, 0, 4 + len(body)) + body


def chain(items: list[tuple[int, bytes]], tail_next: int = 0) -> bytes:
    """[(payload_type, body)] -> bytes with correct next-payload linkage."""
    out = b""
    for i, (_t, body) in enumerate(items):
        nxt = items[i + 1][0] if i + 1 < len(items) else tail_next
        out += _gen(nxt, body)
    return out


def _transform(last: bool, ttype: int, tid: int, key_bits: int | None = None) -> bytes:
    attr = struct.pack("!HH", 0x800E, key_bits) if key_bits else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attr), ttype, 0, tid) + attr


def v2_proposal_body(props: list[tuple[int, int, bytes, list[tuple[int, int, int | None]]]]) -> bytes:
    out = b""
    for i, (num, proto, spi, transforms) in enumerate(props):
        tb = b"".join(_transform(j == len(transforms) - 1, t, tid, kb) for j, (t, tid, kb) in enumerate(transforms))
        length = 8 + len(spi) + len(tb)
        out += struct.pack("!BBHBBBB", 0 if i == len(props) - 1 else 2, 0, length, num, proto, len(spi), len(transforms)) + spi + tb
    return out


def ike_transforms(s: SuiteSpec) -> list[tuple[int, int, int | None]]:
    t = [(C.T_ENCR, _ENCR_ID[s.encr], s.bits if s.encr.startswith("AES") or s.encr.startswith("CAMELLIA") else None)]
    if s.integ:
        t.append((C.T_INTEG, _INTEG_ID[s.integ], None))
    t.append((C.T_PRF, _PRF_ID[s.prf or "HMAC_SHA2_256"], None))
    if s.dh:
        t.append((C.T_DH, _DH_ID[s.dh], None))
    return t


def esp_transforms(s: SuiteSpec) -> list[tuple[int, int, int | None]]:
    t = [(C.T_ENCR, _ENCR_ID[s.encr], s.bits if s.encr.startswith("AES") else None)]
    if s.integ:
        t.append((C.T_INTEG, _INTEG_ID[s.integ], None))
    if s.dh:
        t.append((C.T_DH, _DH_ID[s.dh], None))
    t.append((C.T_ESN, 0, None))
    return t


def v2_sa_ike(suites: list[SuiteSpec]) -> bytes:
    return v2_proposal_body([(i + 1, C.PROTO_IKE, b"", ike_transforms(s)) for i, s in enumerate(suites)])


def v2_sa_esp(suites: list[SuiteSpec], spi: bytes) -> bytes:
    return v2_proposal_body([(i + 1, C.PROTO_ESP, spi, esp_transforms(s)) for i, s in enumerate(suites)])


def ke_body(group: str, rng: Random, v1: bool = False) -> bytes:
    size = {"MODP_768": 96, "MODP_1024": 128, "MODP_1536": 192, "MODP_2048": 256, "MODP_3072": 384,
            "MODP_4096": 512, "ECP_256": 64, "ECP_384": 96, "ECP_521": 132, "CURVE_25519": 32}.get(group, 256)
    data = rng.randbytes(size)
    return data if v1 else struct.pack("!HH", _DH_ID[group], 0) + data


def notify_body(ntype: int, data: bytes = b"", proto: int = 0, spi: bytes = b"") -> bytes:
    return struct.pack("!BBH", proto, len(spi), ntype) + spi + data


def ts_payload(lo: str, hi: str) -> bytes:
    # Number of TS (1) + 3 reserved + one IPv4 address-range selector (RFC 7296 3.13.1)
    sel = struct.pack("!BBHHH", 7, 0, 16, 0, 65535) + ipaddress.IPv4Address(lo).packed + ipaddress.IPv4Address(hi).packed
    return struct.pack("!BBBB", 1, 0, 0, 0) + sel


def ike_header(ispi: bytes, rspi: bytes, first: int, version: int, exch: int, flags: int, msg_id: int, body: bytes) -> bytes:
    return struct.pack("!8s8sBBBBII", ispi, rspi, first, version, exch, flags, msg_id, 28 + len(body)) + body


# ------------------------------------------------------------------------- IKEv2 encryption
@dataclass
class IkeKeys:
    ispi: bytes
    rspi: bytes
    encr: str
    bits: int | None
    integ: str | None
    sk_ei: bytes = b""
    sk_er: bytes = b""
    sk_ai: bytes = b""
    sk_ar: bytes = b""

    @classmethod
    def generate(cls, ispi: bytes, rspi: bytes, s: SuiteSpec, rng: Random) -> "IkeKeys":
        k = cls(ispi, rspi, s.encr, s.bits, s.integ)
        klen = {"3DES": 24, "DES": 8}.get(s.encr, (s.bits or 128) // 8)
        if s.encr == "AES_GCM_16":
            klen += 4  # salt
        k.sk_ei, k.sk_er = rng.randbytes(klen), rng.randbytes(klen)
        if s.integ:
            klen_a = _HASH[s.integ][2]
            k.sk_ai, k.sk_ar = rng.randbytes(klen_a), rng.randbytes(klen_a)
        return k

    def wireshark_row(self) -> str:
        name = {
            "AES_CBC": f"AES-CBC-{self.bits} [RFC3602]", "3DES": "3DES [RFC2451]", "DES": "DES [RFC2405]",
            "AES_GCM_16": f"AES-GCM-{self.bits} with 16 octet ICV [RFC5282]",
        }[self.encr]
        integ = f"{self.integ} [RFC4868]" if self.integ else "NONE [RFC4306]"
        return ",".join([self.ispi.hex(), self.rspi.hex(), self.sk_ei.hex(), self.sk_er.hex(), f'"{name}"',
                         self.sk_ai.hex(), self.sk_ar.hex(), f'"{integ}"'])


def seal_sk_message(keys: IkeKeys, rng: Random, *, exch: int, msg_id: int, from_initiator: bool, is_response: bool,
                    inner_first: int, inner: bytes, ispi: bytes | None = None, rspi: bytes | None = None,
                    frag: tuple[int, int] | None = None) -> bytes:
    """Build a complete IKEv2 message whose payloads are inside one SK (or SKF) payload."""
    flags = 0x10 | (0x08 if from_initiator else 0) | (0x20 if is_response else 0)
    key = keys.sk_ei if from_initiator else keys.sk_er
    akey = keys.sk_ai if from_initiator else keys.sk_ar
    ptype = C.V2_SKF if frag else C.V2_SK
    frag_hdr = struct.pack("!HH", *frag) if frag else b""
    if keys.encr == "AES_GCM_16":
        iv, tag_len, block = rng.randbytes(8), 16, 4
    elif keys.encr in ("3DES", "DES"):
        iv, tag_len, block = rng.randbytes(8), _HASH[keys.integ][1], 8
    else:
        iv, tag_len, block = rng.randbytes(16), _HASH[keys.integ][1], 16
    pad = (-(len(inner) + 1)) % block
    pt = inner + bytes(pad) + bytes([pad])
    body_len = len(frag_hdr) + len(iv) + len(pt) + tag_len
    total = 28 + 4 + body_len
    hdr = struct.pack("!8s8sBBBBII", ispi or keys.ispi, rspi or keys.rspi, ptype, 0x20, exch, flags, msg_id, total)
    sk_hdr = struct.pack("!BBH", inner_first, 0, 4 + body_len)
    aad = hdr + sk_hdr + frag_hdr
    if keys.encr == "AES_GCM_16":
        k, salt = key[:-4], key[-4:]
        enc = Cipher(algorithms.AES(k), modes.GCM(salt + iv)).encryptor()
        enc.authenticate_additional_data(aad)
        ct = enc.update(pt) + enc.finalize()
        return aad + iv + ct + enc.tag
    if keys.encr == "AES_CBC":
        ct = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor().update(pt)
    else:
        k3 = key * 3 if keys.encr == "DES" else key  # single DES == 3DES with K1=K2=K3
        ct = Cipher(TripleDES(k3), modes.CBC(iv)).encryptor().update(pt)
    msg_wo_icv = aad + iv + ct
    h, trunc, _ = _HASH[keys.integ]
    icv = hmac.new(akey, msg_wo_icv, h).digest()[:trunc]
    return msg_wo_icv + icv


# ------------------------------------------------------------------------- IKEv1
def v1_transform(s: SuiteSpec, auth: str, life: int) -> bytes:
    def tv(t: int, v: int) -> bytes:
        return struct.pack("!HH", 0x8000 | t, v)

    attrs = tv(C.A1_ENC, _V1_ENC_ID[C.V2_ENCR_TO_V1[s.encr]])
    if s.bits and s.encr == "AES_CBC":
        attrs += tv(C.A1_KEYLEN, s.bits)
    hname = C.V2_INTEG_TO_V1[s.integ or "HMAC_SHA2_256_128"]
    attrs += tv(C.A1_HASH, _V1_HASH_ID[hname]) + tv(C.A1_AUTH, _V1_AUTH_ID[auth]) + tv(C.A1_GROUP, _DH_ID[s.dh or "MODP_2048"])
    attrs += tv(C.A1_LIFE_TYPE, 1)
    attrs += tv(C.A1_LIFE_DUR, life) if life < 65536 else struct.pack("!HH", C.A1_LIFE_DUR, 4) + struct.pack("!I", life)
    return attrs  # attribute block; framing added in v1_sa_body


def v1_sa_body(suites: list[SuiteSpec], auth: str, life: int) -> bytes:
    trans = b""
    for i, s in enumerate(suites):
        attrs = v1_transform(s, auth, life)
        last = i == len(suites) - 1
        trans += struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attrs), i + 1, 1, 0) + attrs
    prop = struct.pack("!BBHBBBB", 0, 0, 8 + len(trans), 1, 1, 0, len(suites)) + trans
    return struct.pack("!II", 1, 1) + prop


def v1_message(ispi: bytes, rspi: bytes, exch: int, flags: int, msg_id: int, items: list[tuple[int, bytes]]) -> bytes:
    body = chain(items)
    first = items[0][0] if items else 0
    return ike_header(ispi, rspi, first, 0x10, exch, flags, msg_id, body)


def v1_vendor_ids(dpd: bool = True, natt: bool = True, xauth: bool = False, frag: bool = False) -> list[tuple[int, bytes]]:
    vids = []
    for name, on in (("NAT-T RFC 3947", natt), ("DPD RFC 3706", dpd), ("XAUTH", xauth), ("IKE Fragmentation", frag)):
        if on:
            vids.append((C.V1_VID, next(k for k, v in C.VENDOR_IDS.items() if v == name)))
    return vids


# ------------------------------------------------------------------------- ESP + frames
def esp_packet(spi: int, seq: int, payload_len: int, rng: Random) -> bytes:
    return struct.pack("!II", spi, seq) + rng.randbytes(max(payload_len - 8, 8))


def ipv4_udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes, ident: int) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return _ipv4(src, dst, 17, udp, ident)


def ipv4_esp_frame(src: str, dst: str, esp: bytes, ident: int) -> bytes:
    return _ipv4(src, dst, 50, esp, ident)


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int) -> bytes:
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0,
                      ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    s = sum(struct.unpack("!10H", hdr))
    s = (s & 0xFFFF) + (s >> 16)
    s = (s & 0xFFFF) + (s >> 16)
    hdr = hdr[:10] + struct.pack("!H", ~s & 0xFFFF) + hdr[12:]
    return hdr + payload


def ethernet(frame_ip: bytes, src_mac: bytes, dst_mac: bytes) -> bytes:
    return dst_mac + src_mac + b"\x08\x00" + frame_ip


def write_pcap(path: str, packets: list[tuple[float, bytes]]) -> None:
    """Classic libpcap, Ethernet link type, microsecond timestamps."""
    packets = sorted(packets, key=lambda p: p[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(data), len(data)) + data)
