"""Optional IKEv2 decryption using externally supplied SK_e/SK_a keys.

IKEv2 encrypts everything after IKE_SA_INIT (AUTH method, child-SA proposals, PFS key exchange,
traffic selectors), so without keys those facts are *not observable* from a capture. When a
Wireshark-format `ikev2_decryption_table` is supplied (as exported by strongSwan's save-keys
plugin or by the lab), this module opens the SK/SKF payloads and feeds the inner payloads
back through the normal decoder.

Key-table row (Wireshark format, hex fields):
    SPIi, SPIr, SK_ei, SK_er, "<encryption alg>", SK_ai, SK_ar, "<integrity alg>"

Supported: AES-CBC, AES-CTR, AES-GCM (8/12/16), AES-CCM (8/12/16), 3DES-CBC.
Integrity tags on CBC/CTR are not verified (this is an analyzer, not an IPsec endpoint).
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .ike import parse_v2_payloads
from .models import IkeMessage, IkeParseError, ParsedCapture, PayloadSet

_HDR_AND_SK = 28 + 4  # IKE header + SK generic payload header (AEAD associated data)

# integrity name -> ICV length in bytes as carried on the wire (for CBC/CTR trailing tag)
_ICV_LEN = {
    "HMAC_MD5_96": 12, "HMAC_SHA1_96": 12, "HMAC_SHA1_160": 20, "AES_XCBC_96": 12,
    "HMAC_SHA2_256_128": 16, "HMAC_SHA2_384_192": 24, "HMAC_SHA2_512_256": 32,
    "ANY 96-BITS OF AUTHENTICATION [NO CHECKING]": 12,
}


@dataclass(frozen=True)
class IkeSaKeys:
    ispi: bytes
    rspi: bytes
    sk_ei: bytes
    sk_er: bytes
    encr: str  # normalised e.g. "AES-CBC-256"
    sk_ai: bytes
    sk_ar: bytes
    integ: str  # normalised e.g. "HMAC_SHA2_256_128"


def load_key_table(path: str | Path) -> list[IkeSaKeys]:
    """Read a Wireshark-format IKEv2 decryption table."""
    rows: list[IkeSaKeys] = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.reader(line for line in f if line.strip() and not line.startswith("#")):
            if len(r) < 8:
                continue
            ispi, rspi, sk_ei, sk_er, enc, sk_ai, sk_ar, integ = r[:8]
            if not sk_ei:
                continue
            rows.append(IkeSaKeys(
                bytes.fromhex(ispi), bytes.fromhex(rspi), bytes.fromhex(sk_ei), bytes.fromhex(sk_er),
                _norm_enc(enc), bytes.fromhex(sk_ai or ""), bytes.fromhex(sk_ar or ""),
                _norm_integ(integ),
            ))
    return rows


def _norm_enc(s: str) -> str:
    return s.split("[")[0].strip().upper().replace(" ", "_")


def _norm_integ(s: str) -> str:
    return s.split("[")[0].strip().upper()


def _icv_len(enc: str, integ: str) -> int:
    if "GCM" in enc or "CCM" in enc:
        return int(enc.split("WITH_")[1].split("_")[0])  # e.g. AES-GCM-256_WITH_16_OCTET_ICV
    return _ICV_LEN.get(integ, 12)


def _decrypt_sk(msg: IkeMessage, keys: IkeSaKeys, body: bytes) -> bytes:
    """Return the *inner payload bytes* (padding stripped) of an SK/SKF body."""
    key = keys.sk_ei if msg.from_initiator else keys.sk_er
    enc = keys.encr
    icv = _icv_len(enc, keys.integ)
    try:
        if enc.startswith("AES-GCM") or enc.startswith("AES-CCM"):
            tag_len = icv
            salt_len = 4 if "GCM" in enc else 3
            if len(body) < 8 + tag_len + 1:
                raise IkeParseError("SK body too short for AEAD")
            k, salt = key[:-salt_len], key[-salt_len:]
            iv, ct, tag = body[:8], body[8:-tag_len], body[-tag_len:]
            aad = msg.raw[:_HDR_AND_SK] if msg.frag_num is None else msg.raw[:_HDR_AND_SK + 4]
            if enc.startswith("AES-GCM"):
                dec = Cipher(algorithms.AES(k), modes.GCM(salt + iv, tag, min_tag_length=4)).decryptor()
                dec.authenticate_additional_data(aad)
                pt = dec.update(ct) + dec.finalize()
            else:
                pt = AESCCM(k, tag_length=tag_len).decrypt(salt + iv, ct + tag, aad)
        elif enc.startswith("AES-CTR"):
            k, nonce = key[:-4], key[-4:]
            iv, ct = body[:8], body[8: len(body) - icv]
            pt = Cipher(algorithms.AES(k), modes.CTR(nonce + iv + b"\x00\x00\x00\x01")).decryptor().update(ct)
        elif enc.startswith("AES-CBC"):
            iv, ct = body[:16], body[16: len(body) - icv]
            if len(ct) % 16:
                raise IkeParseError("CBC ciphertext not block aligned")
            pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
        elif enc.startswith("3DES") or enc == "DES":  # single DES = TripleDES with an 8-byte key
            iv, ct = body[:8], body[8: len(body) - icv]
            if len(ct) % 8:
                raise IkeParseError("3DES ciphertext not block aligned")
            pt = Cipher(TripleDES(key * 3 if enc == "DES" else key), modes.CBC(iv)).decryptor().update(ct)
        else:
            raise IkeParseError(f"unsupported encryption algorithm in key table: {enc}")
    except InvalidTag as e:
        raise IkeParseError("AEAD tag verification failed (wrong key or corrupted packet)") from e
    if not pt:
        return b""
    pad = pt[-1]
    if pad + 1 > len(pt):
        raise IkeParseError("invalid IKE padding length after decryption")
    return pt[: len(pt) - pad - 1]


def apply_keys(cap: ParsedCapture, keys: list[IkeSaKeys]) -> None:
    """Decrypt every IKEv2 message we hold keys for; reassemble SKF fragments (RFC 7383)."""
    by_spi = {(k.ispi, k.rspi): k for k in keys}
    frags: dict[tuple, list[IkeMessage]] = {}
    for m in cap.ike:
        if m.version != 2 or m.enc_body is None:
            continue
        k = by_spi.get((m.ispi, m.rspi))
        if k is None:
            m.decrypt_error = "no key for this IKE SA"
            continue
        if m.frag_num is not None:
            frags.setdefault((m.ispi, m.rspi, m.msg_id, m.is_response), []).append(m)
            continue
        _open_single(m, k, m.enc_body)
    for group in frags.values():
        group.sort(key=lambda x: x.frag_num or 0)
        k = by_spi[(group[0].ispi, group[0].rspi)]
        total = group[0].frag_total or 0
        if [g.frag_num for g in group] != list(range(1, total + 1)):
            for g in group:
                g.decrypt_error = f"incomplete fragment set ({len(group)}/{total})"
            continue
        try:
            plain = b"".join(_decrypt_sk(g, k, g.enc_body or b"") for g in group)
            group[0].decrypted = parse_v2_payloads(group[0].enc_first_payload, plain)
        except IkeParseError as e:
            group[0].decrypt_error = str(e)
        for g in group[1:]:
            g.decrypted, g.extra_fragment = PayloadSet(), True


def _open_single(m: IkeMessage, k: IkeSaKeys, body: bytes) -> None:
    try:
        plain = _decrypt_sk(m, k, body)
        m.decrypted = parse_v2_payloads(m.enc_first_payload, plain) if plain else PayloadSet()
    except IkeParseError as e:
        m.decrypt_error = str(e)
