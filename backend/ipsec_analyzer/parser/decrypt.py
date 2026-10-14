"""Optional IKE decryption using externally supplied keys (IKEv2 SK_e/SK_a; IKEv1 phase-1 encryption key).

IKEv2 encrypts everything after IKE_SA_INIT (AUTH method, child-SA proposals, PFS key exchange,
traffic selectors), so without keys those facts are *not observable* from a capture. When a
Wireshark-format `ikev2_decryption_table` is supplied (as exported by strongSwan's save-keys
plugin or by the lab), this module opens the SK/SKF payloads and feeds the inner payloads
back through the normal decoder.

Key-table row (Wireshark format, hex fields):
    SPIi, SPIr, SK_ei, SK_er, "<encryption alg>", SK_ai, SK_ar, "<integrity alg>"

Supported: AES-CBC, AES-CTR, AES-GCM (8/12/16), AES-CCM (8/12/16), 3DES-CBC.
Integrity tags on CBC/CTR are not verified (this is an analyzer, not an IPsec endpoint).

IKEv1 (RFC 2409 Appendix B) uses Wireshark's two-column `ikev1_decryption_table`:

    initiator cookie (hex), encryption key (hex; the already-expanded key derived from SKEYID_e)

Everything after the header of an encrypted IKEv1 message is one CBC stream, so the IV matters:
  * first encrypted phase-1 message : IV = H(g^xi | g^xr), truncated to the block size (H = negotiated hash)
  * later phase-1 messages          : IV = last ciphertext block of the previous phase-1 message
  * other Message IDs (Quick Mode, Informational, Transaction): first message IV = H(last phase-1 CBC block | Message ID),
    later ones in the same exchange chain from the previous ciphertext block.
Retransmissions are skipped so they cannot advance the chain. A wrong key or IV shows up as a payload chain that
does not parse, which is reported as a decrypt error rather than guessed around.
"""
from __future__ import annotations

import csv
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from . import constants as C
from .ike import parse_v1_payloads, parse_v2_payloads
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


@dataclass(frozen=True)
class IkeV1Key:
    ispi: bytes
    enc_key: bytes  # expanded phase-1 encryption key (Wireshark "Encryption Key" column)


def load_key_table(path: str | Path) -> list[IkeSaKeys | IkeV1Key]:
    """Read a Wireshark-format decryption table: 8-column IKEv2 rows and/or 2-column IKEv1 rows."""
    rows: list[IkeSaKeys | IkeV1Key] = []
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.reader(line for line in f if line.strip() and not line.startswith("#")):
            if len(r) == 2:
                try:
                    ispi, key = bytes.fromhex(r[0].strip()), bytes.fromhex(r[1].strip())
                except ValueError:
                    continue
                if len(ispi) == 8 and key:
                    rows.append(IkeV1Key(ispi, key))
                continue
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


def apply_keys(cap: ParsedCapture, keys: list[IkeSaKeys | IkeV1Key]) -> None:
    """Decrypt every IKE message we hold keys for; reassemble IKEv2 SKF fragments (RFC 7383)."""
    v1_keys = [k for k in keys if isinstance(k, IkeV1Key)]
    keys = [k for k in keys if isinstance(k, IkeSaKeys)]
    _apply_v1_keys(cap, v1_keys)
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


# ----------------------------------------------------------------------------- IKEv1
_V1_HASH = {1: hashlib.md5, 2: hashlib.sha1, 4: hashlib.sha256, 5: hashlib.sha384, 6: hashlib.sha512}


def _v1_cipher(enc_id: int, key: bytes, keylen_attr: int | None):
    """(cipher factory taking an IV, block size, key) for the negotiated phase-1 encryption."""
    if enc_id == 5:
        need, bs, alg = 24, 8, lambda k: TripleDES(k)
    elif enc_id == 1:
        need, bs, alg = 8, 8, lambda k: TripleDES(k * 3)
    elif enc_id == 7:
        need = (keylen_attr // 8) if keylen_attr else len(key)
        if need not in (16, 24, 32):
            raise IkeParseError(f"unsupported AES key length {need * 8} bits")
        bs, alg = 16, lambda k: algorithms.AES(k)
    else:
        raise IkeParseError(f"unsupported IKEv1 encryption algorithm id {enc_id}")
    if len(key) < need:
        raise IkeParseError(f"supplied key is {len(key)} bytes, {need} needed for the negotiated cipher")
    return (lambda iv: Cipher(alg(key[:need]), modes.CBC(iv)).decryptor()), bs


def _apply_v1_keys(cap: ParsedCapture, keys: list[IkeV1Key]) -> None:
    by_ispi = {k.ispi: k.enc_key for k in keys}
    groups: dict[bytes, list[IkeMessage]] = {}
    for m in cap.ike:
        if m.version == 1 and m.encrypted_v1:
            groups.setdefault(m.ispi, [])
    if not groups:
        return
    for m in cap.ike:
        if m.version == 1 and m.ispi in groups:
            groups[m.ispi].append(m)
    for ispi, msgs in groups.items():
        if ispi not in by_ispi:
            for m in msgs:
                if m.encrypted_v1:
                    m.decrypt_error = "no key for this IKE SA"
            continue
        try:
            _decrypt_v1_sa(sorted(msgs, key=lambda m: (m.ts, m.frame)), by_ispi[ispi])
        except IkeParseError as e:
            for m in msgs:
                if m.encrypted_v1 and m.decrypted is None:
                    m.decrypt_error = str(e)


def _decrypt_v1_sa(msgs: list[IkeMessage], key: bytes) -> None:
    initiator = msgs[0].src
    gi = next((m.clear.ke_data for m in msgs if m.clear.ke_data and m.src == initiator), b"")
    gr = next((m.clear.ke_data for m in msgs if m.clear.ke_data and m.src != initiator), b"")
    chosen = next((p.transforms[0].attrs for m in msgs if m.src != initiator for p in m.clear.v1_proposals[:1] if p.transforms), None)
    if not (gi and gr):
        raise IkeParseError("both Diffie-Hellman public values must be in the capture to derive the IKEv1 IV")
    if chosen is None:
        raise IkeParseError("responder's chosen phase-1 transform not in the capture")
    hash_fn = _V1_HASH.get(chosen.get(C.A1_HASH, 0))
    if hash_fn is None:
        raise IkeParseError(f"unsupported IKEv1 hash algorithm id {chosen.get(C.A1_HASH)}")
    make, bs = _v1_cipher(chosen.get(C.A1_ENC, 0), key, chosen.get(C.A1_KEYLEN))

    p1_iv = hash_fn(gi + gr).digest()[:bs]  # also the "last phase-1 CBC block" until a phase-1 message is encrypted
    chain: dict[int, bytes] = {}  # message id -> IV for that exchange's next encrypted message
    done: dict[bytes, PayloadSet] = {}
    for m in msgs:
        if not m.encrypted_v1 or m.enc_body is None:
            continue
        if m.digest in done:  # retransmission: same ciphertext, same plaintext, must not advance the chain
            m.decrypted = done[m.digest]
            continue
        body = m.enc_body
        if not body or len(body) % bs:
            m.decrypt_error = f"ciphertext length {len(body)} is not a multiple of the {bs}-byte block"
            continue
        if m.msg_id == 0:
            iv = chain.get(0, p1_iv)
        else:
            iv = chain.get(m.msg_id) or hash_fn(p1_iv + struct.pack("!I", m.msg_id)).digest()[:bs]
        dec = make(iv)
        plain = dec.update(body) + dec.finalize()
        chain[m.msg_id] = body[-bs:]
        if m.msg_id == 0:
            p1_iv = body[-bs:]  # phase 2 IVs derive from the last phase-1 CBC block
        try:
            m.decrypted = parse_v1_payloads(m.enc_first_payload, plain)
        except IkeParseError as e:
            m.decrypt_error = f"payloads do not parse after decryption ({e}); wrong key, IV or unsupported mode"
            continue
        done[m.digest] = m.decrypted
