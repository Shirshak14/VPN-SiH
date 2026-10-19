"""Passive reading of a TLS handshake (RFC 5246 / RFC 8446) from a reassembled byte stream.

OpenVPN carries a normal TLS session over its own reliable control channel, so once the stream is reassembled the
visible part is exactly what a TLS sniffer would see:

  * TLS <= 1.2: ClientHello, ServerHello, Certificate, ServerKeyExchange (curve or DH prime) -- everything but the
    keys is in clear text.
  * TLS 1.3: ClientHello and ServerHello only; the server's certificate and everything after it is encrypted, so
    certificate checks are *not possible* there and that is reported, not guessed.

Nothing is decrypted. Anything unparseable stops the parse and what was read so far is kept.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .suites import SUITE_NAMES

VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}
GROUPS = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048", 257: "ffdhe3072",
          258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192", 21: "secp224r1", 19: "secp192r1", 22: "secp256k1",
          0x6399: "x25519kyber768", 0x11EB: "secp256r1mlkem768", 0x11EC: "x25519mlkem768", 0x11ED: "secp384r1mlkem1024"}
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure", 42: "bad_certificate",
          43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
          47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
          70: "protocol_version", 71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
          90: "user_canceled", 109: "missing_extension", 112: "unrecognized_name", 116: "certificate_required"}
HS_NAMES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate",
            12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify",
            16: "ClientKeyExchange", 20: "Finished"}
_REC_NAMES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
_MAX_CERTS = 4


def suite_name(code: int) -> str:
    return SUITE_NAMES.get(code, f"0x{code:04X}")


class _Short(Exception):
    pass


class _R:
    def __init__(self, b: bytes) -> None:
        self.b, self.i = b, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise _Short
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def var8(self) -> bytes:
        return self.take(self.u8())

    def var16(self) -> bytes:
        return self.take(self.u16())

    @property
    def left(self) -> int:
        return len(self.b) - self.i


@dataclass
class TlsView:
    client_versions: list[str] = field(default_factory=list)  # every version the client offered (legacy field + supported_versions)
    client_min: str | None = None
    client_suites: list[str] = field(default_factory=list)
    client_groups: list[str] = field(default_factory=list)
    server_version: str | None = None  # negotiated
    server_suite: str | None = None
    server_group: str | None = None  # TLS 1.3 key_share group
    kx_curve: str | None = None  # TLS <= 1.2 ECDHE named curve
    kx_dh_bits: int | None = None  # TLS <= 1.2 DHE prime size
    cert_der: list[bytes] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    saw_ccs: bool = False
    saw_encrypted: bool = False
    hello_retry: bool = False
    # (stream offset, label) for every record / handshake message start: used to label the packets that carried them
    marks: list[tuple[int, str]] = field(default_factory=list)


def _ver(v: int) -> str:
    return VERSIONS.get(v, f"0x{v:04X}")


def _parse_client_hello(body: bytes, view: TlsView) -> None:
    r = _R(body)
    legacy = r.u16()
    r.take(32)
    r.var8()
    suites = r.var16()
    r.var8()
    codes = [int.from_bytes(suites[i:i + 2], "big") for i in range(0, len(suites) - 1, 2)]
    view.client_suites = [suite_name(c) for c in codes if not _grease(c)]  # GREASE values (RFC 8701) are noise
    versions = [legacy]
    if r.left >= 2:
        ext = _R(r.var16())
        while ext.left >= 4:
            t, data = ext.u16(), ext.var16()
            if t == 0x002B and data:  # supported_versions (client form: 1-byte length + list)
                versions = [int.from_bytes(data[1 + i:3 + i], "big") for i in range(0, data[0], 2)]
            elif t == 0x000A and len(data) >= 2:  # supported_groups
                g = [int.from_bytes(data[2 + i:4 + i], "big") for i in range(0, int.from_bytes(data[:2], "big"), 2)]
                view.client_groups = [GROUPS.get(x, f"0x{x:04X}") for x in g if not _grease(x)]
    real = [v for v in versions if not _grease(v)]
    view.client_versions = [_ver(v) for v in real]
    if real:
        view.client_min = _ver(min(real))


def _grease(v: int) -> bool:
    return v & 0x0F0F == 0x0A0A and (v >> 8) == (v & 0xFF)


def _parse_server_hello(body: bytes, view: TlsView) -> None:
    r = _R(body)
    legacy = r.u16()
    rnd = r.take(32)
    r.var8()
    suite = r.u16()
    r.u8()
    view.hello_retry = rnd.hex() == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
    version = legacy
    if r.left >= 2:
        ext = _R(r.var16())
        while ext.left >= 4:
            t, data = ext.u16(), ext.var16()
            if t == 0x002B and len(data) == 2:
                version = int.from_bytes(data, "big")
            elif t == 0x0033 and len(data) >= 2:
                g = int.from_bytes(data[:2], "big")
                view.server_group = GROUPS.get(g, f"0x{g:04X}")
    view.server_version = _ver(version)
    view.server_suite = suite_name(suite)


def _parse_server_kx(body: bytes, view: TlsView) -> None:
    """ServerKeyExchange: ECDHE (named curve) or DHE (prime). Which one is decided by the negotiated suite name."""
    name = view.server_suite or ""
    r = _R(body)
    if name.startswith("ECDHE") or name.startswith("AECDH"):
        if r.u8() == 3:
            c = r.u16()
            view.kx_curve = GROUPS.get(c, f"0x{c:04X}")
    elif name.startswith("DHE") or name.startswith("ADH") or name.startswith("EDH"):
        p = r.var16()
        view.kx_dh_bits = len(p.lstrip(b"\x00")) * 8


def parse_stream(data: bytes, *, server: bool) -> TlsView:
    """Read one direction of a TLS stream. `server=True` for the server-to-client direction."""
    view = TlsView()
    pos, hs_buf, hs_start, encrypted = 0, b"", 0, False
    try:
        while pos + 5 <= len(data):
            rtype, ver, length = data[pos], int.from_bytes(data[pos + 1:pos + 3], "big"), int.from_bytes(data[pos + 3:pos + 5], "big")
            if rtype not in _REC_NAMES or ver >> 8 != 3 or length > 16384 + 2048:
                break  # not TLS (or desynchronised): stop rather than guess
            body = data[pos + 5:pos + 5 + length]
            complete = len(body) == length
            view.marks.append((pos, _REC_NAMES[rtype] + (" (encrypted)" if rtype == 23 else "")))
            if rtype == 20:
                view.saw_ccs = True
            elif rtype == 23:
                view.saw_encrypted = encrypted = True
            elif rtype == 21 and not encrypted and len(body) == 2:
                view.alerts.append({"level": "fatal" if body[0] == 2 else "warning", "description": ALERTS.get(body[1], str(body[1])),
                                    "from": "server" if server else "client"})
            elif rtype == 22 and not encrypted and complete:
                if not hs_buf:
                    hs_start = pos + 5
                hs_buf += body
                off = 0
                while len(hs_buf) - off >= 4:
                    mtype, mlen = hs_buf[off], int.from_bytes(hs_buf[off + 1:off + 4], "big")
                    if len(hs_buf) - off - 4 < mlen:
                        break
                    msg = hs_buf[off + 4:off + 4 + mlen]
                    view.marks.append((hs_start + off, HS_NAMES.get(mtype, f"Handshake {mtype}")))
                    _handle(mtype, msg, view, server)
                    off += 4 + mlen
                hs_buf = hs_buf[off:]
                hs_start += off
            if not complete:
                break
            pos += 5 + length
            if rtype == 22 and server and view.server_version == "TLSv1.3":
                encrypted = True  # everything after ServerHello in TLS 1.3 is encrypted even when sent as type 22-looking records
    except (_Short, ValueError, IndexError):
        pass
    return view


def _handle(mtype: int, msg: bytes, view: TlsView, server: bool) -> None:
    try:
        if mtype == 1 and not server:
            _parse_client_hello(msg, view)
        elif mtype == 2 and server:
            _parse_server_hello(msg, view)
        elif mtype == 11 and server and view.server_version != "TLSv1.3":
            r = _R(msg)
            chain = _R(r.take(r.u24()))
            while chain.left >= 3 and len(view.cert_der) < _MAX_CERTS:
                view.cert_der.append(chain.take(chain.u24()))
        elif mtype == 12 and server:
            _parse_server_kx(msg, view)
    except (_Short, ValueError):
        pass


# ----------------------------------------------------------------------------- suite classification
@dataclass(frozen=True)
class SuiteInfo:
    name: str
    kex: str  # ECDHE | DHE | RSA | ECDH | DH | PSK | anon | TLS1.3 | unknown
    pfs: bool
    enc: str | None  # AES-128 / AES-256 / CHACHA20 / 3DES / RC4 / NULL ...
    mode: str | None  # GCM | CCM | POLY1305 | CBC | STREAM | NULL
    mac: str | None  # SHA1 | SHA256 | SHA384 | MD5 | AEAD
    issues: tuple[str, ...]  # keys the rules use: null_cipher, export, anon, rc4, des, 3des, md5, cbc_sha1, no_pfs

    @property
    def aead(self) -> bool:
        return self.mode in ("GCM", "CCM", "POLY1305")


def classify_suite(name: str) -> SuiteInfo:
    n = name.upper()
    if n.startswith("0X"):
        return SuiteInfo(name, "unknown", False, None, None, None, ())
    tls13 = n.startswith("TLS_")
    if tls13:
        kex = "TLS1.3"
    elif n.startswith(("ECDHE-PSK", "DHE-PSK", "RSA-PSK", "PSK")):
        kex = "PSK"
    elif n.startswith("ECDHE") or n.startswith("EECDH"):
        kex = "ECDHE"
    elif n.startswith(("DHE", "EDH")):
        kex = "DHE"
    elif n.startswith(("ADH", "AECDH")):
        kex = "anon"
    elif n.startswith("ECDH-"):
        kex = "ECDH"
    elif n.startswith("DH-"):
        kex = "DH"
    elif n.startswith("SRP"):
        kex = "SRP"
    else:
        kex = "RSA"
    t = n.replace("_", "-")
    if "NULL" in t.split("-"):
        enc, mode = "NULL", "NULL"
    elif "RC4" in t:
        enc, mode = "RC4", "STREAM"
    elif "RC2" in t:
        enc, mode = "RC2", "CBC"
    elif "CBC3" in t or "3DES" in t or "DES-EDE3" in t:
        enc, mode = "3DES", "CBC"
    elif "DES" in t:
        enc, mode = "DES", "CBC"
    elif "CHACHA20" in t:
        enc, mode = "CHACHA20", "POLY1305"
    else:
        enc = mode = None
        for fam in ("AES", "CAMELLIA", "ARIA", "SEED", "IDEA"):
            if fam in t:
                import re
                m = re.search(fam + r"[-]?(128|256)", t)
                enc = f"{fam}-{m.group(1)}" if m else fam
                mode = "GCM" if "GCM" in t else "CCM" if "CCM" in t else "CBC"
                break
    if mode in ("GCM", "CCM", "POLY1305"):
        mac = "AEAD"
    elif "MD5" in t.split("-"):
        mac = "MD5"
    elif "SHA384" in t:
        mac = "SHA384"
    elif "SHA256" in t:
        mac = "SHA256"
    elif "SHA" in t.split("-"):
        mac = "SHA1"
    else:
        mac = None
    issues: list[str] = []
    if enc == "NULL":
        issues.append("null_cipher")
    if "EXP" in t.split("-"):
        issues.append("export")
    if kex == "anon":
        issues.append("anon")
    if enc == "RC4":
        issues.append("rc4")
    if enc in ("DES", "RC2"):
        issues.append("des")
    if enc == "3DES":
        issues.append("3des")
    if mac == "MD5":
        issues.append("md5")
    if mode == "CBC" and mac == "SHA1":
        issues.append("cbc_sha1")
    pfs = kex in ("ECDHE", "DHE", "TLS1.3")
    if kex in ("RSA", "ECDH", "DH") and not tls13:
        issues.append("no_pfs")
    return SuiteInfo(name, kex, pfs, enc, mode, mac, tuple(issues))


def version_rank(v: str | None) -> int:
    order = {"SSLv3": 0, "TLSv1": 1, "TLSv1.1": 2, "TLSv1.2": 3, "TLSv1.3": 4}
    return order.get(v or "", -1)


def read_certificate(der: bytes, when: float | None = None) -> dict[str, Any] | None:
    """Key type/size, signature hash, validity of a DER certificate. None if `cryptography` is missing or the DER is bad."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    except ImportError:  # optional dependency: certificate checks are skipped, and the report says so
        return None
    try:
        c = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    k = c.public_key()
    if isinstance(k, rsa.RSAPublicKey):
        kt, bits = "RSA", k.key_size
    elif isinstance(k, ec.EllipticCurvePublicKey):
        kt, bits = f"EC {k.curve.name}", k.key_size
    elif isinstance(k, dsa.DSAPublicKey):
        kt, bits = "DSA", k.key_size
    elif isinstance(k, ed25519.Ed25519PublicKey):
        kt, bits = "Ed25519", 256
    elif isinstance(k, ed448.Ed448PublicKey):
        kt, bits = "Ed448", 448
    else:
        kt, bits = type(k).__name__, None
    try:
        sig = c.signature_hash_algorithm.name if c.signature_hash_algorithm else None
    except Exception:  # noqa: BLE001 - unsupported signature algorithm OID
        sig = None
    nb, na = c.not_valid_before_utc.timestamp(), c.not_valid_after_utc.timestamp()
    return {"subject": c.subject.rfc4514_string()[:120], "issuer": c.issuer.rfc4514_string()[:120], "key_type": kt, "key_bits": bits,
            "signature_hash": sig, "not_before": nb, "not_after": na, "self_signed": c.issuer == c.subject,
            "expired_at_capture": bool(when and when > 9.5e8 and when > na)}
