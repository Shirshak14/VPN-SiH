"""Typed records produced by the parser."""
from __future__ import annotations

from dataclasses import dataclass, field


class IkeParseError(ValueError):
    """Raised when bytes on UDP/500 or UDP/4500 cannot be decoded as a valid IKE message."""


@dataclass(frozen=True)
class Transform:
    """One IKEv2 transform (RFC 7296 3.3.2)."""
    type: int
    id: int
    key_len: int | None = None


@dataclass
class Proposal:
    """One IKEv2 proposal substructure (RFC 7296 3.3.1)."""
    number: int
    protocol: int
    spi: bytes
    transforms: list[Transform] = field(default_factory=list)

    def of_type(self, t: int) -> list[Transform]:
        return [x for x in self.transforms if x.type == t]


@dataclass
class V1Transform:
    """One IKEv1 transform with its decoded attribute map (RFC 2409 Appendix A)."""
    number: int
    id: int
    attrs: dict[int, int] = field(default_factory=dict)


@dataclass
class V1Proposal:
    number: int
    protocol: int
    spi: bytes
    transforms: list[V1Transform] = field(default_factory=list)


@dataclass
class Notify:
    protocol: int
    spi: bytes
    type: int
    data: bytes = b""


@dataclass
class PayloadSet:
    """Everything of interest decoded from one chain of IKE payloads.

    The same structure is used for cleartext payloads and (when keys are supplied) for the
    inner payloads recovered from an IKEv2 Encrypted (SK/SKF) payload.
    """
    types: list[int] = field(default_factory=list)
    proposals: list[Proposal] = field(default_factory=list)  # IKEv2 SA
    v1_proposals: list[V1Proposal] = field(default_factory=list)  # IKEv1 SA
    ke_group: int | None = None
    ke_len: int = 0
    nonce_len: int = 0
    notifies: list[Notify] = field(default_factory=list)
    vendor_ids: list[bytes] = field(default_factory=list)
    id_types: list[tuple[int, int]] = field(default_factory=list)  # (payload type, ID type)
    auth_method: int | None = None  # IKEv2 AUTH payload
    auth_data: bytes = b""
    has_hash: bool = False  # IKEv1 HASH / SIG present
    nat_d_count: int = 0
    ts_count: int = 0
    cert_count: int = 0
    delete_protocols: list[int] = field(default_factory=list)


@dataclass
class IkeMessage:
    frame: int
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    udp_len: int  # UDP payload length (after NAT-T non-ESP marker stripped)
    natt_marker: bool  # arrived on UDP/4500 with non-ESP marker
    ispi: bytes
    rspi: bytes
    version: int  # 1 or 2
    exch: int
    flags: int
    msg_id: int
    length: int  # IKE header length field
    next_payload: int
    digest: bytes  # sha1 of message bytes, used for retransmission detection
    clear: PayloadSet = field(default_factory=PayloadSet)
    # IKEv2 encrypted body (SK) or fragment (SKF), retained so a decryptor can open it later.
    enc_body: bytes | None = None
    enc_first_payload: int = 0
    frag_num: int | None = None
    frag_total: int | None = None
    encrypted_v1: bool = False
    raw: bytes = b""
    decrypted: PayloadSet | None = None
    decrypt_error: str | None = None
    extra_fragment: bool = False  # SKF fragment folded into fragment #1 during reassembly

    @property
    def is_response(self) -> bool:
        if self.version == 2:
            return bool(self.flags & 0x20)
        return False

    @property
    def from_initiator(self) -> bool:
        """IKEv2: Initiator flag. IKEv1: the party that generated the initiator cookie (no flag on wire)."""
        return bool(self.flags & 0x08) if self.version == 2 else True

    @property
    def payloads(self) -> PayloadSet:
        """Decrypted payloads when available, else cleartext ones."""
        return self.decrypted if self.decrypted is not None else self.clear


@dataclass
class EspPacket:
    frame: int
    ts: float
    src: str
    dst: str
    proto: int  # 50 ESP, 51 AH
    spi: int
    seq: int
    length: int
    udp_encap: bool = False


@dataclass
class CaptureStats:
    packets: int = 0
    non_ip: int = 0
    ike_messages: int = 0
    ike_malformed: int = 0
    esp_packets: int = 0
    ah_packets: int = 0
    natt_keepalives: int = 0
    ip_fragments_reassembled: int = 0
    other_udp: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    parse_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)


@dataclass
class ParsedCapture:
    path: str
    ike: list[IkeMessage]
    esp: list[EspPacket]
    stats: CaptureStats
