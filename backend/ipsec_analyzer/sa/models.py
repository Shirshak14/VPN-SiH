"""Tunnel / Security Association model produced by reconstruction. JSON-friendly by design."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Suite:
    """A cryptographic suite as offered or negotiated. Names are IANA registry names."""
    encr: str | None = None
    encr_bits: int | None = None
    integ: str | None = None
    prf: str | None = None
    dh: str | None = None
    auth: str | None = None  # IKEv1 only: authentication method attribute
    lifetime_s: int | None = None
    esn: str | None = None

    def label(self) -> str:
        enc = self.encr or "?"
        if self.encr_bits:
            enc += f"-{self.encr_bits}"
        parts = [enc, self.integ or self.prf, self.dh]
        return "/".join(p for p in parts if p)

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "label": self.label()}


@dataclass
class ChildSa:
    protocol: str  # ESP | AH
    via: str  # IKE_AUTH | CREATE_CHILD_SA | Quick Mode
    ts: float
    suite: Suite
    spi_initiator: str | None = None  # hex; SPI protecting traffic *to* the initiator
    spi_responder: str | None = None
    pfs: bool = False  # key exchange (KE) carried in this exchange
    dh_offered: bool = False  # a DH transform appears in the negotiated proposal
    rekey: bool = False


@dataclass
class TimelineEvent:
    ts: float
    frame: int
    direction: str  # "I->R" | "R->I"
    label: str
    size: int
    encrypted: bool
    retransmit: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class EspFlow:
    spi: str
    src: str
    dst: str
    protocol: str
    packets: int
    bytes: int
    first_ts: float
    last_ts: float
    seq_first: int
    seq_last: int
    seq_gaps: int  # number of missing sequence numbers observed
    seq_replays: int  # packets whose seq <= highest seq already seen
    udp_encap: bool
    mean_iat_ms: float
    mean_len: float


@dataclass
class AttemptSummary:
    """A previous negotiation attempt between the same two endpoints (for downgrade analysis)."""
    ispi: str
    ts: float
    status: str
    failure: str | None
    offered: list[Suite]
    chosen: Suite | None


@dataclass
class Tunnel:
    id: str
    ike_version: int
    exchange_mode: str  # "IKEv2" | "Main Mode" | "Aggressive Mode"
    initiator: str
    responder: str
    ispi: str
    rspi: str
    natt: bool
    first_ts: float
    last_ts: float
    status: str  # established | failed | incomplete
    failure: str | None = None
    offered: list[Suite] = field(default_factory=list)
    chosen: Suite | None = None
    auth_method: str | None = None  # None => not observable (IKEv2 without keys / IKEv1 phase-2)
    auth_observable: bool = False
    child_sas: list[ChildSa] = field(default_factory=list)
    child_observable: bool = False
    ike_rekeys: int = 0
    child_rekeys: int = 0
    create_child_exchanges: int = 0
    retransmits: int = 0
    max_retransmit_streak: int = 0
    cookie_challenges: int = 0
    fragments: int = 0
    dpd_messages: int = 0
    vendor_capabilities: list[str] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    esp_flows: list[EspFlow] = field(default_factory=list)
    prior_attempts: list[AttemptSummary] = field(default_factory=list)
    msg_count: int = 0
    handshake_bytes: int = 0
    handshake_duration_s: float = 0.0
    decrypted: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        import dataclasses

        def conv(o: Any) -> Any:
            if isinstance(o, Suite):
                return o.to_dict()
            if dataclasses.is_dataclass(o):
                return {k: conv(v) for k, v in o.__dict__.items()}
            if isinstance(o, list):
                return [conv(x) for x in o]
            return o

        return conv(self)
