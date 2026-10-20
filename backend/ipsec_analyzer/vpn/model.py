"""What a non-IPsec VPN analysis produces: a `VpnTunnel`, shaped so every existing table, report and API route can carry it."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..sa.models import Tunnel

# Rows are still `Tunnel`-shaped (id, initiator, responder, status, chosen, timeline ...) so the stored payload, the
# reports and the tunnel list need no special cases; the protocol-specific part lives in `vpn` / `facts`.
PROTOCOLS = {"OpenVPN", "WireGuard"}


@dataclass
class VpnTunnel:
    id: str
    protocol: str  # OpenVPN | WireGuard
    source: str  # capture | config
    initiator: str
    responder: str
    status: str  # established | failed | incomplete | configured
    summary: str  # one line shown where IPsec shows the negotiated suite
    first_ts: float = 0.0
    last_ts: float = 0.0
    failure: str | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    session_ref: str = ""  # shown where IPsec shows the SPI

    def to_dict(self) -> dict[str, Any]:
        base = Tunnel(
            id=self.id, ike_version=0, exchange_mode=self.mode_label(), initiator=self.initiator, responder=self.responder,
            ispi=self.session_ref, rspi="", natt=False, first_ts=self.first_ts, last_ts=self.last_ts,
            status=self.status, failure=self.failure, notes=list(self.notes),
        ).to_dict()
        base["chosen"] = {"label": self.summary}
        base["timeline"] = self.timeline
        base["protocol"] = self.protocol
        base["source"] = self.source
        base["vpn"] = self.facts
        return base

    def mode_label(self) -> str:
        return f"{self.protocol} config" if self.source == "config" else self.protocol
