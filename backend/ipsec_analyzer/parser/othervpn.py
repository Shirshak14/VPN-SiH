"""Inventory of non-IPsec VPN traffic (WireGuard, OpenVPN) seen on UDP.

This is the coarse inventory (what was seen, how many packets). The security assessment of OpenVPN and WireGuard
sessions is in `ipsec_analyzer.vpn`: the same packets are fed to its trackers first, so a session they recognise is counted
here too, whatever port it uses. Packets they do not claim fall back to the port/length heuristics below.

WireGuard (whitepaper, "Messages"): every message starts with a 1-byte type (1 initiation, 2 response, 3 cookie reply,
4 transport) and three zero bytes; handshake messages have fixed lengths (148 / 92 / 64 bytes); transport packets are a
multiple of 16 bytes (16-byte header + padded payload + 16-byte tag). The fixed lengths make handshakes a strong
signal; transport packets are only counted once a handshake was seen on the same 4-tuple (either direction), so
unrelated UDP that happens to start with 04 00 00 00 is not claimed.

OpenVPN over UDP: the first byte is `opcode << 3 | key_id`. Hard-reset opcodes (7 client v2, 8 server v2, 10 client v3)
on UDP/1194 mark a session start; other control/data opcodes are counted once a reset was seen on that 4-tuple. This is
port-gated and heuristic: OpenVPN on another port is not found, and a non-OpenVPN service on 1194 sending those first
bytes would be misreported. Ciphers are negotiated inside TLS and are not visible here either way.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..vpn.openvpn import OpenVpnTracker
from ..vpn.wireguard import WireGuardTracker

WG_HANDSHAKE_LEN = {1: 148, 2: 92, 3: 64}
OVPN_PORT = 1194
OVPN_RESET_INIT, OVPN_RESET_RESP = {7, 10}, {8}
OVPN_OPCODES = {4, 5, 6, 7, 8, 9, 10, 11}  # control v1, ack v1, data v1, resets, data v2, client v3, ...
_MAX_ENDPOINTS = 20


@dataclass
class VpnTally:
    protocol: str
    packets: int = 0
    handshake_initiations: int = 0
    handshake_responses: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    endpoints: dict[str, int] = field(default_factory=dict)  # "a:p -> b:p" -> packets

    def to_dict(self) -> dict:
        top = sorted(self.endpoints.items(), key=lambda kv: -kv[1])[:5]
        return {"protocol": self.protocol, "packets": self.packets, "handshake_initiations": self.handshake_initiations,
                "handshake_responses": self.handshake_responses, "first_ts": self.first_ts, "last_ts": self.last_ts,
                "top_flows": [{"flow": k, "packets": v} for k, v in top]}


class OtherVpnInventory:
    def __init__(self) -> None:
        self.tallies: dict[str, VpnTally] = {}
        self._confirmed: set[tuple] = set()  # (protocol, frozenset of the two endpoints)
        self.wireguard = WireGuardTracker()
        self.openvpn = OpenVpnTracker()

    def observe(self, ts: float, src: str, dst: str, sport: int, dport: int, data: bytes, frame: int = 0) -> None:
        kind = None
        for proto_, tracker in (("WireGuard", self.wireguard), ("OpenVPN", self.openvpn)):
            role_ = tracker.observe(ts, frame, src, dst, sport, dport, data)
            if role_ is not None:
                kind = (proto_, role_)
                if role_ in ("init", "resp"):  # a handshake seen by a tracker also confirms the flow for the packet-shape fallback below
                    self._confirmed.add((proto_, frozenset(((src, sport), (dst, dport)))))
                break
        if kind is None:
            kind = self._classify(src, dst, sport, dport, data)
        if kind is None:
            return
        proto, role = kind
        t = self.tallies.setdefault(proto, VpnTally(proto, first_ts=ts))
        t.packets += 1
        t.last_ts = ts
        t.handshake_initiations += role == "init"
        t.handshake_responses += role == "resp"
        flow = f"{src}:{sport} -> {dst}:{dport}"
        if flow in t.endpoints or len(t.endpoints) < _MAX_ENDPOINTS:
            t.endpoints[flow] = t.endpoints.get(flow, 0) + 1

    def _classify(self, src, dst, sport, dport, data: bytes) -> tuple[str, str] | None:
        pair = frozenset(((src, sport), (dst, dport)))
        if len(data) >= 32 and data[0] in (1, 2, 3, 4) and data[1:4] == b"\x00\x00\x00":
            t = data[0]
            if t in WG_HANDSHAKE_LEN:
                if len(data) == WG_HANDSHAKE_LEN[t]:
                    self._confirmed.add(("WireGuard", pair))
                    return "WireGuard", "init" if t == 1 else "resp" if t == 2 else "other"
            elif len(data) % 16 == 0 and ("WireGuard", pair) in self._confirmed:
                return "WireGuard", "data"
        if OVPN_PORT in (sport, dport) and data:
            op = data[0] >> 3
            if op in OVPN_RESET_INIT | OVPN_RESET_RESP and len(data) >= 14:
                self._confirmed.add(("OpenVPN", pair))
                return "OpenVPN", "init" if op in OVPN_RESET_INIT else "resp"
            if op in OVPN_OPCODES and ("OpenVPN", pair) in self._confirmed:
                return "OpenVPN", "data"
        return None

    def summary(self) -> list[dict]:
        return [t.to_dict() for t in self.tallies.values()]
