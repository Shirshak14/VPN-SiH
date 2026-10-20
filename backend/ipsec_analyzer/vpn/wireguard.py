"""WireGuard: handshake and key-lifetime analysis from the wire (whitepaper, "Messages" and "Timers").

    type 1 initiation (148 B)  type | 3 reserved | sender index (4) | ephemeral (32) | encrypted static (48) | encrypted timestamp (28) | mac1 | mac2
    type 2 response   (92 B)   type | 3 reserved | sender index | receiver index | ephemeral (32) | encrypted empty (16) | mac1 | mac2
    type 3 cookie     (64 B)   type | 3 reserved | receiver index | nonce (24) | encrypted cookie (32)
    type 4 transport           type | 3 reserved | receiver index | counter (8, little endian) | encrypted packet + 16-byte tag

There is nothing to negotiate: the primitives are fixed (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s), so a downgrade is not
possible and no cipher is "chosen". What a passive observer can still assess is whether handshakes are answered, how often
keys are replaced against the protocol's own timers (REKEY_AFTER_TIME 120 s, REJECT_AFTER_TIME 180 s), whether a responder
is shedding load with cookies, whether initiations come faster than any honest peer retries (REKEY_TIMEOUT 5 s) and whether
the same transport counter appears twice. Whether a pre-shared key is configured is not visible on the wire at all.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from .model import VpnTunnel

SUITE = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
LEN = {1: 148, 2: 92, 3: 64}
REKEY_AFTER_TIME, REJECT_AFTER_TIME, REKEY_TIMEOUT = 120.0, 180.0, 5.0
_MAX_TUNNELS = 200
_MAX_INDEXES = 8192
_MAX_COUNTERS = 4096
_MAX_EVENTS = 400
_RUN_GAP_S = 30.0


@dataclass
class _Hs:
    ts: float
    frame: int
    sender: int
    src: tuple[str, int]
    dst: tuple[str, int]
    mac2_set: bool
    answered: bool = False
    resp_ts: float | None = None
    resp_frame: int = 0


@dataclass
class _Keypair:
    init_idx: int
    resp_idx: int
    created: float
    first_data: float | None = None
    last_data: float = 0.0
    packets: dict[str, int] = field(default_factory=lambda: {"i2r": 0, "r2i": 0})
    counters: dict[str, set] = field(default_factory=lambda: {"i2r": set(), "r2i": set()})
    dup: int = 0

    @property
    def age(self) -> float:
        return max(0.0, self.last_data - self.created) if self.packets["i2r"] + self.packets["r2i"] else 0.0


@dataclass
class _Tun:
    initiator: tuple[str, int]
    responder: tuple[str, int]
    first_ts: float
    first_frame: int
    last_ts: float = 0.0
    hs: list[_Hs] = field(default_factory=list)
    keypairs: list[_Keypair] = field(default_factory=list)
    cookies: int = 0
    responses: int = 0
    transport: dict[str, int] = field(default_factory=lambda: {"i2r": 0, "r2i": 0})
    bytes_: dict[str, int] = field(default_factory=lambda: {"i2r": 0, "r2i": 0})
    keepalives: int = 0
    endpoints_seen: dict[str, set] = field(default_factory=lambda: {"i": set(), "r": set()})
    events: list[dict[str, Any]] = field(default_factory=list)
    unmatched_response: bool = False


class WireGuardTracker:
    def __init__(self) -> None:
        self.tunnels: list[_Tun] = []
        self.by_flow: dict[frozenset, _Tun] = {}
        self.pending: dict[int, tuple[_Tun, _Hs]] = {}  # initiation sender index -> (tunnel, handshake)
        self.kp_by_idx: dict[int, tuple[_Tun, _Keypair, str]] = {}  # receiver index -> (tunnel, keypair, direction it receives)
        self.cookie_idx: dict[int, _Tun] = {}

    def observe(self, ts: float, idx: int, src: str, dst: str, sport: int, dport: int, data: bytes) -> str | None:
        """Feed one UDP datagram. Returns "init"/"resp"/"other"/"data" when it is WireGuard, else None."""
        n = len(data)
        if n < 32 or data[0] not in (1, 2, 3, 4) or data[1:4] != b"\x00\x00\x00":
            return None
        t = data[0]
        a, b = (src, sport), (dst, dport)
        flow = frozenset((a, b))
        if t in LEN:
            if n != LEN[t]:
                return None
            if t == 1:
                return self._init(ts, idx, a, b, flow, data)
            if t == 2:
                return self._resp(ts, idx, a, b, flow, data)
            return self._cookie(ts, idx, a, b, flow, data)
        if n % 16 != 0:
            return None
        return self._transport(ts, idx, a, b, flow, data)

    # ------------------------------------------------------------------ message handlers
    def _tun(self, flow: frozenset, a: tuple[str, int], b: tuple[str, int], ts: float, idx: int) -> _Tun | None:
        tun = self.by_flow.get(flow)
        if tun is None:
            if len(self.tunnels) >= _MAX_TUNNELS:
                return None
            tun = _Tun(a, b, ts, idx)
            self.tunnels.append(tun)
            self.by_flow[flow] = tun
        tun.last_ts = ts
        return tun

    def _ev(self, tun: _Tun, ts: float, idx: int, direction: str, label: str, size: int, **notes: Any) -> None:
        if len(tun.events) < _MAX_EVENTS:
            tun.events.append({"ts": ts, "frame": idx, "direction": direction, "label": label, "size": size, "encrypted": False,
                               "retransmit": False, "notes": [f"{k}: {v}" for k, v in notes.items()]})

    def _init(self, ts, idx, a, b, flow, data) -> str | None:
        tun = self._tun(flow, a, b, ts, idx)
        if tun is None:
            return None
        sender = int.from_bytes(data[4:8], "little")
        hs = _Hs(ts, idx, sender, a, b, any(data[132:148]))
        tun.hs.append(hs)
        direction = "I->R" if a == tun.initiator else "R->I"
        tun.endpoints_seen["i" if a == tun.initiator else "r"].add(a)
        if len(self.pending) < _MAX_INDEXES:
            self.pending[sender] = (tun, hs)
        self._ev(tun, ts, idx, direction, "Handshake initiation", 148, sender_index=f"0x{sender:08x}", **({"mac2": "set (cookie in use)"} if hs.mac2_set else {}))
        return "init"

    def _resp(self, ts, idx, a, b, flow, data) -> str | None:
        sender, receiver = int.from_bytes(data[4:8], "little"), int.from_bytes(data[8:12], "little")
        hit = self.pending.get(receiver)
        if hit is not None:
            tun, hs = hit
            hs.answered, hs.resp_ts, hs.resp_frame = True, ts, idx
            kp = _Keypair(receiver, sender, ts)
            tun.keypairs.append(kp)
            if len(self.kp_by_idx) < _MAX_INDEXES:
                self.kp_by_idx[sender] = (tun, kp, "i2r")  # data addressed to the responder's index flows initiator -> responder
                self.kp_by_idx[receiver] = (tun, kp, "r2i")
            rtt = f"{(ts - hs.ts) * 1000:.1f} ms"
        else:
            tun = self._tun(flow, b, a, ts, idx)  # initiation not captured: orient by the response
            if tun is None:
                return None
            tun.unmatched_response = True
            rtt = "initiation not in capture"
        tun.responses += 1
        tun.last_ts = ts
        direction = "R->I" if a == tun.responder else "I->R"
        self._ev(tun, ts, idx, direction, "Handshake response", 92, sender_index=f"0x{sender:08x}", receiver_index=f"0x{receiver:08x}", round_trip=rtt)
        return "resp"

    def _cookie(self, ts, idx, a, b, flow, data) -> str | None:
        tun = self.by_flow.get(flow)
        if tun is None:
            return None
        tun.cookies += 1
        tun.last_ts = ts
        self._ev(tun, ts, idx, "R->I" if a == tun.responder else "I->R", "Cookie reply (responder under load)", 64)
        return "other"

    def _transport(self, ts, idx, a, b, flow, data) -> str | None:
        receiver = int.from_bytes(data[4:8], "little")
        counter = int.from_bytes(data[8:16], "little")
        hit = self.kp_by_idx.get(receiver)
        if hit is None:
            return None  # transport-shaped UDP with no handshake behind it is not claimed
        tun, kp, d = hit
        tun.last_ts = ts
        tun.transport[d] += 1
        tun.bytes_[d] += len(data)
        tun.endpoints_seen["i" if d == "i2r" else "r"].add(a)  # the sender of this packet
        if len(data) == 32:
            tun.keepalives += 1
        kp.packets[d] += 1
        if kp.first_data is None:
            kp.first_data = ts
        kp.last_data = ts
        seen = kp.counters[d]
        if counter in seen:
            kp.dup += 1
        elif len(seen) < _MAX_COUNTERS:
            seen.add(counter)
        ev = tun.events[-1] if tun.events else None
        label = "Transport data"
        arrow = "I->R" if d == "i2r" else "R->I"
        if ev and ev["label"].startswith(label) and ev["direction"] == arrow and ts - ev["_last"] < _RUN_GAP_S:
            ev["_n"] += 1
            ev["_bytes"] += len(data)
            ev["_last"] = ts
            ev["_ka"] = ev["_ka"] and len(data) == 32
            ev["label"] = f"{label} ×{ev['_n']}"
            ev["size"] = ev["_bytes"]
        elif len(tun.events) < _MAX_EVENTS:
            tun.events.append({"ts": ts, "frame": idx, "direction": arrow, "label": f"{label} ×1", "size": len(data), "encrypted": True,
                               "retransmit": False, "notes": [], "_n": 1, "_bytes": len(data), "_last": ts, "_ka": len(data) == 32})
        return "data"

    # ------------------------------------------------------------------ results
    def results(self) -> list[VpnTunnel]:
        return [build_tunnel(t, i) for i, t in enumerate(self.tunnels) if t.hs or t.responses]


def _ep(e: tuple[str, int]) -> str:
    return f"{e[0]}:{e[1]}" if ":" not in e[0] else f"[{e[0]}]:{e[1]}"


def build_tunnel(t: _Tun, n: int) -> VpnTunnel:
    inits = len(t.hs)
    answered = [h for h in t.hs if h.answered]
    completed = sorted(k.created for k in t.keypairs)
    intervals = [round(b - a, 1) for a, b in zip(completed, completed[1:])]
    data_total = t.transport["i2r"] + t.transport["r2i"]
    if answered or t.responses:
        status, failure = ("established", None) if data_total else ("incomplete", "handshake answered but no transport data followed")
    else:
        status, failure = "failed", f"{inits} initiation{'s' if inits != 1 else ''} with no response"
    ts_init = sorted(h.ts for h in t.hs)
    max_burst = 0
    j = 0
    for i, x in enumerate(ts_init):  # most initiations inside any 10 s window
        while x - ts_init[j] > 10.0:
            j += 1
        max_burst = max(max_burst, i - j + 1)
    # key age: how long a transport keypair kept carrying data after it was created; the protocol stops accepting at 180 s
    ages = [(round(k.age, 1), k) for k in t.keypairs if k.first_data is not None]
    max_age = max((a for a, _k in ages), default=0.0)
    dup = sum(k.dup for k in t.keypairs)
    rtts = [round((h.resp_ts - h.ts) * 1000, 1) for h in answered if h.resp_ts]
    roamed = sorted({_ep(e) for side in t.endpoints_seen.values() for e in side} - {_ep(t.initiator), _ep(t.responder)})
    facts: dict[str, Any] = {
        "protocol": "WireGuard", "suite": SUITE, "negotiable": False,
        "initiations": inits, "responses": t.responses, "unanswered_initiations": inits - len(answered),
        "initiation_burst_10s": max_burst, "cookie_replies": t.cookies,
        "initiations_with_cookie": sum(1 for h in t.hs if h.mac2_set),
        "handshakes_completed": len(t.keypairs), "rekey_intervals_s": intervals[:20],
        "median_rekey_interval_s": statistics.median(intervals) if intervals else None,
        "max_key_age_s": max_age, "rekey_after_s": REKEY_AFTER_TIME, "reject_after_s": REJECT_AFTER_TIME,
        "transport_packets": dict(t.transport), "transport_bytes": dict(t.bytes_), "keepalive_packets": t.keepalives,
        "counter_duplicates": dup, "counter_packets": data_total,
        "median_round_trip_ms": statistics.median(rtts) if rtts else None,
        "roamed_endpoints": roamed[:5], "duration_s": round(t.last_ts - t.first_ts, 2),
        "initiation_not_captured": t.unmatched_response,
        "frames": [h.frame for h in t.hs[:5]],
        "psk": "not observable on the wire",
    }
    events = []
    for e in sorted(t.events, key=lambda e: e["ts"]):
        e = dict(e)
        if "_n" in e:
            if e.pop("_ka"):
                e["notes"] = ["keepalives only (32-byte packets)"]
            for k in ("_n", "_bytes", "_last"):
                e.pop(k, None)
        events.append(e)
    summary = f"{SUITE} · {len(t.keypairs)} handshake{'s' if len(t.keypairs) != 1 else ''}" if t.keypairs else f"{SUITE} · no completed handshake"
    return VpnTunnel(id=f"wg-{n + 1}-{(t.hs[0].sender if t.hs else 0):08x}", protocol="WireGuard", source="capture", initiator=_ep(t.initiator),
                     responder=_ep(t.responder), status=status, summary=summary, first_ts=t.first_ts, last_ts=t.last_ts, failure=failure,
                     facts=facts, timeline=events, session_ref=f"0x{(t.hs[0].sender if t.hs else 0):08x}")
