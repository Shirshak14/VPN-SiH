"""OpenVPN over UDP: session tracking, control-channel reassembly and what a passive observer can learn from it.

Wire format (OpenVPN `ssl_pkt.h` / protocol description in the OpenVPN reference manual, "TLS Mode Options"):

    byte 0          opcode << 3 | key_id
    P_CONTROL_HARD_RESET_CLIENT_V2 (7) / _SERVER_V2 (8) / P_CONTROL_V1 (4) / P_ACK_V1 (5) / P_CONTROL_SOFT_RESET_V1 (3):
        session id (8) | [tls-auth: HMAC + replay id + time] | ack count (1) | acks (4 each) | [remote session id (8) if acks]
        | [packet id (4) unless P_ACK] | payload (a slice of the TLS byte stream)
    tls-crypt:  opcode | session id | packet id (4) | time (4) | 32-byte tag | encrypted (acks, packet id, payload)
    tls-crypt-v2: the client's first packet is opcode 10 and ends with the wrapped per-client key; the rest as tls-crypt
    P_CONTROL_WKC_V1 (11): tls-crypt-v2 control packet that repeats the wrapped client key
    P_DATA_V2 (9): opcode | peer id (3) | encrypted data   -- cipher and key are negotiated inside TLS and are not visible

What this can and cannot establish, honestly:
  * Plain and tls-auth control channels carry TLS in clear text, so the TLS version, the cipher suite the server chose
    and (TLS <= 1.2) the server certificate are read directly. TLS 1.3 hides the certificate.
  * tls-crypt / tls-crypt-v2 encrypt the control channel: TLS parameters are not observable and are reported as such.
  * The data-channel cipher / HMAC / compression are inside TLS in every mode. A capture can never show them.
  * Detection is by structure, not port: an unprotected hard reset is matched exactly (length, zero ack count, zero packet
    id). Wrapped resets (tls-auth, tls-crypt) have no fixed bytes, so they are accepted only once the server answers with
    a hard-reset reply, or when the flow uses UDP/1194. A wrapped client that is never answered, on another port, is not found.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import VpnTunnel
from .tls import TlsView, classify_suite, parse_stream, read_certificate

OP_SOFT_RESET, OP_CONTROL, OP_ACK, OP_DATA_V1, OP_RESET_C2, OP_RESET_S2, OP_DATA_V2, OP_RESET_C3, OP_WKC = 3, 4, 5, 6, 7, 8, 9, 10, 11
DEFAULT_PORT = 1194
_HMAC_LENS = (20, 32, 64)  # tls-auth digests: SHA-1 (default), SHA-256, SHA-512
_MAX_SESSIONS = 200
_MAX_PKTS_PER_STREAM = 256
_MAX_EVENTS = 400
_WRAP_LABEL = {"none": "none", "tls-auth": "tls-auth", "tls-crypt": "tls-crypt", "tls-crypt-v2": "tls-crypt-v2"}


def classify_client_reset(data: bytes) -> tuple[str, int | None] | None:
    """(control-channel protection, tls-auth digest length) of a client hard reset, or None if it is not one."""
    op, n = data[0] >> 3, len(data)
    if data[0] & 7 != 0:
        return None
    if op == OP_RESET_C3:
        return ("tls-crypt-v2", None) if n >= 1 + 8 + 8 + 32 + 5 + 16 else None
    if op != OP_RESET_C2:
        return None
    if n == 14 and data[9] == 0 and data[10:14] == b"\x00\x00\x00\x00":
        return "none", None
    # tls-crypt: packet id (starts at 1) and a plausible epoch time sit right after the session id, where tls-auth has HMAC bytes
    if n == 54 and 0 < int.from_bytes(data[9:13], "big") < 4096 and 1_000_000_000 < int.from_bytes(data[13:17], "big") < 4_300_000_000:
        return "tls-crypt", None
    for h in _HMAC_LENS:
        if n == 22 + h and data[17 + h] == 0 and data[18 + h:22 + h] == b"\x00\x00\x00\x00":
            return "tls-auth", h
    return None


@dataclass
class _Stream:
    pkts: dict[int, bytes] = field(default_factory=dict)  # packet id -> TLS bytes
    seen: int = 0
    retransmits: int = 0

    def add(self, pid: int, payload: bytes) -> bool:
        """Returns True if this packet id was seen before (a retransmission)."""
        self.seen += 1
        if pid in self.pkts:
            self.retransmits += 1
            return True
        if len(self.pkts) < _MAX_PKTS_PER_STREAM:
            self.pkts[pid] = payload
        return False

    def assemble(self) -> tuple[bytes, dict[int, int]]:
        """Contiguous TLS bytes from packet id 1 (id 0 is the reset), and each packet id's offset in them."""
        out, offs, i = bytearray(), {}, 1
        while i in self.pkts:
            offs[i] = len(out)
            out += self.pkts[i]
            i += 1
        return bytes(out), offs


@dataclass
class OvpnSession:
    client: tuple[str, int]
    server: tuple[str, int]
    client_sid: bytes
    wrap: str
    hmac_len: int | None
    first_ts: float
    first_frame: int
    confirmed: bool
    server_sid: bytes | None = None
    last_ts: float = 0.0
    client_resets: int = 0
    server_resets: int = 0
    streams: dict[tuple[str, int], _Stream] = field(default_factory=dict)
    ctrl_events: list[dict[str, Any]] = field(default_factory=list)
    data_pkts: dict[str, int] = field(default_factory=lambda: {"c2s": 0, "s2c": 0})
    data_bytes: dict[str, int] = field(default_factory=lambda: {"c2s": 0, "s2c": 0})
    data_first_ts: float | None = None
    data_first_frame: int = 0
    soft_resets: int = 0
    key_ids: list[int] = field(default_factory=list)
    key_first_ts: dict[int, float] = field(default_factory=dict)
    acks_only: int = 0
    frames: list[int] = field(default_factory=list)

    def stream(self, direction: str, key_id: int) -> _Stream:
        return self.streams.setdefault((direction, key_id), _Stream())


class OpenVpnTracker:
    def __init__(self) -> None:
        self.by_flow: dict[frozenset, list[OvpnSession]] = {}
        self.count = 0

    # ------------------------------------------------------------------ packet intake
    def observe(self, ts: float, idx: int, src: str, dst: str, sport: int, dport: int, data: bytes) -> str | None:
        """Feed one UDP datagram. Returns "init"/"resp"/"data" when it belongs to an OpenVPN session, else None."""
        if len(data) < 2:
            return None
        flow = frozenset(((src, sport), (dst, dport)))
        sessions = self.by_flow.get(flow)
        op = data[0] >> 3
        if sessions is None and op not in (OP_RESET_C2, OP_RESET_C3):
            return None
        if op in (OP_RESET_C2, OP_RESET_C3) and len(data) >= 14:
            kind = classify_client_reset(data)
            if kind is not None:
                sid = data[1:9]
                cur = next((s for s in (sessions or []) if s.client_sid == sid and s.client == (src, sport)), None)
                if cur is None:
                    if self.count >= _MAX_SESSIONS:
                        return None
                    cur = OvpnSession((src, sport), (dst, dport), sid, kind[0], kind[1], ts, idx,
                                      confirmed=kind[0] == "none" or DEFAULT_PORT in (sport, dport))
                    self.by_flow.setdefault(flow, []).append(cur)
                    self.count += 1
                cur.client_resets += 1
                self._touch(cur, ts, idx)
                self._event(cur, ts, idx, "I->R", "Hard reset (client)" + (" · retransmission" if cur.client_resets > 1 else ""),
                            len(data), cur.wrap in ("tls-crypt", "tls-crypt-v2"), retransmit=cur.client_resets > 1)
                return "init"
        if not sessions:
            return None
        s = sessions[-1]
        c2s = (src, sport) == s.client
        direction = "c2s" if c2s else "s2c"
        kid = data[0] & 7
        if op in (OP_DATA_V2, OP_DATA_V1):
            if s.client_resets and (s.server_sid is not None or s.confirmed):
                s.data_pkts[direction] += 1
                s.data_bytes[direction] += len(data)
                if s.data_first_ts is None:
                    s.data_first_ts, s.data_first_frame = ts, idx
                self._note_key(s, kid, ts)
                self._touch(s, ts, idx)
                return "data"
            return None
        if op not in (OP_SOFT_RESET, OP_CONTROL, OP_ACK, OP_RESET_S2, OP_WKC) or len(data) < 10:
            return None
        sid = data[1:9]
        if c2s:
            if sid != s.client_sid:
                return None
        elif op == OP_RESET_S2:
            if s.server_sid is None:
                if not self._plausible_server_reset(s, data):
                    return None
                s.server_sid = sid
                s.confirmed = True
            elif sid != s.server_sid:
                return None
        elif s.server_sid is None or sid != s.server_sid:
            return None
        self._touch(s, ts, idx)
        self._control(s, ts, idx, direction, op, kid, data)
        return "resp" if op == OP_RESET_S2 else "data"

    @staticmethod
    def _plausible_server_reset(s: OvpnSession, data: bytes) -> bool:
        n = len(data)
        if s.wrap == "none":
            return n == 26 and data[9] == 1 and data[14:22] == s.client_sid
        if s.wrap == "tls-auth":
            return s.hmac_len is not None and n == 34 + s.hmac_len
        return 66 <= n <= 200  # tls-crypt is exactly 66; tls-crypt-v2 servers send a few extra bytes (72 seen with OpenVPN 2.6)

    def _touch(self, s: OvpnSession, ts: float, idx: int) -> None:
        s.last_ts = ts
        if len(s.frames) < 6:
            s.frames.append(idx)

    @staticmethod
    def _note_key(s: OvpnSession, kid: int, ts: float) -> None:
        if kid not in s.key_first_ts:
            s.key_first_ts[kid] = ts
            s.key_ids.append(kid)

    @staticmethod
    def _event(s: OvpnSession, ts: float, idx: int, direction: str, label: str, size: int, encrypted: bool,
               retransmit: bool = False, **extra: Any) -> None:
        if len(s.ctrl_events) < _MAX_EVENTS:
            s.ctrl_events.append({"ts": ts, "frame": idx, "direction": direction, "label": label, "size": size,
                                  "encrypted": encrypted, "retransmit": retransmit, "notes": [], **extra})

    def _control(self, s: OvpnSession, ts: float, idx: int, direction: str, op: int, kid: int, data: bytes) -> None:
        crypt = s.wrap in ("tls-crypt", "tls-crypt-v2")
        dirlab = "I->R" if direction == "c2s" else "R->I"
        if op == OP_RESET_S2:
            s.server_resets += 1
            self._note_key(s, kid, ts)
            self._event(s, ts, idx, dirlab, "Hard reset (server)", len(data), crypt, retransmit=s.server_resets > 1)
            return
        if op == OP_SOFT_RESET:
            s.soft_resets += 1
            self._note_key(s, kid, ts)
            self._event(s, ts, idx, dirlab, f"Soft reset (key renegotiation, key id {kid})", len(data), crypt)
            return
        if op == OP_ACK:
            s.acks_only += 1
            self._note_key(s, kid, ts)
            return
        self._note_key(s, kid, ts)
        if crypt or op == OP_WKC:
            self._event(s, ts, idx, dirlab, "Control (encrypted by tls-crypt)", len(data), True, key_id=kid)
            return
        off = 9 + (s.hmac_len + 8 if s.wrap == "tls-auth" and s.hmac_len else 0)
        try:
            ackn = data[off]
            off += 1 + 4 * ackn + (8 if ackn else 0)
            pid = int.from_bytes(data[off:off + 4], "big")
            payload = data[off + 4:]
        except IndexError:
            return
        if len(data) < off + 4:
            return
        retx = s.stream(direction, kid).add(pid, payload)
        self._event(s, ts, idx, dirlab, "Control", len(data), False, retransmit=retx, key_id=kid, _pid=pid, _plen=len(payload), _dir=direction)

    # ------------------------------------------------------------------ results
    def tunnels(self) -> list[VpnTunnel]:
        """One tunnel per established/answered session; repeated unanswered attempts from one client to one server are one tunnel.

        A client whose server never answers retries on a new socket (new source port, new session id) every few seconds;
        listing each attempt would bury the single fact "this client cannot reach that server".
        """
        out: list[VpnTunnel] = []
        failed: dict[tuple[str, tuple[str, int]], VpnTunnel] = {}
        for sessions in self.by_flow.values():
            for s in sessions:
                if not s.confirmed:
                    continue
                t = build_tunnel(s, len(out))
                if s.server_sid is None:
                    key = (s.client[0], s.server)
                    prev = failed.get(key)
                    if prev is not None:
                        _merge_attempt(prev, t)
                        continue
                    failed[key] = t
                    t.facts["attempts"] = 1
                out.append(t)
        return out

    def confirmed_flows(self) -> set[frozenset]:
        return {f for f, ss in self.by_flow.items() if any(s.confirmed for s in ss)}


def _ep(e: tuple[str, int]) -> str:
    return f"{e[0]}:{e[1]}" if ":" not in e[0] else f"[{e[0]}]:{e[1]}"


def build_tunnel(s: OvpnSession, n: int) -> VpnTunnel:
    crypt = s.wrap in ("tls-crypt", "tls-crypt-v2")
    c_view = s_view = None
    c_off: dict[int, int] = {}
    s_off: dict[int, int] = {}
    if not crypt:
        cs, ss = s.streams.get(("c2s", 0)), s.streams.get(("s2c", 0))
        if cs:
            data, c_off = cs.assemble()
            c_view = parse_stream(data, server=False)
        if ss:
            data, s_off = ss.assemble()
            s_view = parse_stream(data, server=True)
        _label_events(s, c_view, s_view, c_off, s_off)
    view = TlsView()
    if c_view:
        view.client_versions, view.client_min = c_view.client_versions, c_view.client_min
        view.client_suites, view.client_groups = c_view.client_suites, c_view.client_groups
    if s_view:
        for f in ("server_version", "server_suite", "server_group", "kx_curve", "kx_dh_bits", "cert_der", "saw_ccs", "saw_encrypted"):
            setattr(view, f, getattr(s_view, f))
    alerts = (c_view.alerts if c_view else []) + (s_view.alerts if s_view else [])
    established = s.data_pkts["c2s"] > 0 and s.data_pkts["s2c"] > 0
    answered = s.server_sid is not None
    fatal = [a for a in alerts if a["level"] == "fatal"]
    if established:
        status, failure = "established", None
    elif not answered:
        status, failure = "failed", f"no reply to {s.client_resets} client hard reset{'s' if s.client_resets != 1 else ''}"
    elif fatal:
        status, failure = "failed", f"TLS alert {fatal[0]['description']} (from {fatal[0]['from']})"
    else:
        status, failure = "incomplete", "server replied but no data-channel traffic followed"
    suite = classify_suite(view.server_suite) if view.server_suite else None
    cert = None
    if view.cert_der:
        cert = read_certificate(view.cert_der[0], s.first_ts)
        if cert:
            cert["chain_length"] = len(view.cert_der)
    if crypt:
        tls_vis = "hidden"
    elif view.server_version is None:
        tls_vis = "none"
    elif view.server_version == "TLSv1.3":
        tls_vis = "hello_only"
    else:
        tls_vis = "full"
    offered = {
        "versions": view.client_versions, "min_version": view.client_min, "suite_count": len(view.client_suites),
        "weak_suites": sorted({x for x in view.client_suites if classify_suite(x).issues and set(classify_suite(x).issues) & {"null_cipher", "export", "anon", "rc4", "des", "3des", "md5"}})[:12],
        "groups": view.client_groups[:12],
    } if view.client_min else None
    negotiated = None
    if suite:
        negotiated = {"version": view.server_version, "suite": suite.name, "kex": suite.kex, "pfs": suite.pfs, "cipher": suite.enc,
                      "mode": suite.mode, "mac": suite.mac, "aead": suite.aead, "issues": list(suite.issues),
                      "group": view.server_group or view.kx_curve, "dh_bits": view.kx_dh_bits}
    renegs = max(s.soft_resets, len(s.key_ids) - 1)
    facts: dict[str, Any] = {
        "protocol": "OpenVPN", "control_protection": s.wrap, "tls_visibility": tls_vis,
        "tls_offered": offered, "tls_negotiated": negotiated, "alerts": alerts, "certificate": cert,
        "client_resets": s.client_resets, "server_answered": answered,
        "data_packets": dict(s.data_pkts), "data_bytes": dict(s.data_bytes), "renegotiations": renegs,
        "key_ids": list(s.key_ids), "port": s.server[1], "duration_s": round(s.last_ts - s.first_ts, 2),
        "frames": list(s.frames), "client_session_id": s.client_sid.hex(),
        "data_channel": "not observable: cipher, HMAC and compression are negotiated inside TLS",
    }
    if renegs == 0 and s.data_first_ts is not None:
        facts["single_key_s"] = round(s.last_ts - s.data_first_ts, 1)  # how long the one data-channel key has been in use
    if tls_vis == "hidden":
        label = f"{s.wrap} control channel · TLS hidden"
    elif negotiated:
        label = f"{view.server_version} · {suite.name if suite else '?'} · control: {_WRAP_LABEL[s.wrap]}"
    elif answered:
        label = f"TLS not seen · control: {_WRAP_LABEL[s.wrap]}"
    else:
        label = "no server reply"
    timeline = _timeline(s)
    t = VpnTunnel(id=f"ovpn-{n + 1}-{s.client_sid.hex()[:8]}", protocol="OpenVPN", source="capture", initiator=_ep(s.client),
                  responder=_ep(s.server), status=status, summary=label, first_ts=s.first_ts, last_ts=s.last_ts, failure=failure,
                  facts=facts, timeline=timeline, session_ref=s.client_sid.hex())
    return t


def _merge_attempt(into: VpnTunnel, t: VpnTunnel) -> None:
    f, g = into.facts, t.facts
    f["attempts"] += 1
    f["client_resets"] += g["client_resets"]
    f["frames"] = (f["frames"] + g["frames"])[:6]
    into.first_ts, into.last_ts = min(into.first_ts, t.first_ts), max(into.last_ts, t.last_ts)
    f["duration_s"] = round(into.last_ts - into.first_ts, 2)
    into.failure = f"no reply to {f['client_resets']} client hard resets over {f['attempts']} connection attempts"
    into.timeline = sorted(into.timeline + t.timeline, key=lambda e: e["ts"])[:_MAX_EVENTS]


def _label_events(s: OvpnSession, c_view: TlsView | None, s_view: TlsView | None, c_off: dict[int, int], s_off: dict[int, int]) -> None:
    for e in s.ctrl_events:
        if "_pid" not in e:
            continue
        view, offs = (c_view, c_off) if e["_dir"] == "c2s" else (s_view, s_off)
        pid, plen = e["_pid"], e["_plen"]
        if view is not None and pid in offs:
            lo, hi = offs[pid], offs[pid] + plen
            labs = [lab for off, lab in view.marks if lo <= off < hi]
            # a record header is followed by its handshake messages: show the messages, not both
            msgs = [x for x in labs if x not in ("Handshake", "Handshake (encrypted)")]
            e["label"] = "Control · " + (", ".join(dict.fromkeys(msgs)) if msgs else "TLS continuation" if plen else "empty")
            e["encrypted"] = any("encrypted" in x.lower() for x in labs) and not any(m in HS_VISIBLE for m in msgs)
        elif plen == 0:
            e["label"] = "Control · empty"


HS_VISIBLE = {"ClientHello", "ServerHello", "Certificate", "ServerKeyExchange", "ServerHelloDone", "ClientKeyExchange", "CertificateRequest"}


def _timeline(s: OvpnSession) -> list[dict[str, Any]]:
    ev = [{k: v for k, v in e.items() if not k.startswith("_")} for e in s.ctrl_events]
    if s.data_first_ts is not None:
        ev.append({"ts": s.data_first_ts, "frame": s.data_first_frame, "direction": "I->R", "label": f"Data channel opens ({s.data_pkts['c2s']} packets out, "
                   f"{s.data_pkts['s2c']} in over the capture)", "size": 0, "encrypted": True, "retransmit": False, "notes": []})
    ev.sort(key=lambda e: e["ts"])
    return ev[:_MAX_EVENTS]
