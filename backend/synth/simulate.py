"""Simulate one IPsec tunnel's on-the-wire life from a TunnelSpec and emit packets + ground truth."""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from random import Random

from ipsec_analyzer.parser import constants as C

from . import builder as B
from .builder import SuiteSpec

MAC_I, MAC_R = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"


@dataclass
class TunnelSpec:
    label: str  # benign | weak-config | downgrade | behavioral
    family: str
    initiator: str
    responder: str
    version: int = 2
    aggressive: bool = False
    natt: bool = False
    offered_ike: list[SuiteSpec] = field(default_factory=list)
    chosen_ike: SuiteSpec | None = None  # None -> responder rejects (NO_PROPOSAL_CHOSEN)
    offered_esp: list[SuiteSpec] = field(default_factory=list)
    chosen_esp: SuiteSpec | None = None
    auth: str = "PSK"  # PSK | RSA
    rtt_ms: float = 25.0
    proc_ms: float = 15.0
    traffic_pkts: int = 120
    traffic_rate_hz: float = 20.0
    child_rekeys: int = 0
    rekey_uses_ke: bool = True
    dpd_interval_s: float = 0.0
    dpd_count: int = 0
    retransmits: int = 0
    cookie: bool = False
    frag_auth: bool = False
    replay_ratio: float = 0.0
    gap_ratio: float = 0.0
    extra_vid_bytes: int = 0  # oversized handshake padding (fuzzing / scanner behaviour)
    half_open_attempts: int = 0  # >0: scan-like, unanswered IKE_SA_INIT attempts
    prior_reject: list[SuiteSpec] | None = None  # earlier attempt offered this and was rejected
    v1_life_s: int = 28800
    terminate: bool = True


@dataclass
class TunnelTruth:
    ispi: str
    label: str
    family: str
    ike_version: int
    negotiated_ike: str | None
    negotiated_esp: str | None
    expect_rules: list[str]
    assessable_rules: list[str]
    natt: bool = False
    aux_ispis: list[str] = field(default_factory=list)  # related attempts (rejected retries, scan probes)
    ike_datagrams: int = 0  # IKE datagrams written to the capture for this scenario (incl. retransmits, fragments)
    esp_datagrams: int = 0
    auth: str = "PSK"


def _jit(rng: Random, ms: float, rel: float = 0.15) -> float:
    return max(ms * (1 + rng.gauss(0, rel)), 0.05) / 1000.0


class _Sim:
    def __init__(self, spec: TunnelSpec, rng: Random, t0: float, ident0: int) -> None:
        self.s, self.rng, self.t, self.ident = spec, rng, t0, ident0
        self.pkts: list[tuple[float, bytes]] = []
        self.msgid = 0
        self.flow_stats: list[tuple[int, int, int]] = []  # (packets on wire, replays, gaps)
        self.aux_ispis: list[str] = []
        self.n_ike = 0
        self.n_esp = 0

    # ---- packet emitters
    def _ip(self, frame: bytes, from_i: bool) -> bytes:
        self.ident += 1
        return B.ethernet(frame, MAC_I if from_i else MAC_R, MAC_R if from_i else MAC_I)

    def ike(self, ts: float, from_i: bool, data: bytes, force500: bool = False) -> None:
        s = self.s
        self.n_ike += 1
        src, dst = (s.initiator, s.responder) if from_i else (s.responder, s.initiator)
        if s.natt and not force500:
            data = b"\x00\x00\x00\x00" + data
            sport = dport = 4500
        else:
            sport = dport = 500
        self.pkts.append((ts, self._ip(B.ipv4_udp_frame(src, dst, sport, dport, data, self.ident), from_i)))

    def esp(self, ts: float, from_i: bool, spi: int, seq: int, length: int) -> None:
        s = self.s
        self.n_esp += 1
        src, dst = (s.initiator, s.responder) if from_i else (s.responder, s.initiator)
        pk = B.esp_packet(spi, seq, length, self.rng)
        if s.natt:
            frame = B.ipv4_udp_frame(src, dst, 4500, 4500, pk, self.ident)
        else:
            frame = B.ipv4_esp_frame(src, dst, pk, self.ident)
        self.pkts.append((ts, self._ip(frame, from_i)))

    # ---- ESP flow
    def flow(self, start: float, n: int, spi: int, from_i: bool) -> float:
        s, rng = self.s, self.rng
        ts, seq, sent, replays, gaps = start, 0, [], 0, 0
        for _ in range(n):
            ts += rng.expovariate(s.traffic_rate_hz)
            seq += 1
            size = rng.choice((104, 120, 136, 152)) if rng.random() < 0.5 else int(min(max(rng.gauss(900, 450), 96), 1476))
            if rng.random() < s.gap_ratio:
                gaps += 1
                continue  # packet missing from the capture -> sequence gap
            self.esp(ts, from_i, spi, seq, size)
            sent.append(seq)
            if rng.random() < s.replay_ratio and len(sent) > 4:
                self.esp(ts + 0.0004, from_i, spi, rng.choice(sent[:-2]), size)  # replayed / duplicated sequence number
                replays += 1
        self.flow_stats.append((len(sent) + replays, replays, gaps))
        return ts


def _ike_id(kind: int, data: bytes) -> bytes:
    return struct.pack("!BBBB", kind, 0, 0, 0) + data


def simulate(spec: TunnelSpec, rng: Random, t0: float, ident0: int = 1000) -> tuple[list[tuple[float, bytes]], list[str], TunnelTruth, float]:
    """Returns (packets, wireshark key rows, truth, end_time)."""
    sim = _Sim(spec, rng, t0, ident0)
    keyrows: list[str] = []
    if spec.version == 2:
        ispi = _v2(sim, keyrows)
    else:
        ispi = _v1(sim)
    truth = _truth(spec, ispi, sim)
    end = max((p[0] for p in sim.pkts), default=t0)
    return sim.pkts, keyrows, truth, end


# ============================================================================= IKEv2
def _v2(sim: _Sim, keyrows: list[str]) -> bytes:
    s, rng = sim.s, sim.rng
    if s.half_open_attempts:
        return _half_open(sim)
    t = sim.t
    if s.prior_reject:
        t = _rejected_attempt(sim, t)
        t += rng.uniform(0.4, 2.5)

    ispi, rspi = rng.randbytes(8), rng.randbytes(8)
    rtt = _jit(rng, s.rtt_ms)
    proc = _jit(rng, s.proc_ms * (1.0 + 0.4 * (len(s.offered_ike) > 1)))
    ni, nr = rng.randbytes(32), rng.randbytes(32)
    natd = [(41, B.notify_body(16388, rng.randbytes(20))), (41, B.notify_body(16389, rng.randbytes(20)))]

    def init_req(cookie: bytes | None = None) -> bytes:
        items = ([(41, B.notify_body(16390, cookie))] if cookie else []) + [
            (33, B.v2_sa_ike(s.offered_ike)), (34, B.ke_body(s.offered_ike[0].dh or "MODP_2048", rng)), (40, ni),
            *natd, (41, B.notify_body(16430))]
        if s.extra_vid_bytes:
            items.append((43, rng.randbytes(s.extra_vid_bytes)))
        return B.ike_header(ispi, b"\x00" * 8, items[0][0], 0x20, 34, 0x08, 0, B.chain(items))

    if s.chosen_ike is None:  # (not used for retry flows: prior_reject handles the rejected attempt)
        raise ValueError("chosen_ike required")
    ch = s.chosen_ike

    # IKE_SA_INIT (with optional cookie challenge and retransmissions of the unanswered request)
    req = init_req()
    for k in range(s.retransmits):
        sim.ike(t, True, req, force500=True)
        t += 0.5 * (2 ** k) * rng.uniform(0.9, 1.1)
    sim.ike(t, True, req, force500=True)
    if s.cookie:
        cookie = rng.randbytes(20)
        t += rtt + 0.002
        sim.ike(t, False, B.ike_header(ispi, b"\x00" * 8, 41, 0x20, 34, 0x20, 0, B.chain([(41, B.notify_body(16390, cookie))])), True)
        t += 0.002
        req = init_req(cookie)
        sim.ike(t, True, req, force500=True)
    t += rtt + proc
    resp_items = [(33, B.v2_sa_ike([ch])), (34, B.ke_body(ch.dh or "MODP_2048", rng)), (40, nr), *natd]
    if s.extra_vid_bytes:
        resp_items.append((43, rng.randbytes(s.extra_vid_bytes // 2)))
    sim.ike(t, False, B.ike_header(ispi, rspi, resp_items[0][0], 0x20, 34, 0x20, 0, B.chain(resp_items)), True)

    keys = B.IkeKeys.generate(ispi, rspi, ch, rng)
    keyrows.append(keys.wireshark_row())

    # IKE_AUTH
    t += _jit(rng, s.proc_ms)
    spi_i, spi_r = rng.randbytes(4), rng.randbytes(4)
    auth_len = 256 if s.auth == "RSA" else 32
    auth_body = struct.pack("!B3x", 1 if s.auth == "RSA" else 2) + rng.randbytes(auth_len)
    cert = [(37, b"\x04" + rng.randbytes(rng.randint(900, 1300)))] if s.auth == "RSA" else []
    inner_i = B.chain([
        (35, _ike_id(2, b"vpn-initiator.example.net")), *cert, (39, auth_body),
        (33, B.v2_sa_esp(s.offered_esp, spi_i)), (44, B.ts_payload("10.1.0.0", "10.1.255.255")),
        (45, B.ts_payload("10.2.0.0", "10.2.255.255"))])
    first_i = 35
    _send_sk(sim, keys, exch=35, msg_id=1, from_i=True, is_resp=False, first=first_i, inner=inner_i, frag=s.frag_auth, t=t)
    t += rtt + _jit(rng, s.proc_ms * 1.5)
    inner_r = B.chain([
        (36, _ike_id(2, b"vpn-gateway.example.net")), (39, auth_body),
        (33, B.v2_sa_esp([s.chosen_esp], spi_r)), (44, B.ts_payload("10.1.0.0", "10.1.255.255")),
        (45, B.ts_payload("10.2.0.0", "10.2.255.255"))])
    _send_sk(sim, keys, exch=35, msg_id=1, from_i=False, is_resp=True, first=36, inner=inner_r, frag=s.frag_auth, t=t)
    t += rtt / 2

    # Traffic, DPD, rekeys
    msgid = 2
    t_ready = t
    spi_i_int, spi_r_int = struct.unpack("!I", spi_i)[0], struct.unpack("!I", spi_r)[0]
    n_seg = s.child_rekeys + 1
    per = max(s.traffic_pkts // n_seg, 4)
    seg_start = t
    for seg in range(n_seg):
        e1 = sim.flow(seg_start, per, spi_r_int, True)  # to responder uses responder's inbound SPI
        e2 = sim.flow(seg_start, per, spi_i_int, False)
        seg_end = max(e1, e2)
        if seg < s.child_rekeys:
            rt = seg_end + rng.uniform(0.05, 0.4) * (0.05 if s.family == "rekey_storm" else 1)
            new_i, new_r = rng.randbytes(4), rng.randbytes(4)
            esp_o = B.v2_sa_esp(s.offered_esp, new_i)
            items = [(41, B.notify_body(16393, spi=spi_r, proto=3)), (33, esp_o), (40, ni)]
            if s.rekey_uses_ke and s.chosen_esp.dh:
                items.append((34, B.ke_body(s.chosen_esp.dh, rng)))
            items += [(44, B.ts_payload("10.1.0.0", "10.1.255.255")), (45, B.ts_payload("10.2.0.0", "10.2.255.255"))]
            _send_sk(sim, keys, exch=36, msg_id=msgid, from_i=True, is_resp=False, first=items[0][0], inner=B.chain(items), t=rt)
            ritems = [(33, B.v2_sa_esp([s.chosen_esp], new_r)), (40, nr)]
            if s.rekey_uses_ke and s.chosen_esp.dh:
                ritems.append((34, B.ke_body(s.chosen_esp.dh, rng)))
            ritems += [(44, B.ts_payload("10.1.0.0", "10.1.255.255")), (45, B.ts_payload("10.2.0.0", "10.2.255.255"))]
            _send_sk(sim, keys, exch=36, msg_id=msgid, from_i=False, is_resp=True, first=ritems[0][0], inner=B.chain(ritems), t=rt + rtt + proc)
            msgid += 1
            spi_i_int, spi_r_int = struct.unpack("!I", new_i)[0], struct.unpack("!I", new_r)[0]
            seg_start = rt + rtt + proc + 0.01
        else:
            t = seg_end
    for k in range(s.dpd_count):
        dt = t_ready + (k + 1) * s.dpd_interval_s
        _send_sk(sim, keys, exch=37, msg_id=msgid, from_i=True, is_resp=False, first=0, inner=b"", t=dt)
        _send_sk(sim, keys, exch=37, msg_id=msgid, from_i=False, is_resp=True, first=0, inner=b"", t=dt + rtt)
        msgid += 1
    if s.terminate:
        t = max(p[0] for p in sim.pkts) + 0.05
        dele = B.chain([(42, struct.pack("!BBH", 1, 0, 0))])
        _send_sk(sim, keys, exch=37, msg_id=msgid, from_i=True, is_resp=False, first=42, inner=dele, t=t)
        _send_sk(sim, keys, exch=37, msg_id=msgid, from_i=False, is_resp=True, first=0, inner=b"", t=t + rtt)
    return ispi


def _send_sk(sim: _Sim, keys: B.IkeKeys, *, exch: int, msg_id: int, from_i: bool, is_resp: bool, first: int,
             inner: bytes, t: float, frag: bool = False) -> None:
    rng = sim.rng
    if frag and len(inner) > 900:
        parts = [inner[i:i + 900] for i in range(0, len(inner), 900)]
        for n, part in enumerate(parts, start=1):
            m = B.seal_sk_message(keys, rng, exch=exch, msg_id=msg_id, from_initiator=from_i, is_response=is_resp,
                                  inner_first=first if n == 1 else 0, inner=part, frag=(n, len(parts)))
            sim.ike(t + 0.0002 * n, from_i, m)
        return
    m = B.seal_sk_message(keys, rng, exch=exch, msg_id=msg_id, from_initiator=from_i, is_response=is_resp,
                          inner_first=first, inner=inner)
    sim.ike(t, from_i, m)


def _rejected_attempt(sim: _Sim, t: float) -> float:
    s, rng = sim.s, sim.rng
    ispi = rng.randbytes(8)
    items = [(33, B.v2_sa_ike(s.prior_reject or [])), (34, B.ke_body((s.prior_reject or [])[0].dh or "MODP_2048", rng)),
             (40, rng.randbytes(32))]
    sim.ike(t, True, B.ike_header(ispi, b"\x00" * 8, 33, 0x20, 34, 0x08, 0, B.chain(items)), True)
    rt = t + _jit(sim.rng, s.rtt_ms) + 0.003
    sim.ike(rt, False, B.ike_header(ispi, b"\x00" * 8, 41, 0x20, 34, 0x20, 0, B.chain([(41, B.notify_body(14))])), True)
    return rt


def _half_open(sim: _Sim) -> bytes:
    s, rng = sim.s, sim.rng
    t, first = sim.t, b""
    for _ in range(s.half_open_attempts):
        ispi = rng.randbytes(8)
        if first:
            sim.aux_ispis.append(ispi.hex())
        first = first or ispi
        items = [(33, B.v2_sa_ike(s.offered_ike)), (34, B.ke_body(s.offered_ike[0].dh or "MODP_2048", rng)), (40, rng.randbytes(32))]
        req = B.ike_header(ispi, b"\x00" * 8, 33, 0x20, 34, 0x08, 0, B.chain(items))
        for k in range(s.retransmits + 1):
            sim.ike(t, True, req, True)
            t += 0.5 * (2 ** k)
        t += rng.uniform(0.05, 0.6)
    return first


# ============================================================================= IKEv1
def _v1(sim: _Sim) -> bytes:
    s, rng = sim.s, sim.rng
    t = sim.t
    ispi, rspi = rng.randbytes(8), rng.randbytes(8)
    rtt, proc = _jit(rng, s.rtt_ms), _jit(rng, s.proc_ms)
    auth = "PSK"
    ch = s.chosen_ike
    vids = B.v1_vendor_ids(rng, dpd=True, natt=True, xauth=False, frag=False)
    if s.extra_vid_bytes:
        vids.append((13, rng.randbytes(s.extra_vid_bytes)))

    def send(ts: float, from_i: bool, m: bytes) -> None:
        sim.ike(ts, from_i, m, force500=True)

    idb = struct.pack("!BBH", 1, 0, 0) + bytes(int(x) for x in s.initiator.split("."))
    hashb = rng.randbytes(32)
    if s.aggressive:
        m1 = B.v1_message(ispi, b"\x00" * 8, 4, 0, 0, [(1, B.v1_sa_body(s.offered_ike, auth, s.v1_life_s)),
                          (4, B.ke_body(s.offered_ike[0].dh or "MODP_2048", rng, v1=True)), (10, rng.randbytes(20)), (5, idb), *vids])
        for k in range(s.retransmits):
            send(t, True, m1)
            t += 0.5 * (2 ** k)
        send(t, True, m1)
        t += rtt + proc
        send(t, False, B.v1_message(ispi, rspi, 4, 0, 0, [(1, B.v1_sa_body([ch], auth, s.v1_life_s)),
                                    (4, B.ke_body(ch.dh or "MODP_2048", rng, v1=True)), (10, rng.randbytes(20)), (5, idb), (8, hashb), *vids]))
        t += rtt / 2 + proc
        send(t, True, B.v1_message(ispi, rspi, 4, 0, 0, [(8, hashb)]))
    else:
        m1 = B.v1_message(ispi, b"\x00" * 8, 2, 0, 0, [(1, B.v1_sa_body(s.offered_ike, auth, s.v1_life_s)), *vids])
        for k in range(s.retransmits):
            send(t, True, m1)
            t += 0.5 * (2 ** k)
        send(t, True, m1)
        t += rtt
        send(t, False, B.v1_message(ispi, rspi, 2, 0, 0, [(1, B.v1_sa_body([ch], auth, s.v1_life_s)), *vids]))
        t += rtt / 2
        ke = lambda: (4, B.ke_body(ch.dh or "MODP_2048", rng, v1=True))
        send(t, True, B.v1_message(ispi, rspi, 2, 0, 0, [ke(), (10, rng.randbytes(20))]))
        t += rtt + proc
        send(t, False, B.v1_message(ispi, rspi, 2, 0, 0, [ke(), (10, rng.randbytes(20))]))
        t += rtt / 2 + proc
        enc = lambda: ike_enc_blob(ispi, rspi, 2, 0, rng)
        send(t, True, enc())
        t += rtt
        send(t, False, ike_enc_blob(ispi, rspi, 2, 0, rng))
    # Quick Mode (encrypted; contents unobservable) + ESP
    t += rtt / 2 + 0.002
    qmid = rng.randrange(1, 2**32)
    for i, from_i in enumerate((True, False, True)):
        send(t + i * (rtt / 2 if i else 0), from_i, ike_enc_blob(ispi, rspi, 32, qmid, rng))
    t += rtt * 1.5 + 0.01
    spi_i, spi_r = rng.getrandbits(32) | 0x100, rng.getrandbits(32) | 0x100
    e1 = sim.flow(t, s.traffic_pkts // 2, spi_r, True)
    e2 = sim.flow(t, s.traffic_pkts // 2, spi_i, False)
    end = max(e1, e2)
    for k in range(s.dpd_count):
        dt = t + (k + 1) * s.dpd_interval_s
        send(dt, True, ike_enc_blob(ispi, rspi, 5, rng.randrange(1, 2**32), rng))
        send(dt + rtt, False, ike_enc_blob(ispi, rspi, 5, rng.randrange(1, 2**32), rng))
    return ispi


def ike_enc_blob(ispi: bytes, rspi: bytes, exch: int, msg_id: int, rng: Random) -> bytes:
    """IKEv1 message with the Encryption flag set: opaque ciphertext (phase-1 keys are never derivable from a capture)."""
    body = rng.randbytes(rng.choice((48, 64, 80, 96, 112, 176)))
    return B.ike_header(ispi, rspi, 8, 0x10, exch, 0x01, msg_id, body)


# ============================================================================= truth
def _truth(spec: TunnelSpec, ispi: bytes, sim: _Sim) -> TunnelTruth:
    from ipsec_analyzer.rules import load_policy

    from .expected import expected_rules  # local import to avoid a cycle at import time

    exp, assess = expected_rules(spec, load_policy(), sim.flow_stats)
    return TunnelTruth(
        ispi=ispi.hex(), label=spec.label, family=spec.family, ike_version=spec.version,
        negotiated_ike=spec.chosen_ike.label() if spec.chosen_ike and not spec.half_open_attempts else None,
        negotiated_esp=spec.chosen_esp.label() if spec.chosen_esp and not spec.half_open_attempts else None,
        expect_rules=exp, assessable_rules=assess, natt=spec.natt, aux_ispis=sim.aux_ispis,
        ike_datagrams=sim.n_ike, esp_datagrams=sim.n_esp, auth=spec.auth if spec.version == 2 else "PSK",
    )
