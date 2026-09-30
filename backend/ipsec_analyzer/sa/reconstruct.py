"""Rebuild per-tunnel Security Association state from parsed IKE/ESP/AH records.

One `Tunnel` per IKE SA (keyed by the initiator SPI). Handshake retries that reuse the same
initiator SPI (cookie challenge, INVALID_KE_PAYLOAD) stay inside one tunnel; a fresh attempt
gets a new SPI, is a separate tunnel, and is linked to earlier attempts between the same two
endpoints via `prior_attempts` (this is what the downgrade rule reads).
"""
from __future__ import annotations

import itertools
from collections import defaultdict
from dataclasses import dataclass, field

from ..parser import constants as C
from ..parser.models import CaptureStats, EspPacket, IkeMessage, ParsedCapture, Proposal
from .models import AttemptSummary, ChildSa, EspFlow, Suite, TimelineEvent, Tunnel

_MAX_COMBOS = 64
_PRIOR_WINDOW_S = 300.0


@dataclass
class Reconstruction:
    tunnels: list[Tunnel]
    orphan_esp: list[EspFlow] = field(default_factory=list)
    stats: CaptureStats | None = None


# ----------------------------------------------------------------------------- suites
def _v2_suites(proposals: list[Proposal], proto: int = C.PROTO_IKE) -> list[Suite]:
    out: list[Suite] = []
    for p in proposals:
        if p.protocol != proto:
            continue
        encs = p.of_type(C.T_ENCR) or [None]
        integs = p.of_type(C.T_INTEG) or [None]
        prfs = p.of_type(C.T_PRF) or [None]
        dhs = p.of_type(C.T_DH) or [None]
        for e, i, pr, d in itertools.islice(itertools.product(encs, integs, prfs, dhs), _MAX_COMBOS):
            aead = e is not None and e.id in C.AEAD_ENCR
            integ_name = None if (i is None or i.id == 0 or aead) else C.INTEG.get(i.id, f"INTEG_{i.id}")
            out.append(Suite(
                encr=C.ENCR.get(e.id, f"ENCR_{e.id}") if e else None,
                encr_bits=e.key_len if e else None,
                integ=integ_name,
                prf=C.PRF.get(pr.id, f"PRF_{pr.id}") if pr else None,
                dh=(C.DH_GROUP.get(d.id, f"GROUP_{d.id}") if d and d.id else None),
            ))
    return out


def _v1_suites(msg: IkeMessage) -> list[Suite]:
    out: list[Suite] = []
    for p in msg.clear.v1_proposals:
        for t in p.transforms:
            a = t.attrs
            life = a.get(C.A1_LIFE_DUR) if a.get(C.A1_LIFE_TYPE, 1) == 1 else None
            out.append(Suite(
                encr=C.V1_ENC.get(a.get(C.A1_ENC), f"ENC_{a.get(C.A1_ENC)}") if C.A1_ENC in a else None,
                encr_bits=a.get(C.A1_KEYLEN),
                integ=C.V1_HASH.get(a.get(C.A1_HASH), f"HASH_{a.get(C.A1_HASH)}") if C.A1_HASH in a else None,
                dh=C.DH_GROUP.get(a.get(C.A1_GROUP), f"GROUP_{a.get(C.A1_GROUP)}") if C.A1_GROUP in a else None,
                auth=C.V1_AUTH.get(a.get(C.A1_AUTH), f"AUTH_{a.get(C.A1_AUTH)}") if C.A1_AUTH in a else None,
                lifetime_s=life,
            ))
    return out


def _child_suite(p: Proposal) -> tuple[Suite, bool]:
    """Suite for an ESP/AH child proposal, and whether it carries a DH (PFS) transform."""
    (s,) = _v2_suites([p], p.protocol)[:1] or [Suite()]
    return s, s.dh is not None


# ----------------------------------------------------------------------------- helpers
def _exch_name(m: IkeMessage) -> str:
    return (C.V2_EXCHANGE if m.version == 2 else C.V1_EXCHANGE).get(m.exch, f"exch-{m.exch}")


def _payload_label(m: IkeMessage) -> str:
    names = C.V2_PAYLOAD if m.version == 2 else C.V1_PAYLOAD
    ps = m.payloads
    types = [t for t in ps.types if t not in (46, 53)] if m.version == 2 else ps.types
    lab = ", ".join(names.get(t, str(t)) for t in types)
    if m.encrypted_v1:
        return "encrypted (IKEv1 phase-1 keys unavailable)"
    if m.enc_body is not None and m.decrypted is None:
        return (lab + " + " if lab else "") + "SK[encrypted]"
    return lab


def _notify_names(m: IkeMessage) -> list[tuple[int, str]]:
    table = C.NOTIFY_V2 if m.version == 2 else C.NOTIFY_V1
    return [(n.type, table.get(n.type, f"NOTIFY_{n.type}")) for n in m.payloads.notifies]


# ----------------------------------------------------------------------------- main
def reconstruct(cap: ParsedCapture) -> Reconstruction:
    groups: dict[bytes, list[IkeMessage]] = defaultdict(list)
    for m in cap.ike:
        if m.extra_fragment:
            continue  # folded into fragment #1
        groups[m.ispi].append(m)

    tunnels = [t for t in (_build_tunnel(msgs, cap) for msgs in groups.values()) if t is not None]
    tunnels.sort(key=lambda t: t.first_ts)

    for t in tunnels:
        t.prior_attempts = [
            AttemptSummary(p.ispi, p.first_ts, p.status, p.failure, p.offered, p.chosen)
            for p in tunnels
            if p is not t and p.initiator == t.initiator and p.responder == t.responder
            and 0 < t.first_ts - p.first_ts <= _PRIOR_WINDOW_S
        ]

    orphans = _attach_esp(tunnels, cap.esp)
    return Reconstruction(tunnels, orphans, cap.stats)


def _build_tunnel(msgs: list[IkeMessage], cap: ParsedCapture) -> Tunnel | None:
    if not msgs:
        return None
    msgs.sort(key=lambda m: (m.ts, m.frame))
    first = msgs[0]
    v = first.version
    if v == 2:
        init_msgs = [m for m in msgs if m.flags & C.V2_FLAG_INITIATOR]
        seed = init_msgs[0] if init_msgs else first
        initiator, responder = (seed.src, seed.dst) if init_msgs else (seed.dst, seed.src)
        mode = "IKEv2"
    else:
        seed = first
        initiator, responder = seed.src, seed.dst
        mode = "Aggressive Mode" if any(m.exch == C.V1_AGGRESSIVE for m in msgs) else "Main Mode"
        if not any(m.exch in (C.V1_MAIN, C.V1_AGGRESSIVE) for m in msgs):
            mode = "IKEv1 (phase 1 not captured)"
    rspi = next((m.rspi for m in msgs if m.rspi != b"\x00" * 8), b"\x00" * 8)

    t = Tunnel(
        id=f"ikev{v}-{first.ispi.hex()}", ike_version=v, exchange_mode=mode, initiator=initiator,
        responder=responder, ispi=first.ispi.hex(), rspi=rspi.hex(), natt=False,
        first_ts=msgs[0].ts, last_ts=msgs[-1].ts, status="incomplete",
    )
    t.msg_count = len(msgs)
    t.decrypted = any(m.decrypted is not None and not m.extra_fragment for m in msgs)
    t.natt = any(m.natt_marker or C.NATT_PORT in (m.sport, m.dport) for m in msgs)

    def from_initiator(m: IkeMessage) -> bool:
        return m.src == initiator if v == 1 else bool(m.flags & C.V2_FLAG_INITIATOR)

    seen: dict[tuple, int] = {}
    streak = 0
    for m in msgs:
        key = (m.msg_id, m.exch, m.src, m.digest)
        retrans = key in seen
        seen[key] = seen.get(key, 0) + 1
        if retrans:
            t.retransmits += 1
            streak += 1
            t.max_retransmit_streak = max(t.max_retransmit_streak, streak)
        else:
            streak = 0
        notes = [n for _c, n in _notify_names(m)]
        if m.frag_num is not None:
            t.fragments += 1
            notes.append(f"fragment {m.frag_num}/{m.frag_total}")
        if m.decrypt_error:
            notes.append(f"decrypt: {m.decrypt_error}")
        t.timeline.append(TimelineEvent(
            ts=m.ts, frame=m.frame, direction="I->R" if from_initiator(m) else "R->I",
            label=f"{_exch_name(m)} {'response' if m.is_response else 'request'}"
            if v == 2 else f"{_exch_name(m)}",
            size=m.length, encrypted=(m.enc_body is not None and m.decrypted is None) or m.encrypted_v1,
            retransmit=retrans, notes=([_payload_label(m)] if _payload_label(m) else []) + notes,
        ))
        if v == 1 and C.V1_FRAG in m.clear.types:
            t.fragments += 1

    _fill_negotiation(t, msgs, from_initiator)
    _fill_status(t, msgs)
    hs = [m for m in msgs if (m.exch in (C.V2_SA_INIT, C.V2_AUTH) if v == 2 else m.exch in (C.V1_MAIN, C.V1_AGGRESSIVE))]
    t.handshake_bytes = sum(m.length for m in hs)
    t.handshake_duration_s = (hs[-1].ts - hs[0].ts) if len(hs) > 1 else 0.0
    return t


def _fill_negotiation(t: Tunnel, msgs: list[IkeMessage], from_initiator) -> None:
    v = t.ike_version
    caps: set[str] = set()
    for m in msgs:
        for vid in m.clear.vendor_ids:
            name = C.VENDOR_IDS.get(vid)
            if name:
                caps.add(name)
        if m.clear.nat_d_count or any(n.type in (C.N_NAT_SRC, C.N_NAT_DST) for n in m.clear.notifies):
            caps.add("NAT detection")
        if any(n.type == C.N_FRAG_SUPPORTED for n in m.clear.notifies):
            caps.add("IKE Fragmentation")
        if any(n.type == C.N_COOKIE for n in m.clear.notifies) and not from_initiator(m):
            t.cookie_challenges += 1
    t.vendor_capabilities = sorted(caps)

    if v == 2:
        for m in msgs:
            if m.exch != C.V2_SA_INIT or not m.clear.proposals:
                continue
            suites = _v2_suites(m.clear.proposals)
            if not m.is_response:
                if not t.offered:
                    t.offered = suites
            elif suites:
                t.chosen = suites[0]
        t.dpd_messages = sum(1 for m in msgs if m.exch == C.V2_INFO)
        t.create_child_exchanges = sum(1 for m in msgs if m.exch == C.V2_CREATE_CHILD and not m.is_response)
        # Authentication + child SAs are encrypted; visible only when decrypted.
        for m in msgs:
            ps = m.decrypted
            if ps is None:
                continue
            if ps.auth_method is not None and t.auth_method is None:
                t.auth_method = C.V2_AUTH_METHOD.get(ps.auth_method, f"method-{ps.auth_method}")
                t.auth_observable = True
            _collect_child_v2(t, msgs, m, ps)
        t.child_observable = t.decrypted and any(c for c in t.child_sas)
        t.ike_rekeys = sum(
            1 for m in msgs if m.decrypted and m.exch == C.V2_CREATE_CHILD and not m.is_response
            and any(p.protocol == C.PROTO_IKE for p in m.decrypted.proposals)
        )
        t.child_rekeys = sum(1 for c in t.child_sas if c.rekey)
    else:
        init_msg = next((m for m in msgs if m.clear.v1_proposals and from_initiator(m)), None)
        resp_msg = next((m for m in msgs if m.clear.v1_proposals and not from_initiator(m)), None)
        if init_msg:
            t.offered = _v1_suites(init_msg)
        if resp_msg:
            ch = _v1_suites(resp_msg)
            t.chosen = ch[0] if ch else None
        if t.chosen and t.chosen.auth:
            t.auth_method, t.auth_observable = t.chosen.auth, True
        elif t.offered and t.offered[0].auth:
            t.auth_method, t.auth_observable = t.offered[0].auth, True
        t.dpd_messages = sum(1 for m in msgs if m.exch == C.V1_INFO)
        t.create_child_exchanges = len({m.msg_id for m in msgs if m.exch == C.V1_QUICK})
        if any(m.exch == C.V1_QUICK for m in msgs):
            t.notes.append("IKEv1 Quick Mode is fully encrypted: ESP transforms and PFS are not observable "
                           "without phase-1 keys.")


def _collect_child_v2(t: Tunnel, msgs: list[IkeMessage], m: IkeMessage, ps) -> None:
    esp_props = [p for p in ps.proposals if p.protocol in (C.PROTO_ESP, C.PROTO_AH)]
    if not esp_props:
        return
    sender_is_init = bool(m.flags & C.V2_FLAG_INITIATOR)
    if not m.is_response:
        # Requests carry the *offer*; remember which SPI/KE, chosen suite comes from the response.
        return
    p = esp_props[0]
    suite, dh_off = _child_suite(p)
    # Find matching request for KE / REKEY_SA info.
    req = next((r for r in msgs if r.msg_id == m.msg_id and r.exch == m.exch and not r.is_response), None)
    req_ps = req.decrypted if req is not None and req.decrypted is not None else None
    pfs = bool(req_ps and req_ps.ke_group is not None)
    rekey = bool(req_ps and any(n.type == C.N_REKEY_SA for n in req_ps.notifies))
    req_spi = next((q.spi for q in (req_ps.proposals if req_ps else []) if q.protocol == p.protocol and q.spi), b"")
    # requester is the opposite party of the responder (`m`)
    spi_req, spi_resp = req_spi.hex() or None, p.spi.hex() or None
    child = ChildSa(
        protocol=C.PROTO_NAME.get(p.protocol, "ESP"), via=C.V2_EXCHANGE.get(m.exch, str(m.exch)),
        ts=m.ts, suite=suite, pfs=pfs, dh_offered=dh_off, rekey=rekey,
    )
    if sender_is_init:  # responder message is from the initiator side => requester was the responder
        child.spi_responder, child.spi_initiator = spi_req, spi_resp
    else:
        child.spi_initiator, child.spi_responder = spi_req, spi_resp
    t.child_sas.append(child)


def _fill_status(t: Tunnel, msgs: list[IkeMessage]) -> None:
    fatal: list[str] = []
    for m in msgs:
        for code, name in _notify_names(m):
            if (m.version == 2 and code < 16384 and code not in (C.N_INVALID_KE,)) or \
               (m.version == 1 and 1 <= code <= 30):
                if m.version == 2 and m.decrypted is None and m.enc_body is not None:
                    continue
                fatal.append(name)
    if t.ike_version == 2:
        responded_init = any(m.exch == C.V2_SA_INIT and m.is_response and m.clear.proposals for m in msgs)
        auth_done = any(m.exch == C.V2_AUTH and m.is_response for m in msgs)
        if fatal:
            t.status, t.failure = "failed", fatal[0]
        elif auth_done:
            t.status = "established"
        elif responded_init:
            t.status, t.failure = "incomplete", "IKE_AUTH not completed in capture"
        else:
            t.status, t.failure = "incomplete", "no IKE_SA_INIT response captured"
    else:
        uniq = {m.digest for m in msgs if m.exch in (C.V1_MAIN, C.V1_AGGRESSIVE)}
        need = 3 if t.exchange_mode == "Aggressive Mode" else 6
        if fatal:
            t.status, t.failure = "failed", fatal[0]
        elif len(uniq) >= need:
            t.status = "established"
        else:
            t.status, t.failure = "incomplete", f"only {len(uniq)}/{need} phase-1 messages captured"


# ----------------------------------------------------------------------------- ESP
def _flows(esp: list[EspPacket]) -> list[tuple[EspFlow, list[EspPacket]]]:
    by: dict[tuple, list[EspPacket]] = defaultdict(list)
    for p in esp:
        by[(p.spi, p.src, p.dst, p.proto)].append(p)
    out = []
    for (spi, src, dst, proto), pk in by.items():
        pk.sort(key=lambda p: p.frame)
        mx, gaps, replays = pk[0].seq, 0, 0
        for p in pk[1:]:
            if p.seq > mx:
                gaps += min(p.seq - mx - 1, 65535)
                mx = p.seq
            else:
                replays += 1
        iats = [b.ts - a.ts for a, b in zip(pk, pk[1:])]
        out.append((EspFlow(
            spi=f"{spi:08x}", src=src, dst=dst, protocol="ESP" if proto == 50 else "AH",
            packets=len(pk), bytes=sum(p.length for p in pk), first_ts=pk[0].ts, last_ts=pk[-1].ts,
            seq_first=pk[0].seq, seq_last=pk[-1].seq, seq_gaps=gaps, seq_replays=replays,
            udp_encap=any(p.udp_encap for p in pk),
            mean_iat_ms=(sum(iats) / len(iats) * 1000) if iats else 0.0,
            mean_len=sum(p.length for p in pk) / len(pk),
        ), pk))
    return out


def _attach_esp(tunnels: list[Tunnel], esp: list[EspPacket]) -> list[EspFlow]:
    orphans: list[EspFlow] = []
    for flow, _pk in _flows(esp):
        target = next(
            (t for t in tunnels for c in t.child_sas if flow.spi in (c.spi_initiator, c.spi_responder)), None
        )
        if target is None:
            cands = [t for t in tunnels if {t.initiator, t.responder} == {flow.src, flow.dst}
                     and t.first_ts <= flow.first_ts + 0.001]
            if cands:
                target = max(cands, key=lambda t: t.first_ts)
        if target is None:
            orphans.append(flow)
        else:
            target.esp_flows.append(flow)
            target.last_ts = max(target.last_ts, flow.last_ts)
    return orphans
