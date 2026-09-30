"""Per-tunnel behavioural features. `ml.model.GROUPS` selects which ones each forest sees.

Only quantities observable *without* decryption are used, so the score is identical whether or not
IKEv2 keys accompany the capture. Algorithm strength is reduced to coarse policy ranks so the model
complements (rather than duplicates) the rule engine.
"""
from __future__ import annotations

import numpy as np

from ..rules.engine import RuleEngine
from ..sa.models import Tunnel

FEATURES: list[tuple[str, str]] = [
    ("ike_version", "IKE version"),
    ("aggressive", "Aggressive Mode"),
    ("msg_count", "IKE messages in tunnel"),
    ("mean_msg_bytes", "Mean IKE message size (B)"),
    ("first_msg_bytes", "First handshake message size (B)"),
    ("handshake_bytes", "Handshake bytes (B)"),
    ("first_rtt_ms", "First request→response latency (ms)"),
    ("mean_hs_gap_ms", "Mean inter-message gap in handshake (ms)"),
    ("max_hs_gap_ms", "Max inter-message gap in handshake (ms)"),
    ("retransmits", "Retransmitted IKE messages"),
    ("max_retransmit_streak", "Longest retransmit streak"),
    ("cookie_challenges", "Cookie challenges"),
    ("n_offered", "Proposals offered"),
    ("chosen_rank", "Negotiated suite policy rank (0-3)"),
    ("best_offered_rank", "Best offered suite policy rank (0-3)"),
    ("rank_drop", "Offered→chosen rank drop"),
    ("failed_prior_attempts", "Earlier failed attempts (same peers)"),
    ("incomplete", "Handshake incomplete"),
    ("create_child_per_min", "CREATE_CHILD_SA / Quick Mode rate (per min)"),
    ("dpd_messages", "Liveness (DPD) messages"),
    ("fragments", "IKE fragments"),
    ("natt", "NAT-T in use"),
    ("esp_flows", "ESP flows"),
    ("esp_packets", "ESP packets"),
    ("esp_mean_len", "Mean ESP packet length (B)"),
    ("esp_mean_iat_ms", "Mean ESP inter-arrival (ms)"),
    ("esp_replay_ratio", "ESP replayed-sequence ratio"),
    ("esp_gap_ratio", "ESP missing-sequence ratio"),
    ("duration_s", "Tunnel observed duration (s)"),
]
FEATURE_NAMES = [n for n, _ in FEATURES]
FEATURE_LABELS = dict(FEATURES)

_HS = ("IKE_SA_INIT", "IKE_AUTH", "Identity Protection", "Aggressive Mode")


def extract(t: Tunnel, engine: RuleEngine) -> dict[str, float]:
    ev = [e for e in t.timeline if not e.retransmit]
    hs = [e for e in ev if e.label.startswith(_HS)]
    gaps = [(b.ts - a.ts) * 1000 for a, b in zip(hs, hs[1:])]
    first_rtt = (ev[1].ts - ev[0].ts) * 1000 if len(ev) > 1 else 0.0
    n_ike = max(t.msg_count, 1)
    offered = [engine.suite_rank(s) for s in t.offered]
    offered = [r for r in offered if r is not None]
    chosen = engine.suite_rank(t.chosen) if t.chosen else None
    best = max(offered) if offered else 0
    ch = chosen if chosen is not None else best
    dur = max(t.last_ts - t.first_ts, 1e-3)
    esp_pk = sum(f.packets for f in t.esp_flows)
    esp_bytes = sum(f.bytes for f in t.esp_flows)
    replays = sum(f.seq_replays for f in t.esp_flows)
    gap_n = sum(f.seq_gaps for f in t.esp_flows)
    iat = [f.mean_iat_ms for f in t.esp_flows if f.packets > 1]
    return {
        "ike_version": float(t.ike_version),
        "aggressive": float(t.exchange_mode == "Aggressive Mode"),
        "msg_count": float(t.msg_count),
        "mean_msg_bytes": sum(e.size for e in t.timeline) / n_ike,
        "first_msg_bytes": float(ev[0].size) if ev else 0.0,
        "handshake_bytes": float(t.handshake_bytes),
        "first_rtt_ms": first_rtt,
        "mean_hs_gap_ms": float(np.mean(gaps)) if gaps else 0.0,
        "max_hs_gap_ms": float(max(gaps)) if gaps else 0.0,
        "retransmits": float(t.retransmits),
        "max_retransmit_streak": float(t.max_retransmit_streak),
        "cookie_challenges": float(t.cookie_challenges),
        "n_offered": float(len(t.offered)),
        "chosen_rank": float(ch),
        "best_offered_rank": float(best),
        "rank_drop": float(max(best - ch, 0)),
        "failed_prior_attempts": float(sum(1 for p in t.prior_attempts if p.status == "failed")),
        "incomplete": float(t.status == "incomplete"),
        "create_child_per_min": t.create_child_exchanges / (dur / 60.0) if dur > 1 else 0.0,
        "dpd_messages": float(t.dpd_messages),
        "fragments": float(t.fragments),
        "natt": float(t.natt),
        "esp_flows": float(len(t.esp_flows)),
        "esp_packets": float(esp_pk),
        "esp_mean_len": esp_bytes / esp_pk if esp_pk else 0.0,
        "esp_mean_iat_ms": float(np.mean(iat)) if iat else 0.0,
        "esp_replay_ratio": replays / esp_pk if esp_pk else 0.0,
        "esp_gap_ratio": gap_n / (esp_pk + gap_n) if esp_pk else 0.0,
        "duration_s": dur,
    }
