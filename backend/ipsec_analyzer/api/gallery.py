"""Sample gallery: curated stories for the bundled captures plus a live preview computed by the real pipeline.

The stories are the only authored text. Every number on a gallery card (tunnels, top risk, violations, rules) comes
from analysing the capture itself, so the cards cannot drift from what the results page then shows.
"""
from __future__ import annotations

import threading
import traceback
from pathlib import Path
from typing import Any

from ..pipeline import analyze
from ..rules.policy import SEV_ORDER

# name -> (title, story, kind). Order here is the gallery order. `kind` groups cards: tour, weak, downgrade, baseline, real.
CURATED: dict[str, tuple[str, str, str]] = {
    "demo_gateway_audit": ("Audit a whole gateway", "A simulated corporate VPN gateway with compliant, weak, downgraded and anomalous tunnels side by side. "
                           "The best first click: see the risk ranking, ATT&CK map and fix plan for a full estate.", "tour"),
    "weak_des_md5_modp768": ("Single-DES, MD5 and a 768-bit group", "Real strongSwan traffic negotiating algorithms that were broken years ago. "
                            "Shows how weak cryptography is caught from the handshake alone.", "weak"),
    "weak_ikev1_aggressive_psk": ("Aggressive Mode with a pre-shared key", "Real IKEv1 Aggressive Mode: the peer's PSK hash is exposed on the wire and can be cracked offline.", "weak"),
    "w_v1_aggr_psk_00": ("Aggressive Mode, simulated", "The same weakness as a simulated single-tunnel scenario, handy for comparing with the real lab capture.", "weak"),
    "downgrade_retry_after_reject": ("Downgrade after a rejected proposal", "A strong proposal is rejected with NO_PROPOSAL_CHOSEN and the initiator retries with weaker algorithms. "
                                     "Real lab traffic.", "downgrade"),
    "d_retry_after_reject_00": ("Downgrade, simulated", "The retry-after-reject downgrade pattern as a simulated scenario.", "downgrade"),
    "a_slow_relay_00": ("Behaviour, not crypto: a slow relay", "A simulated tunnel whose configuration can look acceptable but whose timing does not. "
                        "This is where the anomaly model earns its place.", "anomaly"),
    "ok_aes256gcm_ecp384": ("A compliant tunnel", "Real AES-256-GCM with ECP-384 and nothing to fix. Use it to see what a clean result looks like.", "baseline"),
    "b_modern_00": ("Modern baseline, simulated", "A clean, modern simulated tunnel used as the benign baseline for the anomaly model.", "baseline"),
    "ikev2-decrypt-aes256gcm16.pcap": ("Third-party IKEv2 with AES-GCM", "From Wireshark's public sample set, with the decryption keys from its test suite so authentication and child SAs are assessed too. A modern suite, so a clean result.", "real"),
    "ikev2-decrypt-3des-sha1_160.pcap": ("Third-party IKEv2 with 3DES", "From Wireshark's public sample set: a legacy 3DES and SHA-1 negotiation, decrypted with the published keys.", "real"),
    "ikev1-certs.pcap": ("Third-party IKEv1 with certificates", "From Wireshark's public sample set (IKEv1, certificate test capture). Its older proposals are flagged rule by rule.", "real"),
    "ikev1-bug-12610.pcapng": ("Third-party IKEv1 capture (bug 12610)", "From Wireshark's public sample set, kept as a regression capture for IKEv1 parsing.", "real"),
    "ikev1-bug-12620.pcapng": ("Third-party IKEv1 capture (bug 12620)", "From Wireshark's public sample set, kept as a regression capture for IKEv1 parsing.", "real"),
}
ORDER = {n: i for i, n in enumerate(CURATED)}
KIND_FALLBACK = {"synthetic": "tour", "real-lab": "tour", "real-public": "real"}

_previews: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def describe(name: str, fallback: str, provenance: str) -> dict[str, Any]:
    title, story, kind = CURATED.get(name, (name, fallback, KIND_FALLBACK.get(provenance, "tour")))
    return {"title": title, "story": story, "kind": kind, "order": ORDER.get(name, len(ORDER)), "preview": _previews.get(name)}


def preview_of(res: Any) -> dict[str, Any]:
    """Headline numbers of an AnalysisResult, all read from the analysis."""
    viol = [(f.severity, f.rule_id) for t in res.tunnels for f in t.findings if f.category == "violation"]
    top = max(res.tunnels, key=lambda t: t.risk.score, default=None)
    rules: dict[str, str] = {}
    for sev, rid in sorted(viol, key=lambda v: (SEV_ORDER[v[0]], v[1])):
        rules.setdefault(rid, sev)
    return {"tunnels": len(res.tunnels), "violations": len(viol), "top_score": top.risk.score if top else None, "top_band": top.risk.band if top else None,
            "anomalous": sum(1 for t in res.tunnels if t.anomaly and t.anomaly.get("is_anomalous")),
            "rules": [{"rule_id": r, "severity": s} for r, s in list(rules.items())[:4]], "rule_count": len(rules)}


def warm_previews(samples: dict[str, dict[str, Any]], engine: Any, model: Any) -> None:
    """Analyse each bundled capture once, in the background, and keep only the headline numbers. Nothing is stored in the database."""
    for name, s in samples.items():
        with _lock:
            if name in _previews:
                continue
        try:
            res = analyze(Path(s["pcap"]), Path(s["keys"]) if s["keys"] else None, engine, model)
        except Exception:  # noqa: BLE001 - a bad sample must not stop the others or the API
            traceback.print_exc()
            continue
        with _lock:
            _previews[name] = preview_of(res)
