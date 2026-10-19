"""Sample gallery: curated stories for the bundled captures plus a live preview computed by the real pipeline.

The stories are the only authored text. Every number on a gallery card (tunnels, top risk, violations, rules) comes
from analysing the capture itself, so the cards cannot drift from what the results page then shows.
"""
from __future__ import annotations

import threading
import traceback
from pathlib import Path
from typing import Any

from ..pipeline import analyze, analyze_log, analyze_vpn_config
from ..rules.policy import SEV_ORDER

# name -> (title, story, kind). Order here is the gallery order. `kind` groups cards: tour, weak, downgrade, baseline, real, log, vpn, config.
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
    "strongswan_gateway.log": ("Audit a gateway from its strongSwan log", "No packet capture needed: the daemon's own log states every proposal it received and selected. "
                               "Six IKE SAs (hand-written sample log): compliant, weak suite chosen, downgrade retry, aggressive-mode PSK, auth failure.", "log"),
    "strongswan_initiator_filelog.log": ("An initiator's log: retransmits, then a clean tunnel", "A hand-written strongSwan initiator log in plain filelog format: three retransmits of the first message, then a compliant tunnel.", "log"),
    "ovpn_tls12_cbc_sha1": ("OpenVPN with a legacy TLS suite", "Real OpenVPN 2.6 traffic: TLS 1.2 with a CBC and SHA-1 suite and a readable control channel. The handshake alone shows the TLS version, the chosen suite and the server certificate.", "vpn"),
    "ovpn_tls10_legacy": ("OpenVPN forced to TLS 1.0", "Real OpenVPN 2.6 negotiating TLS 1.0, a version deprecated by RFC 8996. The client's offer and the server's choice are both read from the wire.", "vpn"),
    "ovpn_weak_cert": ("OpenVPN with a 1024-bit, SHA-1 server certificate", "Real OpenVPN 2.6: the server certificate crosses the wire in clear text (TLS 1.2), so its key size and signature hash are checked.", "vpn"),
    "ovpn_tls13_tlscrypt": ("OpenVPN done right: TLS 1.3 + tls-crypt", "Real OpenVPN 2.6 with the control channel encrypted by tls-crypt. Nothing to flag, and the page says what could not be observed.", "vpn"),
    "ovpn_unanswered": ("An OpenVPN client talking to nothing", "Real OpenVPN 2.6 client whose server is not running: repeated hard resets and no reply, grouped into one finding.", "vpn"),
    "wg_rekey": ("WireGuard with a rekey", "Real WireGuard traffic over two minutes: handshakes, keepalives, and the rekey at the protocol's 120-second timer, all checked against the whitepaper's timers.", "vpn"),
    "wg_unanswered": ("WireGuard handshakes nobody answers", "Real WireGuard initiations to a peer that is not there: WireGuard stays silent to the unauthenticated, so this looks the same as a wrong key or a firewall.", "vpn"),
    "openvpn_legacy_client.ovpn": ("Audit an OpenVPN client profile", "No capture needed: a tutorial-era client profile with Blowfish, compression and no server-certificate check, assessed from the file with the standards behind each finding.", "config"),
    "openvpn_permissive_server.conf": ("Audit an OpenVPN server config", "A server config that grew by copy-paste: TLS 1.0, MD5, no client certificates, no revocation list. The file's secrets are never stored.", "config"),
    "openvpn_hardened_server.conf": ("A hardened OpenVPN server config", "tls-crypt-v2, AEAD ciphers, TLS 1.2+, CRL: what a clean configuration result looks like.", "config"),
    "wireguard_site_gateway.conf": ("Audit a WireGuard gateway config", "Three peers: missing pre-shared keys and a roaming peer allowed to claim every address. Private keys are removed before analysis.", "config"),
    "wireguard_hardened_client.conf": ("A WireGuard client with a pre-shared key", "Narrow AllowedIPs and a PresharedKey: nothing to fix beyond the protocol's fixed primitives.", "config"),
    "ikev1-bug-12620.pcapng": ("Third-party IKEv1 capture (bug 12620)", "From Wireshark's public sample set, kept as a regression capture for IKEv1 parsing.", "real"),
}
ORDER = {n: i for i, n in enumerate(CURATED)}
KIND_FALLBACK = {"synthetic": "tour", "real-lab": "tour", "real-public": "real", "sample-log": "log", "sample-config": "config"}

_previews: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()


def describe(name: str, fallback: str, provenance: str) -> dict[str, Any]:
    title, story, kind = CURATED.get(name, (name, fallback, KIND_FALLBACK.get(provenance, "tour")))
    return {"title": title, "story": story, "kind": kind, "order": ORDER.get(name, len(ORDER)), "preview": _previews.get(name)}


def preview_of(res: Any) -> dict[str, Any]:
    """Headline numbers of an AnalysisResult, all read from the analysis."""
    every = res.everything
    viol = [(f.severity, f.rule_id) for t in every for f in t.findings if f.category == "violation"]
    top = max(every, key=lambda t: t.risk.score, default=None)
    rules: dict[str, str] = {}
    for sev, rid in sorted(viol, key=lambda v: (SEV_ORDER[v[0]], v[1])):
        rules.setdefault(rid, sev)
    return {"tunnels": len(every), "violations": len(viol), "top_score": top.risk.score if top else None, "top_band": top.risk.band if top else None,
            "anomalous": sum(1 for t in res.tunnels if t.anomaly and t.anomaly.get("is_anomalous")),
            "rules": [{"rule_id": r, "severity": s} for r, s in list(rules.items())[:4]], "rule_count": len(rules)}


def warm_previews(samples: dict[str, dict[str, Any]], engine: Any, model: Any) -> None:
    """Analyse each bundled capture once, in the background, and keep only the headline numbers. Nothing is stored in the database."""
    for name, s in samples.items():
        with _lock:
            if name in _previews:
                continue
        try:
            if s.get("input") == "log":
                res = analyze_log(Path(s["pcap"]), engine)
            elif s.get("input") == "config":
                res = analyze_vpn_config(Path(s["pcap"]), engine)
            else:
                res = analyze(Path(s["pcap"]), Path(s["keys"]) if s["keys"] else None, engine, model)
        except Exception:  # noqa: BLE001 - a bad sample must not stop the others or the API
            traceback.print_exc()
            continue
        with _lock:
            _previews[name] = preview_of(res)
