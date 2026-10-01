"""Scenario families: samplers that turn a seeded RNG into TunnelSpecs.

Label semantics
  benign        policy-compliant. Advisory (low-severity) notes such as IKEv1-with-strong-crypto or
                HMAC-SHA1 are allowed and are NOT counted as alerts.
  weak-config   misconfiguration with at least one medium-or-higher policy finding.
  downgrade     proposal downgrade / weak selection despite compliant offer.
  behavioral    policy-compliant crypto but abnormal handshake/ESP behaviour (relay-like latency,
                rekey storms, oversized handshakes, scan probes, replay/gap injection).
All are simulated (`synthetic`); none is a real-world incident.
"""
from __future__ import annotations

from random import Random
from typing import Callable

from .builder import SuiteSpec
from .simulate import TunnelSpec

S = SuiteSpec

# --- suite catalogues -----------------------------------------------------------------------
STRONG_IKE = [
    S("AES_GCM_16", 256, None, "HMAC_SHA2_384", "ECP_384"), S("AES_GCM_16", 256, None, "HMAC_SHA2_384", "CURVE_25519"),
    S("AES_GCM_16", 128, None, "HMAC_SHA2_256", "ECP_256"), S("AES_GCM_16", 256, None, "HMAC_SHA2_384", "MODP_3072"),
    S("AES_CBC", 256, "HMAC_SHA2_384_192", "HMAC_SHA2_384", "MODP_3072"), S("AES_CBC", 256, "HMAC_SHA2_256_128", "HMAC_SHA2_256", "ECP_384"),
    S("AES_CBC", 256, "HMAC_SHA2_512_256", "HMAC_SHA2_512", "MODP_4096"),
]
ACCEPT_IKE = [
    S("AES_CBC", 128, "HMAC_SHA2_256_128", "HMAC_SHA2_256", "MODP_2048"), S("AES_CBC", 256, "HMAC_SHA2_256_128", "HMAC_SHA2_256", "MODP_2048"),
]
SHA1_IKE = [S("AES_CBC", 256, "HMAC_SHA1_96", "HMAC_SHA1", "MODP_2048"), S("AES_CBC", 128, "HMAC_SHA1_96", "HMAC_SHA1", "ECP_256")]


def esp_for(ike: SuiteSpec, pfs: bool) -> SuiteSpec:
    dh = ike.dh if pfs else None
    if ike.encr == "AES_GCM_16":
        return S("AES_GCM_16", ike.bits, None, None, dh)
    return S(ike.encr, ike.bits, ike.integ, None, dh)


def _endpoints(rng: Random) -> tuple[str, str]:
    return f"198.51.{rng.randint(1, 250)}.{rng.randint(2, 250)}", f"203.0.{rng.randint(1, 250)}.{rng.randint(2, 250)}"


def _base(rng: Random, label: str, family: str) -> TunnelSpec:
    a, b = _endpoints(rng)
    rtt = min(max(rng.lognormvariate(3.2, 0.7), 2.0), 160.0)  # median ~25 ms
    auth = rng.choice(("PSK", "RSA"))
    return TunnelSpec(
        label=label, family=family, initiator=a, responder=b, natt=rng.random() < 0.25, auth=auth,
        rtt_ms=rtt, proc_ms=rng.uniform(6, 40), traffic_pkts=rng.randint(40, 260), traffic_rate_hz=rng.uniform(4, 70),
        child_rekeys=rng.choice((0, 0, 1, 2)), dpd_count=rng.choice((0, 1, 2, 3)), dpd_interval_s=rng.uniform(8, 30),
        frag_auth=(auth == "RSA" and rng.random() < 0.6), cookie=rng.random() < 0.05,
        retransmits=1 if rng.random() < 0.06 else 0,
    )


def _to_v1(s: TunnelSpec) -> None:
    s.version, s.natt, s.frag_auth, s.cookie, s.child_rekeys = 1, False, False, False, 0


def _behavioral(rng: Random, family: str) -> TunnelSpec:
    s = b_modern(rng)
    s.label, s.family = "behavioral", family
    return s


def _finish(spec: TunnelSpec, ike: SuiteSpec, esp: SuiteSpec) -> TunnelSpec:
    spec.offered_ike, spec.chosen_ike = [ike], ike
    spec.offered_esp, spec.chosen_esp = [esp], esp
    return spec


# --- benign ---------------------------------------------------------------------------------
def b_modern(rng: Random) -> TunnelSpec:
    s = _base(rng, "benign", "b_modern")
    ike = rng.choice(STRONG_IKE)
    return _finish(s, ike, esp_for(ike, pfs=True))


def b_acceptable(rng: Random) -> TunnelSpec:
    s = _base(rng, "benign", "b_acceptable")
    ike = rng.choice(ACCEPT_IKE)
    return _finish(s, ike, esp_for(ike, pfs=True))


def b_multi_offer(rng: Random) -> TunnelSpec:
    """Initiator offers a strong list; responder picks its (compliant) preference. Not a downgrade."""
    s = _base(rng, "benign", "b_multi_offer")
    offers = rng.sample(STRONG_IKE + ACCEPT_IKE, rng.randint(2, 3))
    chosen = rng.choice(offers)
    s.offered_ike, s.chosen_ike = offers, chosen
    s.offered_esp, s.chosen_esp = [esp_for(o, True) for o in offers], esp_for(chosen, True)
    return s


def b_legacy_sha1(rng: Random) -> TunnelSpec:
    s = _base(rng, "benign", "b_legacy_sha1")
    ike = rng.choice(SHA1_IKE)
    return _finish(s, ike, esp_for(ike, pfs=True))


def b_v1_strong(rng: Random) -> TunnelSpec:
    s = _base(rng, "benign", "b_v1_strong")
    _to_v1(s)
    ike = S("AES_CBC", rng.choice((128, 256)), rng.choice(("HMAC_SHA2_256_128", "HMAC_SHA2_384_192")), None, rng.choice(("MODP_2048", "MODP_3072")))
    return _finish(s, ike, esp_for(ike, pfs=True))


# --- weak-config ----------------------------------------------------------------------------
def w_ike_3des(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_ike_3des")
    ike = S("3DES", None, rng.choice(("HMAC_SHA2_256_128", "HMAC_SHA1_96")), "HMAC_SHA2_256", rng.choice(("MODP_2048", "MODP_3072")))
    esp = esp_for(rng.choice(STRONG_IKE), True)
    return _finish(s, ike, esp)


def w_ike_dh1024(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_ike_dh1024")
    ike = S("AES_CBC", 256, "HMAC_SHA2_256_128", "HMAC_SHA2_256", rng.choice(("MODP_1024", "MODP_768", "MODP_1536")))
    return _finish(s, ike, esp_for(ike, pfs=True))


def w_ike_md5(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_ike_md5")
    ike = S("AES_CBC", 128, "HMAC_MD5_96", "HMAC_MD5", rng.choice(("MODP_2048", "MODP_1024")))
    return _finish(s, ike, esp_for(ike, pfs=True))


def w_esp_weak(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_esp_weak")
    ike = rng.choice(STRONG_IKE)
    esp = S(rng.choice(("3DES", "DES")), None, rng.choice(("HMAC_SHA1_96", "HMAC_MD5_96", "HMAC_SHA2_256_128")), None, ike.dh if rng.random() < 0.5 else None)
    return _finish(s, ike, esp)


def w_no_pfs(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_no_pfs")
    ike = rng.choice(STRONG_IKE + ACCEPT_IKE)
    s.child_rekeys, s.rekey_uses_ke = rng.choice((1, 2, 3)), False
    return _finish(s, ike, esp_for(ike, pfs=False))


def w_v1_aggr_psk(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_v1_aggr_psk")
    _to_v1(s)
    s.aggressive = True
    ike = S(rng.choice(("AES_CBC", "AES_CBC", "3DES")), 128, rng.choice(("HMAC_SHA1_96", "HMAC_SHA2_256_128")), None,
            rng.choice(("MODP_1024", "MODP_2048", "MODP_1536")))
    if ike.encr == "3DES":
        ike = S("3DES", None, ike.integ, None, ike.dh)
    return _finish(s, ike, esp_for(ike, pfs=False))


def w_v1_main_legacy(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_v1_main_legacy")
    _to_v1(s)
    ike = S("3DES", None, rng.choice(("HMAC_MD5_96", "HMAC_SHA1_96")), None, rng.choice(("MODP_1024", "MODP_768")))
    return _finish(s, ike, esp_for(ike, pfs=False))


def w_legacy_combo(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_legacy_combo")
    ike = S(rng.choice(("3DES", "DES")), None, rng.choice(("HMAC_MD5_96", "HMAC_SHA1_96")), rng.choice(("HMAC_MD5", "HMAC_SHA1")),
            rng.choice(("MODP_768", "MODP_1024")))
    return _finish(s, ike, esp_for(ike, pfs=False))


def w_long_lifetime(rng: Random) -> TunnelSpec:
    s = _base(rng, "weak-config", "w_long_lifetime")
    _to_v1(s)
    s.aggressive = True  # combine with aggressive PSK so the family stays medium+
    ike = S("AES_CBC", 256, "HMAC_SHA2_256_128", None, "MODP_2048")
    s.v1_life_s = rng.choice((172800, 604800, 2592000))
    return _finish(s, ike, esp_for(ike, pfs=False))


# --- downgrade ------------------------------------------------------------------------------
_WEAK_SUITES = [S("3DES", None, "HMAC_SHA1_96", "HMAC_SHA1", "MODP_1024"), S("3DES", None, "HMAC_MD5_96", "HMAC_MD5", "MODP_1024"),
                S("DES", None, "HMAC_MD5_96", "HMAC_MD5", "MODP_768")]


def d_offer_strong_chose_weak(rng: Random) -> TunnelSpec:
    s = _base(rng, "downgrade", "d_offer_strong_chose_weak")
    strong, weak = rng.choice(STRONG_IKE), rng.choice(_WEAK_SUITES)
    s.offered_ike, s.chosen_ike = [strong, weak], weak
    s.offered_esp, s.chosen_esp = [esp_for(strong, True), esp_for(weak, True)], esp_for(weak, True)
    s.proc_ms *= 1.5
    return s


def d_retry_after_reject(rng: Random) -> TunnelSpec:
    s = _base(rng, "downgrade", "d_retry_after_reject")
    strong, weak = rng.choice(STRONG_IKE), rng.choice(_WEAK_SUITES)
    s.prior_reject = [strong]
    s.offered_ike, s.chosen_ike = [weak], weak
    s.offered_esp, s.chosen_esp = [esp_for(weak, True)], esp_for(weak, True)
    return s


def d_dh_only(rng: Random) -> TunnelSpec:
    s = _base(rng, "downgrade", "d_dh_only")
    hi = rng.choice(STRONG_IKE[3:5] + ACCEPT_IKE)
    lo = S(hi.encr, hi.bits, hi.integ, hi.prf, rng.choice(("MODP_1024", "MODP_768")))
    s.offered_ike, s.chosen_ike = [hi, lo], lo
    s.offered_esp, s.chosen_esp = [esp_for(hi, True), esp_for(lo, True)], esp_for(lo, True)
    return s


# --- behavioural anomalies (compliant crypto) -----------------------------------------------
def a_retransmit_burst(rng: Random) -> TunnelSpec:
    s = _behavioral(rng, "a_retransmit_burst")
    s.retransmits, s.rtt_ms = rng.randint(3, 6), rng.uniform(40, 200)
    return s


def a_slow_relay(rng: Random) -> TunnelSpec:
    s = _behavioral(rng, "a_slow_relay")
    s.rtt_ms, s.proc_ms = rng.uniform(380, 900), rng.uniform(5, 20)
    return s


def a_rekey_storm(rng: Random) -> TunnelSpec:
    s = _behavioral(rng, "a_rekey_storm")
    s.child_rekeys = rng.randint(9, 16)
    s.traffic_pkts, s.traffic_rate_hz = rng.randint(90, 160), rng.uniform(60, 140)
    return s


def a_esp_replay(rng: Random) -> TunnelSpec:
    s = _behavioral(rng, "a_esp_replay")
    s.replay_ratio, s.gap_ratio = rng.uniform(0.04, 0.12), rng.choice((0.0, rng.uniform(0.06, 0.2)))
    s.traffic_pkts = max(s.traffic_pkts, 100)
    return s


def a_oversize_handshake(rng: Random) -> TunnelSpec:
    s = _behavioral(rng, "a_oversize_handshake")
    s.extra_vid_bytes = rng.randint(700, 1200)
    s.frag_auth = False
    return s


def a_half_open_scan(rng: Random) -> TunnelSpec:
    s = _behavioral(rng, "a_half_open_scan")
    s.half_open_attempts, s.retransmits = rng.randint(8, 25), rng.randint(2, 4)
    s.cookie, s.frag_auth = False, False
    return s


FAMILIES: dict[str, Callable[[Random], TunnelSpec]] = {
    f.__name__: f for f in (
        b_modern, b_acceptable, b_multi_offer, b_legacy_sha1, b_v1_strong,
        w_ike_3des, w_ike_dh1024, w_ike_md5, w_esp_weak, w_no_pfs, w_v1_aggr_psk, w_v1_main_legacy, w_legacy_combo, w_long_lifetime,
        d_offer_strong_chose_weak, d_retry_after_reject, d_dh_only,
        a_retransmit_burst, a_slow_relay, a_rekey_storm, a_esp_replay, a_oversize_handshake, a_half_open_scan,
    )
}
BENIGN_FAMILIES = [n for n in FAMILIES if n.startswith("b_")]
