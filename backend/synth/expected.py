"""Ground-truth rule expectations derived from a TunnelSpec (i.e. from the configuration we generated).

`expect_rules`     : everything a perfect analyst would flag given the full configuration.
`assessable_rules` : the subset that is observable from the capture bytes (e.g. IKEv1 Quick Mode
                     and IKEv2 child SAs are encrypted, so ESP-* rules are only assessable for IKEv2
                     when decryption keys accompany the capture).
"""
from __future__ import annotations

from ipsec_analyzer.parser.constants import V2_ENCR_TO_V1 as _V1_ENC, V2_INTEG_TO_V1 as _V1_HASH
from ipsec_analyzer.rules.policy import V1_UNOBSERVABLE_RULES, Policy

from .builder import SuiteSpec

_BAD = ("prohibited", "deprecated")


def _rank(policy: Policy, s: SuiteSpec, v1: bool) -> int | None:
    enc = _V1_ENC.get(s.encr, s.encr) if v1 else s.encr
    integ = _V1_HASH.get(s.integ, s.integ) if v1 else s.integ
    ranks = [r for r in (policy.rank("encryption", enc), policy.rank("integrity", integ),
                         None if v1 else policy.rank("integrity", s.prf), policy.rank("dh", s.dh)) if r is not None]
    return min(ranks) if ranks else None


def expected_rules(spec, policy: Policy, flow_stats: list[tuple[int, int, int]]) -> tuple[list[str], list[str]]:
    exp: set[str] = set()
    v1 = spec.version == 1
    ch = None if spec.half_open_attempts else spec.chosen_ike
    th = policy.thresholds
    if ch:
        enc = _V1_ENC.get(ch.encr, ch.encr) if v1 else ch.encr
        if policy.tier("encryption", enc) in _BAD:
            exp.add("IKE-ENC-WEAK")
        integ = _V1_HASH.get(ch.integ, ch.integ) if v1 else ch.integ
        if policy.tier("integrity", integ) in _BAD or (not v1 and policy.tier("integrity", ch.prf) in _BAD):
            exp.add("IKE-INTEG-WEAK")
        if policy.tier("dh", ch.dh) in _BAD:
            exp.add("IKE-DH-WEAK")
    if v1:
        exp.add("IKE-V1-LEGACY")
        if spec.aggressive:
            exp.add("IKE-AGGR-PSK")
        if spec.v1_life_s > th["max_ike_lifetime_s"]:
            exp.add("IKE-LIFETIME-LONG")
    ce = None if spec.half_open_attempts else spec.chosen_esp
    esp_rules: set[str] = set()
    if ce:
        if policy.tier("encryption", ce.encr) in _BAD:
            esp_rules.add("ESP-ENC-WEAK")
        if ce.integ and policy.tier("integrity", ce.integ) in _BAD:
            esp_rules.add("ESP-INTEG-WEAK")
        if spec.child_rekeys and (not ce.dh or not spec.rekey_uses_ke):  # PFS judged from rekeys only
            esp_rules.add("ESP-NO-PFS")
    exp |= esp_rules
    # downgrade
    offered = [r for r in (_rank(policy, s, v1) for s in spec.offered_ike) if r is not None]
    cr = _rank(policy, ch, v1) if ch else None
    if ch and offered and cr is not None and cr <= 1 < max(offered):
        exp.add("SA-DOWNGRADE")
    if spec.prior_reject and offered and max(offered) <= 1:
        pr = [r for r in (_rank(policy, s, v1) for s in spec.prior_reject) if r is not None]
        if pr and max(pr) >= 2:
            exp.add("SA-DOWNGRADE")
    if spec.retransmits >= th["retransmit_alert"]:
        exp.add("SA-RETRANSMIT-EXCESS")
    for pk, rep, gap in flow_stats:
        if pk >= th["esp_min_packets"]:
            if rep / pk >= th["esp_replay_ratio"]:
                exp.add("ESP-SEQ-REPLAY")
            if gap / (pk + gap) >= th["esp_gap_ratio"]:
                exp.add("ESP-SEQ-GAPS")
    assessable = set(exp)
    if v1:
        assessable -= V1_UNOBSERVABLE_RULES
    return sorted(exp), sorted(assessable)
