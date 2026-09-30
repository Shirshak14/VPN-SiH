"""Deterministic rule engine: evaluates reconstructed tunnels against the YAML policy pack."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..sa.models import Suite, Tunnel
from .policy import TIER_RANK, Policy, load_policy

Evidence = dict[str, Any]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str  # violation | coverage
    tunnel_id: str
    description: str
    evidence: Evidence = field(default_factory=dict)
    refs: list[str] = field(default_factory=list)
    mitre: list[dict[str, str]] = field(default_factory=list)
    remediation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


# A check returns None (no violation) or (severity_key_or_tier, evidence).
CheckResult = list[tuple[str, Evidence]]
Check = Callable[[Tunnel, "RuleEngine", dict[str, Any], dict[str, Any]], CheckResult]
_CHECKS: dict[str, Check] = {}


def check(name: str) -> Callable[[Check], Check]:
    def deco(fn: Check) -> Check:
        _CHECKS[name] = fn
        return fn
    return deco


class RuleEngine:
    def __init__(self, policy_path: str | Path | None = None) -> None:
        self.policy: Policy = load_policy(policy_path, known_checks=set(_CHECKS))

    # ------------------------------------------------------------------ public
    def evaluate(self, t: Tunnel) -> list[Finding]:
        out: list[Finding] = []
        for rule in self.policy.rules:
            hits = _CHECKS[rule["check"]](t, self, rule.get("params", {}), rule)
            if not hits:
                continue
            key, evidence = hits[0]
            if len(hits) > 1:  # one finding per rule per tunnel; keep every instance as evidence
                evidence = {**evidence, "instances": [e for _k, e in hits]}
            sev = rule.get("severity_by_tier", {}).get(key) or rule.get("severity")
            if sev is not None:
                out.append(self._finding(rule, t, sev, "violation", evidence))
        out.extend(self._coverage(t))
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        out.sort(key=lambda f: (order[f.severity], f.rule_id))
        return out

    def suite_rank(self, s: Suite) -> int | None:
        """Worst tier rank across a suite's components (None if nothing classifiable)."""
        p = self.policy
        ranks = [r for r in (
            p.rank("encryption", s.encr), p.rank("integrity", s.integ),
            p.rank("integrity", s.prf), p.rank("dh", s.dh),
        ) if r is not None]
        return min(ranks) if ranks else None

    # ------------------------------------------------------------------ internals
    def _finding(self, rule: dict, t: Tunnel, sev: str, cat: str, evidence: Evidence) -> Finding:
        cat_ = self.policy.raw["mitre_catalog"]
        rem = self.policy.raw["remediations"][rule["remediation"]]
        return Finding(
            rule_id=rule["id"], title=rule["title"], severity=sev, category=cat, tunnel_id=t.id,
            description=" ".join(rule["description"].split()), evidence=evidence, refs=list(rule.get("refs", [])),
            mitre=[{"id": m, **cat_[m]} for m in rule.get("mitre", [])],
            remediation={"id": rule["remediation"], **rem},
        )

    def _coverage(self, t: Tunnel) -> list[Finding]:
        """Things the analyzer could NOT assess. Reported honestly, never scored."""
        out: list[Finding] = []

        def cov(rid: str, title: str, why: str) -> None:
            out.append(Finding(rid, title, "info", "coverage", t.id, why, {"reason": why}))

        if t.ike_version == 2 and not t.decrypted:
            cov("COV-IKEV2-ENCRYPTED", "IKEv2 authentication and child SA not observable",
                "IKEv2 encrypts everything after IKE_SA_INIT. Without the SK_e/SK_a keys the auth method, ESP "
                "algorithms and PFS status cannot be assessed; only IKE SA suite, timing and ESP sequencing are.")
        elif t.ike_version == 1 and t.create_child_exchanges:
            cov("COV-IKEV1-PHASE2", "IKEv1 Quick Mode not observable",
                "Quick Mode is encrypted with phase-1 keys; ESP transforms and PFS were not assessed.")
        if t.status == "established" and not t.child_sas and t.ike_version == 2 and t.decrypted:
            cov("COV-NO-CHILD", "No child SA found in decrypted IKE_AUTH", "IKE_AUTH decrypted but carried no ESP/AH proposal.")
        return out


# ====================================================================== checks
def _suite_component(s: Suite, component: str) -> list[tuple[str, str | None, str]]:
    """[(policy category, algorithm, human label)] for a component of one suite."""
    if component == "encryption":
        return [("encryption", s.encr, "encryption")]
    if component == "integrity":
        return [("integrity", s.integ, "integrity"), ("integrity", s.prf, "PRF")]
    if component == "dh":
        return [("dh", s.dh, "DH group")]
    raise ValueError(component)


@check("suite_tier")
def _suite_tier(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    suites: list[tuple[str, Suite]] = []
    if params["scope"] == "ike":
        if t.chosen:
            suites.append(("IKE SA", t.chosen))
    else:
        suites += [(f"{c.protocol} child ({c.via})", c.suite) for c in t.child_sas]
    offenders: list[Evidence] = []
    for where, s in suites:
        for cat, alg, label in _suite_component(s, params["component"]):
            tier = eng.policy.tier(cat, alg)
            if tier in rule.get("severity_by_tier", {}):
                ev = {"algorithm": alg, "component": label, "tier": tier, "where": where, "negotiated": s.label()}
                if s.encr_bits and label == "encryption":
                    ev["key_bits"] = s.encr_bits
                if not any(o["algorithm"] == alg and o["where"] == where and o["component"] == label for o in offenders):
                    offenders.append(ev)
    if not offenders:
        return []
    # One finding per rule per tunnel: severity of the worst offender, all offenders listed as evidence.
    worst = min(offenders, key=lambda o: TIER_RANK[o["tier"]])
    return [(worst["tier"], {**worst, "all_offenders": offenders})]


@check("child_no_pfs")
def _no_pfs(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    if not t.child_sas:
        return []
    initial = [c for c in t.child_sas if not c.rekey]
    no_dh = [c for c in t.child_sas if not c.dh_offered and not c.pfs]
    rekeys_no_ke = [c for c in t.child_sas if c.via == "CREATE_CHILD_SA" and not c.pfs]
    if no_dh or rekeys_no_ke:
        return [("", {
            "child_sas": len(t.child_sas), "without_dh_transform": len(no_dh),
            "rekeys_without_key_exchange": len(rekeys_no_ke), "initial_child_sas": len(initial),
            "negotiated": [c.suite.label() for c in t.child_sas][:3],
        })]
    return []


@check("aggressive_psk")
def _aggr_psk(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    if t.exchange_mode == "Aggressive Mode" and t.auth_method in ("PSK", "XAUTH_PSK"):
        return [("", {"exchange": t.exchange_mode, "auth_method": t.auth_method,
                      "note": "identity and HASH_R sent before authentication"})]
    return []


@check("ikev1_used")
def _v1(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    return [("", {"exchange": t.exchange_mode})] if t.ike_version == 1 else []


@check("downgrade")
def _downgrade(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    evidence: Evidence = {}
    offered_ranks = [(eng.suite_rank(s), s) for s in t.offered if eng.suite_rank(s) is not None]
    if t.chosen is not None and offered_ranks:
        cr = eng.suite_rank(t.chosen)
        best_r, best_s = max(offered_ranks, key=lambda x: x[0])
        if cr is not None and cr <= 1 < best_r:  # chosen weak/prohibited while a compliant suite was offered
            evidence["offered_compliant_suite"] = best_s.label()
            evidence["negotiated_suite"] = t.chosen.label()
            evidence["pattern"] = "responder selected weak suite despite compliant offer"
    if offered_ranks:
        this_best = max(r for r, _ in offered_ranks)
        for prev in t.prior_attempts:
            pr = [eng.suite_rank(s) for s in prev.offered if eng.suite_rank(s) is not None]
            if prev.status == "failed" and pr and max(pr) >= 2 and this_best <= 1:
                evidence["prior_attempt"] = {"ispi": prev.ispi, "failure": prev.failure,
                                             "offered": [s.label() for s in prev.offered][:3]}
                evidence["retry_offered"] = [s.label() for s in t.offered][:3]
                evidence["pattern"] = (evidence.get("pattern", "") + "; " if evidence.get("pattern") else "") + \
                    "retry after rejection offered only weak suites"
                break
    return [("", evidence)] if evidence else []


@check("ike_lifetime")
def _lifetime(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    lim = eng.policy.thresholds["max_ike_lifetime_s"]
    lt = t.chosen.lifetime_s if t.chosen else None
    return [("", {"lifetime_s": lt, "limit_s": lim})] if lt and lt > lim else []


@check("retransmits")
def _retransmits(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    lim = eng.policy.thresholds["retransmit_alert"]
    if t.retransmits >= lim:
        return [("", {"retransmits": t.retransmits, "longest_streak": t.max_retransmit_streak, "threshold": lim})]
    return []


@check("esp_replay")
def _esp_replay(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    th = eng.policy.thresholds
    out: CheckResult = []
    for f in t.esp_flows:
        if f.packets >= th["esp_min_packets"] and f.seq_replays / f.packets >= th["esp_replay_ratio"]:
            out.append(("", {"spi": f.spi, "packets": f.packets, "replayed": f.seq_replays,
                             "ratio": round(f.seq_replays / f.packets, 4)}))
    return out[:3]


@check("esp_gaps")
def _esp_gaps(t: Tunnel, eng: RuleEngine, params: dict, rule: dict) -> CheckResult:
    th = eng.policy.thresholds
    out: CheckResult = []
    for f in t.esp_flows:
        total = f.packets + f.seq_gaps
        if f.packets >= th["esp_min_packets"] and f.seq_gaps / total >= th["esp_gap_ratio"]:
            out.append(("", {"spi": f.spi, "packets": f.packets, "missing": f.seq_gaps,
                             "ratio": round(f.seq_gaps / total, 4)}))
    return out[:3]
