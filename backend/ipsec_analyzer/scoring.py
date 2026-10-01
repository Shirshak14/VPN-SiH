"""Per-tunnel risk score (0-100). The formula is intentionally small enough to print in the UI.

    R = 1 - prod_i (1 - w(severity_i))          noisy-OR over rule findings, w from the policy pack
    A = anomaly_weight * anomaly_score           anomaly_score in [0, 1] from the Isolation Forest
    risk = 100 * (1 - (1 - R) * (1 - A))         independent-evidence combination

Findings of category "coverage" (things we could not assess) never contribute.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .rules.engine import Finding
from .rules.policy import SEVERITIES, Policy

FORMULA = "risk = 100 × (1 − (1 − R) × (1 − A)),  R = 1 − ∏(1 − w_severity),  A = anomaly_weight × anomaly_score"


@dataclass
class RiskScore:
    score: float
    band: str
    rules_component: float  # R
    anomaly_component: float  # A
    anomaly_score: float | None
    contributions: list[dict[str, Any]] = field(default_factory=list)
    formula: str = FORMULA

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def score_tunnel(findings: list[Finding], anomaly_score: float | None, policy: Policy) -> RiskScore:
    prod, contribs = 1.0, []
    for f in findings:
        if f.category != "violation":
            continue
        w = policy.severity_weight(f.severity)
        if w > 0:
            prod *= 1.0 - w
            contribs.append({"rule_id": f.rule_id, "severity": f.severity, "weight": w})
    r = 1.0 - prod
    a = policy.raw["risk"]["anomaly_weight"] * (anomaly_score or 0.0)
    risk = 100.0 * (1.0 - (1.0 - r) * (1.0 - a))
    bands = policy.raw["risk"]["bands"]
    band = next((b for b in SEVERITIES[:-1] if risk >= bands[b]), "info")
    return RiskScore(round(risk, 1), band, round(r, 4), round(a, 4), anomaly_score, contribs)
