"""Grouped Isolation Forest behavioural baseline + SHAP explanations.

Why grouped: a single Isolation Forest over ~15 mixed features isolates an outlier only when the
random split happens to pick the one feature that is abnormal, so single-signal anomalies (e.g. a
relay adding 600 ms of latency) barely move the score. Instead, one small forest is fitted per
behavioural domain (handshake size, handshake timing, reliability, proposal pattern, lifecycle/ESP),
each on **benign tunnels only**, and calibrated on its own benign score distribution.

    group score  = clip(0.5 * (raw - median_benign) / max(p99_benign - median_benign, floor), 0, 1)
    tunnel score = max over groups          (a tunnel is flagged when score > 0.5, i.e. strictly more
                                             unusual than the benign 99th percentile)

Benign median / p99 are computed from **out-of-fold** scores (5-fold) so held-out benign tunnels are
not judged against a threshold fitted to points the forest has already seen.

Explanations come from `shap.TreeExplainer` on the fitted forest of the dominant group.
Nothing is precomputed or hard-coded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import shap
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import KFold

from ..rules.engine import RuleEngine
from ..sa.models import Tunnel
from . import features as F

DEFAULT_MODEL = Path(__file__).resolve().parents[2] / "models" / "anomaly_if.joblib"
SPAN_FLOOR = 0.03  # minimum calibration span so near-constant benign groups don't flag on noise

# ESP replay/gap ratios are deliberately NOT modelled: they are exactly zero in every benign tunnel, so a
# forest has nothing to learn from (degenerate trees); the rule engine covers them deterministically.
GROUPS: dict[str, list[str]] = {
    "first message size": ["first_msg_bytes"],
    "message size": ["mean_msg_bytes"],
    "handshake timing": ["first_rtt_ms", "max_hs_gap_ms"],
    "reliability": ["retransmits", "cookie_challenges", "incomplete", "failed_prior_attempts"],
    "proposal pattern": ["ike_version", "aggressive", "n_offered"],
    "rekey rate": ["create_child_per_min"],
}


@dataclass
class ModelMeta:
    n_train: int
    n_estimators: int
    calibration: dict[str, dict[str, float]]  # group -> {median, p99}
    feature_medians: dict[str, float]
    trained_on: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "groups": GROUPS}


class AnomalyModel:
    def __init__(self, forests: dict[str, IsolationForest], meta: ModelMeta, engine: RuleEngine | None = None) -> None:
        self.forests, self.meta = forests, meta
        self.engine = engine or RuleEngine()
        self._explainers: dict[str, shap.TreeExplainer] = {}

    # ------------------------------------------------------------------ training
    @classmethod
    def fit(cls, tunnels: list[Tunnel], names: list[str], engine: RuleEngine | None = None,
            n_estimators: int = 200, seed: int = 7) -> "AnomalyModel":
        engine = engine or RuleEngine()
        rows = [F.extract(t, engine) for t in tunnels]
        forests: dict[str, IsolationForest] = {}
        calib: dict[str, dict[str, float]] = {}
        for g, cols in GROUPS.items():
            X = np.array([[r[c] for c in cols] for r in rows], dtype=float)
            forests[g] = IsolationForest(n_estimators=n_estimators, max_samples=min(256, len(X)),
                                         contamination="auto", random_state=seed).fit(X)
            raw = np.zeros(len(X))
            for tr, te in KFold(5, shuffle=True, random_state=seed).split(X):
                fold = IsolationForest(n_estimators=100, max_samples=min(256, len(tr)), random_state=seed).fit(X[tr])
                raw[te] = -fold.score_samples(X[te])
            calib[g] = {"median": float(np.median(raw)), "p99": float(np.percentile(raw, 99))}
        meta = ModelMeta(len(rows), n_estimators, calib,
                         {n: float(np.median([r[n] for r in rows])) for n in F.FEATURE_LABELS}, names)
        return cls(forests, meta, engine)

    # ------------------------------------------------------------------ scoring
    def _group_score(self, g: str, feats: dict[str, float]) -> tuple[float, float, np.ndarray]:
        x = np.array([[feats[c] for c in GROUPS[g]]], dtype=float)
        raw = float(-self.forests[g].score_samples(x)[0])
        c = self.meta.calibration[g]
        span = max(c["p99"] - c["median"], SPAN_FLOOR)
        return float(min(max(0.5 * (raw - c["median"]) / span, 0.0), 1.0)), raw, x

    def score(self, t: Tunnel, top_k: int = 5) -> dict[str, Any]:
        feats = F.extract(t, self.engine)
        per = {g: self._group_score(g, feats) for g in GROUPS}
        top_g = max(per, key=lambda g: per[g][0])
        score = per[top_g][0]
        return {
            "score": round(score, 4), "is_anomalous": score > 0.5, "threshold": 0.5, "dominant_group": top_g,
            "groups": [{"group": g, "score": round(s, 4), "features": GROUPS[g]} for g, (s, _r, _x) in
                       sorted(per.items(), key=lambda kv: -kv[1][0])],
            "features": feats,
            "explanation": self._explain(top_g, per[top_g][2], top_k),
        }

    def _explain(self, group: str, x: np.ndarray, top_k: int) -> dict[str, Any]:
        try:
            if group not in self._explainers:
                self._explainers[group] = shap.TreeExplainer(self.forests[group])
            sv = np.asarray(self._explainers[group].shap_values(x))[0]
        except Exception as e:  # SHAP cannot explain degenerate (split-free) forests; say so instead of inventing values
            return {"method": "SHAP TreeExplainer on the fitted IsolationForest", "group": group, "top_features": [],
                    "error": f"explanation unavailable: {type(e).__name__}"}
        contrib = -sv  # SHAP explains the forest's decision function (higher = more normal); flip: + = more anomalous
        cols = GROUPS[group]
        order = np.argsort(-np.abs(contrib))[:top_k]
        return {
            "method": "SHAP TreeExplainer on the fitted IsolationForest",
            "group": group,
            "top_features": [{
                "feature": cols[i], "label": F.FEATURE_LABELS[cols[i]], "value": round(float(x[0, i]), 4),
                "baseline_median": round(self.meta.feature_medians[cols[i]], 4), "shap": round(float(contrib[i]), 5),
                "direction": "raises anomaly" if contrib[i] > 0 else "lowers anomaly",
            } for i in order],
        }

    # ------------------------------------------------------------------ persistence
    def save(self, path: str | Path = DEFAULT_MODEL) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"forests": self.forests, "meta": self.meta}, path)
        path.with_suffix(".json").write_text(json.dumps(self.meta.to_dict() | {"trained_on": len(self.meta.trained_on)}, indent=1))

    @classmethod
    def load(cls, path: str | Path = DEFAULT_MODEL, engine: RuleEngine | None = None) -> "AnomalyModel":
        blob = joblib.load(path)
        return cls(blob["forests"], blob["meta"], engine)
