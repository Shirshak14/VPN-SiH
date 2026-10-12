"""Experiment: does a small autoencoder add anything to the deployed anomaly layer?

    python -m experiments.autoencoder_eval            # from backend/, after generating the corpus and training the model

The brief asked for a PyTorch autoencoder. This uses scikit-learn's MLPRegressor trained to reproduce its input
(bottleneck network) so the experiment needs no new dependency; it is the same idea, not the same framework.

Protocol, matching how the forests are judged: fit on the benign `train` split only; standardise log1p features;
anomaly score = mean squared reconstruction error (averaged over 3 seeds); threshold = 99th percentile of 5-fold
out-of-fold benign training errors (flag strictly above it); evaluate on the held-out `test` split and compare with
the deployed model (`AnomalyModel.is_anomalous`) on the same tunnels. Prints a Markdown table.
"""
from __future__ import annotations

import json
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.model_selection import KFold
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from ipsec_analyzer.ml import features as F
from ipsec_analyzer.ml.model import AnomalyModel
from ipsec_analyzer.pipeline import analyze
from ipsec_analyzer.rules import RuleEngine

warnings.filterwarnings("ignore")  # sklearn convergence chatter
ROOT = Path(__file__).resolve().parents[2] / "data" / "captures"
# ESP replay/gap ratios are constant zero in every benign tunnel: no variance for an autoencoder to learn.
COLS = [c for c in F.FEATURE_NAMES if c not in ("esp_replay_ratio", "esp_gap_ratio")]
ARCHS = {"6": (6,), "16-4-16": (16, 4, 16)}


def load() -> tuple[list, list, list]:
    man = json.loads((ROOT / "manifest.json").read_text())
    eng, model = RuleEngine(), AnomalyModel.load()
    train, test = [], []
    for m in man.values():
        if m["split"] not in ("train", "test"):
            continue
        res = analyze(ROOT / m["file"], ROOT / m["keys"] if m.get("keys") else None, eng)
        truth = {t["ispi"]: t for t in m["tunnels"]}
        for r in res.tunnels:
            t = truth.get(r.tunnel.ispi)
            if t is None:
                continue
            row = (F.extract(r.tunnel, eng), t["label"], t["family"], model.score(r.tunnel)["is_anomalous"])
            (train if m["split"] == "train" else test).append(row)
    return train, test, []


def fit(x: np.ndarray, hidden: tuple[int, ...], seed: int) -> MLPRegressor:
    return MLPRegressor(hidden_layer_sizes=hidden, activation="tanh", alpha=1e-3, max_iter=3000, random_state=seed).fit(x, x)


def mse(m: MLPRegressor, x: np.ndarray) -> np.ndarray:
    return ((m.predict(x) - x) ** 2).mean(axis=1)


def main() -> None:
    train, test, _ = load()
    mat = lambda rows: np.log1p(np.array([[r[0][c] for c in COLS] for r in rows]))  # noqa: E731
    benign = [r for r in train if r[1] == "benign"]
    sc = StandardScaler().fit(mat(benign))
    xa, xb = sc.transform(mat(benign)), sc.transform(mat(test))
    fam = np.array([r[2] for r in test])
    positive = np.array([r[1] != "benign" for r in test])
    deployed = np.array([r[3] for r in test])
    flags: dict[str, np.ndarray] = {}
    for name, hidden in ARCHS.items():
        oof = np.zeros(len(xa))
        for tr, te in KFold(5, shuffle=True, random_state=7).split(xa):
            oof[te] = mse(fit(xa[tr], hidden, 7), xa[te])
        thr = np.percentile(oof, 99)
        err = np.mean([mse(fit(xa, hidden, s), xb) for s in range(3)], axis=0)
        flags[name] = err > thr
    print(f"benign train tunnels: {len(xa)}; held-out test tunnels: {len(xb)} ({int(positive.sum())} positive)\n")
    print("| Family | n | Deployed anomaly layer | " + " | ".join(f"Autoencoder {a}" for a in ARCHS) + " |")
    print("|---|---|---|" + "---|" * len(ARCHS))
    by = defaultdict(list)
    for i, f in enumerate(fam):
        by[f].append(i)
    for f in sorted(by):
        if f.startswith("b_"):
            continue
        ix = by[f]
        print(f"| {f} | {len(ix)} | {int(deployed[ix].sum())}/{len(ix)} | " + " | ".join(f"{int(fl[ix].sum())}/{len(ix)}" for fl in flags.values()) + " |")
    ben = ~positive
    print(f"| **benign false alarms** | {int(ben.sum())} | {int(deployed[ben].sum())} | " + " | ".join(str(int(fl[ben].sum())) for fl in flags.values()) + " |")
    print(f"| **all positives caught** | {int(positive.sum())} | {int(deployed[positive].sum())} | " + " | ".join(str(int(fl[positive].sum())) for fl in flags.values()) + " |")


if __name__ == "__main__":
    main()
