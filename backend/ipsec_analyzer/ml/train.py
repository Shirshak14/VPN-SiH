"""Train the anomaly baseline from the benign `train` split of the corpus manifest.

    python -m ipsec_analyzer.ml.train --manifest ../data/captures/manifest.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..pipeline import analyze
from ..rules import RuleEngine
from .model import DEFAULT_MODEL, AnomalyModel


def collect_train_tunnels(manifest_path: Path):
    root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text())
    engine = RuleEngine()
    tunnels, names = [], []
    for name, m in manifest.items():
        if m.get("split") != "train":
            continue
        res = analyze(root / m["file"], root / m["keys"] if m.get("keys") else None, engine)
        truth = {t["ispi"]: t for t in m["tunnels"]}
        for tr in res.tunnels:
            if tr.tunnel.ispi in truth and truth[tr.tunnel.ispi]["label"] == "benign":
                tunnels.append(tr.tunnel)
                names.append(name)
    return tunnels, names


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="../data/captures/manifest.json")
    ap.add_argument("--out", default=str(DEFAULT_MODEL))
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    tunnels, names = collect_train_tunnels(Path(args.manifest))
    if len(tunnels) < 20:
        raise SystemExit(f"only {len(tunnels)} benign training tunnels found; generate the corpus first (python -m synth.generate)")
    model = AnomalyModel.fit(tunnels, names, n_estimators=args.trees, seed=args.seed)
    model.save(args.out)
    print(f"trained IsolationForest on {model.meta.n_train} benign tunnels -> {args.out}")
    for g, c in model.meta.calibration.items():
        print(f"  {g:18s} benign median={c['median']:.4f}  p99={c['p99']:.4f}")


if __name__ == "__main__":
    main()
