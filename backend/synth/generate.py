"""Generate the labelled synthetic corpus and the demo capture.

    python -m synth.generate --out ../data/captures --per-family 6 --benign-per-family 14 --seed 2026
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from random import Random

from . import builder as B
from .families import BENIGN_FAMILIES, FAMILIES
from .simulate import simulate

DEMO_MIX = [
    "b_modern", "b_multi_offer", "b_v1_strong", "w_ike_3des", "w_v1_aggr_psk", "w_no_pfs",
    "d_retry_after_reject", "d_offer_strong_chose_weak", "a_slow_relay", "a_esp_replay", "w_ike_dh1024",
]


def build_capture(specs, rng: Random, base_ts: float, spacing: float = 12.0):
    packets, keyrows, truths, ts = [], [], [], base_ts
    for spec in specs:
        pk, keys, truth, end = simulate(spec, rng, ts)
        packets += pk
        keyrows += keys
        truths.append(truth)
        ts += spacing + rng.uniform(0, spacing / 2)
    return packets, keyrows, truths


def write_capture(out: Path, name: str, packets, keyrows) -> None:
    B.write_pcap(str(out / f"{name}.pcap"), packets)
    if keyrows:
        (out / f"{name}.keys").write_text("# IKEv2 SK keys (Wireshark ikev2_decryption_table format)\n" + "\n".join(keyrows) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../data/captures")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--per-family", type=int, default=6)
    ap.add_argument("--benign-per-family", type=int, default=14)
    args = ap.parse_args()

    out = Path(args.out) / "synthetic"
    out.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, dict] = {}
    for fam, fn in FAMILIES.items():
        n = args.benign_per_family if fam in BENIGN_FAMILIES else args.per_family
        for i in range(n):
            rng = Random(f"{args.seed}/{fam}/{i}")
            spec = fn(rng)
            name = f"{fam}_{i:02d}"
            packets, keyrows, truths = build_capture([spec], rng, base_ts=1_760_000_000 + i * 1000)
            write_capture(out, name, packets, keyrows)
            # Only benign captures can train the unsupervised baseline; hold ~30% of them out for testing.
            split = "train" if (fam in BENIGN_FAMILIES and i % 10 < 7) else "test"
            manifest[name] = {
                "file": f"synthetic/{name}.pcap", "keys": f"synthetic/{name}.keys" if keyrows else None,
                "provenance": "synthetic", "family": fam, "split": split, "tunnels": [asdict(t) for t in truths],
            }
    # Demo capture: one "gateway" capture with a mix of tunnels
    rng = Random(f"{args.seed}/demo")
    specs = [FAMILIES[f](rng) for f in DEMO_MIX]
    packets, keyrows, truths = build_capture(specs, rng, base_ts=1_760_500_000, spacing=9.0)
    write_capture(out, "demo_gateway_audit", packets, keyrows)
    manifest["demo_gateway_audit"] = {
        "file": "synthetic/demo_gateway_audit.pcap", "keys": "synthetic/demo_gateway_audit.keys", "provenance": "synthetic",
        "family": "demo", "split": "demo", "tunnels": [asdict(t) for t in truths],
    }
    (Path(args.out) / "manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True))
    print(f"wrote {len(manifest)} captures to {out}")


if __name__ == "__main__":
    main()
