"""Behavioural detection: retransmit-aware turnaround, half-open flood rule, benign-envelope groups.

Captures are generated on the fly by the simulator (seeded), so these tests need no committed corpus.
"""
from pathlib import Path
from random import Random

import pytest

from ipsec_analyzer.ml.features import extract
from ipsec_analyzer.ml.model import AnomalyModel
from ipsec_analyzer.pipeline import analyze
from ipsec_analyzer.rules import RuleEngine
from synth.families import FAMILIES
from synth.generate import build_capture, write_capture

ENGINE = RuleEngine()


def _analyze(tmp_path: Path, name: str, specs, seed: int = 1):
    pk, keys, _truths = build_capture(specs, Random(seed), 1_700_000_000.0)
    write_capture(tmp_path, name, pk, keys)
    return analyze(tmp_path / f"{name}.pcap", None, ENGINE)


def _tunnels(tmp_path, family: str, n: int, seed: int):
    rng = Random(seed)
    res = _analyze(tmp_path, f"{family}_{seed}", [FAMILIES[family](rng) for _ in range(n)], seed)
    return [r.tunnel for r in res.tunnels]


@pytest.fixture(scope="module")
def model(tmp_path_factory):
    d = tmp_path_factory.mktemp("train")
    benign = [t for i, f in enumerate(("b_modern", "b_acceptable", "b_multi_offer", "b_legacy_sha1", "b_v1_strong"))
              for t in _tunnels(d, f, 30, 100 + i)]
    return AnomalyModel.fit(benign, ["train"] * len(benign), ENGINE, n_estimators=100)


def test_retransmit_delay_is_not_counted_as_slow_peer(tmp_path):
    rng = Random(5)
    spec = FAMILIES["b_modern"](rng)
    spec.retransmits, spec.rtt_ms = 2, 20.0  # first request lost twice: 0.5 s + 1 s of timers before the answer
    (t,) = _tunnels_from_specs(tmp_path, [spec])
    assert t.retransmits == 2
    assert extract(t, ENGINE)["first_rtt_ms"] < 150  # measured from the last transmission, not the first


def _tunnels_from_specs(tmp_path, specs):
    return [r.tunnel for r in _analyze(tmp_path, "custom", specs).tunnels]


def test_half_open_scan_raises_flood_rule_and_benign_does_not(tmp_path):
    scan = _analyze(tmp_path, "scan", [FAMILIES["a_half_open_scan"](Random(3))])
    first = scan.tunnels[0]
    assert first.tunnel.half_open_peers >= 8
    assert "IKE-HALF-OPEN-FLOOD" in {f.rule_id for f in first.findings if f.category == "violation"}
    benign = _analyze(tmp_path, "benign", [FAMILIES["b_modern"](Random(4)) for _ in range(6)], seed=4)
    assert all(r.tunnel.half_open_peers == 0 for r in benign.tunnels)
    assert not any(f.rule_id == "IKE-HALF-OPEN-FLOOD" for r in benign.tunnels for f in r.findings)


@pytest.mark.parametrize("family,group", [
    ("a_slow_relay", "response time"),
    ("a_retransmit_burst", "retransmissions"),
    ("a_half_open_scan", "half-open handshakes"),
])
def test_envelope_group_flags_behavioural_family(tmp_path, model, family, group):
    flagged = 0
    ts = _tunnels(tmp_path, family, 6, 200)
    for t in ts:
        a = model.score(t)
        flagged += a["is_anomalous"] and a["dominant_group"] == group
    assert flagged >= 5, f"{family}: only {flagged}/6 flagged by '{group}'"


def test_envelope_explanation_is_labelled_as_not_shap(tmp_path, model):
    t = _tunnels(tmp_path, "a_slow_relay", 1, 300)[0]
    a = model.score(t)
    assert a["dominant_group"] == "response time"
    assert "not SHAP" in a["explanation"]["method"]
    assert a["explanation"]["top_features"][0]["shap"] > 1.5  # well past the benign p99 span


def test_benign_tunnels_stay_quiet_on_envelope_groups(tmp_path, model):
    env = {"response time", "retransmissions", "half-open handshakes"}
    fp = 0
    for f in ("b_modern", "b_acceptable", "b_multi_offer"):
        for t in _tunnels(tmp_path, f, 20, 400):
            a = model.score(t)
            fp += a["is_anomalous"] and a["dominant_group"] in env
    assert fp <= 1


def test_lab_scan_probe_is_parsed_and_flagged_and_evaluated(tmp_path):
    """The lab's stdlib probe builder emits packets our parser accepts; evaluate_lab judges a scan capture."""
    import json
    import os
    import sys

    from ipsec_analyzer.evaluation import evaluate_lab
    from synth import builder as B

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "lab"))
    from scan_probe import ike_sa_init

    pkts = [(1000.0 + 0.3 * i, B.ethernet(B.ipv4_udp_frame("10.99.0.2", "10.99.0.3", 500, 500,
            ike_sa_init(os.urandom(8), os.urandom(256), os.urandom(32)), 100 + i), b"\x02" * 6, b"\x04" * 6)) for i in range(12)]
    B.write_pcap(str(tmp_path / "behav_half_open_scan.pcap"), pkts)
    (tmp_path / "manifest.json").write_text(json.dumps({"behav_half_open_scan": {
        "file": "behav_half_open_scan.pcap", "label": "behavioral", "ike_version": 2, "keys": None,
        "expect_rules": ["IKE-HALF-OPEN-FLOOD"], "optional_rules": ["SA-RETRANSMIT-EXCESS"], "scan_attempts": 12}}))
    out = evaluate_lab(tmp_path, None)
    assert out["rule_level"]["tp"] == 1 and out["rule_level"]["fp"] == 0 and out["rule_level"]["fn"] == 0
    assert out["detection"]["rules"]["tp"] == 1
