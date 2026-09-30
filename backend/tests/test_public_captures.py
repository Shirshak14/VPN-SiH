"""Parser + rule engine validated on REAL third-party captures (Wireshark test suite)."""
from pathlib import Path

import pytest

from ipsec_analyzer.evaluation import validate_public
from ipsec_analyzer.pipeline import analyze
from ipsec_analyzer.rules import RuleEngine

PUBLIC = Path(__file__).resolve().parents[2] / "data" / "public"
KEYS = PUBLIC / "ikev2_decryption_table.tmpl"


def test_all_independent_oracle_checks_pass():
    r = validate_public(PUBLIC)
    failed = [c for c in r["checks"] if not c["ok"]]
    assert not failed, failed


def _rules(name, keys=None):
    res = analyze(PUBLIC / name, keys, RuleEngine())
    return {f.rule_id for t in res.tunnels for f in t.findings if f.category == "violation"}


def test_openswan_default_ikev1_flagged():
    assert {"IKE-ENC-WEAK", "IKE-DH-WEAK", "IKE-INTEG-WEAK", "IKE-V1-LEGACY"} <= _rules("ikev1-certs.pcap")


def test_real_aggressive_mode_psk_flagged():
    assert "IKE-AGGR-PSK" in _rules("ikev1-bug-12620.pcapng")


def test_real_3des_ikev2_flagged_with_keys():
    assert "IKE-ENC-WEAK" in _rules("ikev2-decrypt-3des-sha1_160.pcap", KEYS)


def test_without_keys_reports_coverage_gap_not_false_clean():
    res = analyze(PUBLIC / "ikev2-decrypt-aes256cbc.pcapng", None, RuleEngine())
    assert any(f.rule_id == "COV-IKEV2-ENCRYPTED" for f in res.tunnels[0].findings)


def test_malformed_datagram_is_counted_not_fatal(tmp_path):
    from synth import builder as B
    junk = B.ipv4_udp_frame("10.0.0.1", "10.0.0.2", 500, 500, b"\x00" * 40, 1)
    B.write_pcap(str(tmp_path / "j.pcap"), [(1.0, B.ethernet(junk, b"\x02" * 6, b"\x04" * 6))])
    from ipsec_analyzer.parser import parse_pcap
    cap = parse_pcap(tmp_path / "j.pcap")
    assert cap.stats.ike_malformed == 1 and not cap.ike
