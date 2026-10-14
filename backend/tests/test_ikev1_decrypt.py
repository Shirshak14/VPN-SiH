"""IKEv1 key-assisted decryption, validated on real Wireshark-suite captures (no synthetic ciphertext, so the IV logic is
not checked against itself): every encrypted message must open into a valid payload chain, and Quick Mode becomes assessable."""
from pathlib import Path

from ipsec_analyzer.parser import parse_pcap
from ipsec_analyzer.parser.decrypt import IkeV1Key, load_key_table
from ipsec_analyzer.pipeline import analyze
from ipsec_analyzer.rules import RuleEngine

PUBLIC = Path(__file__).resolve().parents[2] / "data" / "public"
KEYS = PUBLIC / "ikev1_decryption_table.tmpl"


def _tunnel(name, keys=KEYS):
    (res,) = analyze(PUBLIC / name, keys, RuleEngine()).tunnels
    return res, {f.rule_id for f in res.findings if f.category == "violation"}, {f.rule_id for f in res.findings if f.category == "coverage"}


def test_key_table_has_three_ikev1_rows():
    rows = load_key_table(KEYS)
    assert len(rows) == 3 and all(isinstance(r, IkeV1Key) and len(r.ispi) == 8 for r in rows)


def test_every_encrypted_message_opens_in_all_three_captures():
    keys = load_key_table(KEYS)
    for name in ("ikev1-certs.pcap", "ikev1-bug-12610.pcapng", "ikev1-bug-12620.pcapng"):
        enc = [m for m in parse_pcap(PUBLIC / name, keys=keys).ike if m.encrypted_v1]
        assert enc and all(m.decrypted is not None and m.decrypt_error is None for m in enc), name


def test_quick_mode_in_cert_capture_is_3des_md5_with_pfs():
    res, rules, cov = _tunnel("ikev1-certs.pcap")
    (child,) = res.tunnel.child_sas
    assert child.via == "Quick Mode" and child.pfs and child.suite.label() == "3DES/HMAC_MD5/MODP_1024"
    assert {"ESP-ENC-WEAK", "ESP-INTEG-WEAK"} <= rules and "ESP-NO-PFS" not in rules
    assert "COV-IKEV1-PHASE2" not in cov


def test_quick_mode_without_ke_payload_is_flagged_no_pfs():
    res, rules, _ = _tunnel("ikev1-bug-12610.pcapng")
    (child,) = res.tunnel.child_sas
    assert not child.pfs and child.suite.encr == "AES_CBC" and child.suite.integ == "HMAC_SHA1"
    assert {"ESP-NO-PFS", "ESP-INTEG-WEAK"} <= rules


def test_without_keys_quick_mode_is_a_coverage_gap_not_a_clean_bill():
    res, rules, cov = _tunnel("ikev1-bug-12610.pcapng", keys=None)
    assert "COV-IKEV1-PHASE2" in cov and not (rules & {"ESP-NO-PFS", "ESP-INTEG-WEAK", "ESP-ENC-WEAK"})
    assert not res.tunnel.child_observable


def test_wrong_key_is_reported_not_guessed(tmp_path):
    bad = tmp_path / "bad.tmpl"
    bad.write_text("ab3e0f1f8bc3be8e," + "00" * 32 + "\n")
    res, rules, cov = _tunnel("ikev1-bug-12610.pcapng", keys=bad)
    assert "COV-IKEV1-PHASE2" in cov and not res.tunnel.child_sas
    assert any("Decryption was attempted but failed" in n for n in res.tunnel.notes)
    cap = parse_pcap(PUBLIC / "ikev1-bug-12610.pcapng", keys=load_key_table(bad))
    assert all(m.decrypt_error for m in cap.ike if m.encrypted_v1)
