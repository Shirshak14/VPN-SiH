"""OpenVPN and WireGuard analysis against REAL traffic from the lab (`lab/vpn_lab.py`), with the lab's own ground truth.

Ground truth is not read from the packets under test: for OpenVPN it is what the client's own log reported ("Control Channel: TLSv1.3, cipher
... TLS_AES_256_GCM_SHA384", "Data Channel: cipher 'AES-256-GCM'") and the options the script wrote; for WireGuard it is the configuration the
script wrote. Nothing here is hand-built bytes.
"""
import json
from pathlib import Path

import pytest

from ipsec_analyzer.parser import parse_pcap
from ipsec_analyzer.pipeline import analyze

CAP = Path(__file__).resolve().parents[2] / "data" / "captures" / "vpn"
pytestmark = pytest.mark.skipif(not (CAP / "manifest.json").exists(), reason="lab captures not present (python lab/vpn_lab.py, as root)")
MAN = json.loads((CAP / "manifest.json").read_text()) if (CAP / "manifest.json").exists() else {}
OVPN = sorted(n for n, m in MAN.items() if m["protocol"] == "OpenVPN")
WG = sorted(n for n, m in MAN.items() if m["protocol"] == "WireGuard")

# the violations a correct analysis must raise for each capture, by rule id (severity checked separately)
EXPECT = {
    "ovpn_tls13_plain": {"OVPN-CTRL-UNPROTECTED"},
    "ovpn_port_4443": {"OVPN-CTRL-UNPROTECTED"},
    "ovpn_tls13_tlscrypt": set(),
    "ovpn_tls13_tlscrypt_v2": set(),
    "ovpn_tls12_tlsauth_gcm": {"OVPN-CTRL-UNPROTECTED"},
    "ovpn_tls12_cbc_sha1": {"OVPN-CTRL-UNPROTECTED", "OVPN-TLS-CBC"},
    "ovpn_tls12_rsa_kex": {"OVPN-CTRL-UNPROTECTED", "OVPN-TLS-CBC", "OVPN-TLS-NO-PFS"},
    "ovpn_tls10_legacy": {"OVPN-CTRL-UNPROTECTED", "OVPN-TLS-CBC", "OVPN-TLS-LEGACY", "OVPN-OFFERS-LEGACY"},
    "ovpn_weak_cert": {"OVPN-CTRL-UNPROTECTED", "OVPN-CERT-WEAK"},
    "ovpn_unanswered": {"OVPN-CTRL-UNPROTECTED", "OVPN-NO-REPLY"},
    "ovpn_tls_mismatch": {"OVPN-CTRL-UNPROTECTED", "OVPN-STALLED"},
    "wg_basic": {"WG-NOT-FIPS"}, "wg_psk": {"WG-NOT-FIPS"}, "wg_rekey": {"WG-NOT-FIPS"},
    "wg_unanswered": {"WG-NOT-FIPS", "WG-NO-RESPONSE"},
}


def _vpn(name):
    return parse_pcap(CAP / f"{name}.pcap").vpn_tunnels


def test_the_manifest_and_the_expectations_cover_the_same_captures():
    assert set(EXPECT) == set(MAN)


@pytest.mark.parametrize("name", OVPN)
def test_openvpn_session_matches_the_clients_own_log(name):
    truth = MAN[name]["ground_truth"]
    (t,) = _vpn(name)  # exactly one session per capture, retries merged
    f = t.facts
    assert f["control_protection"] == truth["control_protection"]
    assert (t.status == "established") == truth["connected"], (t.status, t.failure)
    assert f["port"] == MAN[name]["port"]
    if truth["control_protection"] in ("tls-crypt", "tls-crypt-v2"):
        assert f["tls_visibility"] == "hidden" and f["tls_negotiated"] is None and f["certificate"] is None
    elif "tls_version" in truth:
        n = f["tls_negotiated"]
        assert (n["version"], n["suite"]) == (truth["tls_version"], truth["tls_cipher"])
    assert "not observable" in f["data_channel"]  # and the analysis never claims a data-channel cipher
    assert "data_cipher" not in json.dumps(f)


@pytest.mark.parametrize("name", [n for n in OVPN if "cert_key" in MAN[n]["ground_truth"]])
def test_server_certificate_is_read_from_the_wire(name):
    truth = MAN[name]["ground_truth"]
    (t,) = _vpn(name)
    c = t.facts["certificate"]
    assert f"{c['key_type']} {c['key_bits']}" == truth["cert_key"] and c["signature_hash"] == truth["cert_signature"]


@pytest.mark.parametrize("name", WG)
def test_wireguard_session_matches_the_written_configuration(name):
    truth = MAN[name]["ground_truth"]
    (t,) = _vpn(name)
    f = t.facts
    assert f["suite"] == truth["suite"] and f["negotiable"] is False
    assert (f["responses"] > 0) == truth["peer_answered"]
    assert f["handshakes_completed"] >= (truth["min_handshakes"] if truth["peer_answered"] else 0)
    assert (t.status == "established") == truth["peer_answered"]
    assert f["psk"] == "not observable on the wire"  # the analysis never guesses at the pre-shared key
    if name == "wg_rekey":  # WireGuard's own timer: REKEY_AFTER_TIME is 120 s
        assert 110 <= f["rekey_intervals_s"][0] <= 135 and f["max_key_age_s"] < 180


@pytest.mark.parametrize("name", sorted(EXPECT))
def test_findings_are_exactly_the_expected_rules(name):
    res = analyze(CAP / f"{name}.pcap")
    assert res.tunnels == [] and len(res.vpn) == 1  # no IPsec tunnel is invented
    r = res.vpn[0]
    got = {f.rule_id for f in r.findings if f.category == "violation"}
    assert got == EXPECT[name], (name, got ^ EXPECT[name])
    for f in r.findings:
        assert f.description
        if f.category == "violation":  # every violation names its sources and its fix; coverage notes are statements of what is unseen
            assert f.refs and f.remediation.get("steps")


def test_severities_and_scores_order_sensibly():
    def score(n):
        return analyze(CAP / f"{n}.pcap").vpn[0]
    assert {f.rule_id: f.severity for f in score("ovpn_tls10_legacy").findings}["OVPN-TLS-LEGACY"] == "high"
    assert {f.rule_id: f.severity for f in score("ovpn_tls12_rsa_kex").findings}["OVPN-TLS-NO-PFS"] == "high"
    assert score("ovpn_tls13_tlscrypt").risk.score == 0.0 and score("wg_rekey").risk.score == 0.0
    assert score("ovpn_tls13_tlscrypt").risk.score < score("ovpn_tls13_plain").risk.score < score("ovpn_tls10_legacy").risk.score
    assert score("ovpn_tls12_tlsauth_gcm").risk.score < score("ovpn_tls13_plain").risk.score  # tls-auth authenticates, plain does not


def test_inventory_still_counts_what_the_trackers_saw():
    for name in ("ovpn_port_4443", "ovpn_tls13_tlscrypt", "wg_rekey"):  # the port-4443 session is found although the old inventory only looked at UDP/1194
        inv = parse_pcap(CAP / f"{name}.pcap").stats.other_vpn
        assert len(inv) == 1 and inv[0]["packets"] >= 20
    assert parse_pcap(CAP / "wg_rekey.pcap").stats.other_vpn[0]["protocol"] == "WireGuard"


def test_timeline_labels_the_handshake_messages_from_the_wire():
    (t,) = _vpn("ovpn_tls12_cbc_sha1")
    labels = " | ".join(e["label"] for e in t.timeline)
    for msg in ("Hard reset (client)", "Hard reset (server)", "ClientHello", "ServerHello", "Certificate", "ServerKeyExchange", "ChangeCipherSpec", "Data channel opens"):
        assert msg in labels, msg
    (w,) = _vpn("wg_rekey")
    kinds = [e["label"].split(" ×")[0] for e in w.timeline]
    assert kinds.count("Handshake initiation") == 3 and kinds.count("Handshake response") == 2
