"""OpenVPN and WireGuard situations the lab cannot produce on demand, built byte-exactly (see synth/vpn_builder.py).

Every scenario goes through the real path: pcap -> parse_pcap -> trackers -> rules -> risk.
"""
import datetime as dt
from pathlib import Path

import pytest

from ipsec_analyzer.pipeline import analyze
from ipsec_analyzer.vpn.rules import load_pack
from synth import vpn_builder as V

C, S = ("198.51.100.1", 40001), ("198.51.100.2", 1194)
T0 = 1_760_000_000.0


def run(tmp_path: Path, pkts, name="s.pcap"):
    return analyze(V.udp_pcap(tmp_path / name, pkts))


def fired(res, tunnel=0):
    return {f.rule_id: f.severity for f in res.vpn[tunnel].findings if f.category == "violation"}


def coverage(res, tunnel=0):
    return {f.rule_id for f in res.vpn[tunnel].findings if f.category == "coverage"}


def tls12_session(suite, t0=T0, server=S, client=C, kx=None, certs=None, client_suites=(0xC02F, 0x009F), **kw):
    """TLS 1.2 handshake: ClientHello, then ServerHello (+Certificate +ServerKeyExchange) as separate records."""
    srv = [V.server_hello(suite)]
    if certs:
        srv.append(V.certificate_msg(certs))
    if kx:
        srv.append(kx)
    return V.ovpn_session(t0, client, server, [V.client_hello((0x0303,), client_suites)], srv, **kw)


# ----------------------------------------------------------------------------- scenarios (also reused by the coverage test)
def scn_dhe_small(tmp_path, bits=1024):
    return run(tmp_path, tls12_session(0x009F, kx=V.server_kx_dhe(bits)))


def scn_null_suite(tmp_path, suite=0x003B):
    return run(tmp_path, tls12_session(suite, client_suites=(0xC02F, suite)))


def scn_alert(tmp_path):
    return run(tmp_path, V.ovpn_session(T0, C, S, [V.client_hello((0x0303,), (0xC02F,))], [V.alert(70)], data=(0, 0)))


def scn_no_reneg(tmp_path, rekey=False):
    pk = V.ovpn_session(T0, C, S, [V.client_hello((0x0303,), (0xC02F,))], [V.server_hello(0xC02F)], data=(3, 3), data_span_s=8000.0)
    if rekey:
        pk.append((T0 + 3600, C[0], C[1], S[0], S[1], V.ovpn_data(kid=1)))
    return run(tmp_path, pk)


def scn_legacy_offer(tmp_path):
    return run(tmp_path, V.ovpn_session(T0, C, S, [V.client_hello((0x0304, 0x0302, 0x0301), (0x1302, 0xC014, 0x000A, 0x0005))],
                                        [V.server_hello(0x1302, version=0x0304)]))


def _cert(bits=2048, not_after=None):  # the library will not sign with SHA-1; the lab capture ovpn_weak_cert covers that case with a real certificate
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(65537, bits)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "vpn.test")])
    now = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
         .not_valid_before((not_after or now) - dt.timedelta(days=365)).not_valid_after(not_after or now + dt.timedelta(days=300)))
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def scn_cert(tmp_path, **kw):
    return run(tmp_path, tls12_session(0xC02F, certs=[_cert(**kw)], kx=V.server_kx_ecdhe()))


def wg_flow(t0=T0, a=("203.0.113.1", 51820), b=("203.0.113.2", 51820), rekey_at=None, data_until=20.0, dup=0, extra=None):
    """Initiation, response, then data both ways every second until `data_until` seconds after the response."""
    pk = [(t0, *a, *b, V.wg_init(0x11))]
    pk.append((t0 + 0.02, *b, *a, V.wg_resp(0x22, 0x11)))
    n = 0
    t = t0 + 0.5
    while t - t0 <= data_until:
        n += 1
        pk.append((t, *a, *b, V.wg_data(0x22, n)))
        pk.append((t + 0.001, *b, *a, V.wg_data(0x11, n)))
        t += 1.0
    for i in range(dup):  # the same counter again
        pk.append((t0 + 1.2 + i * 0.01, *a, *b, V.wg_data(0x22, 1)))
    pk += extra or []
    return pk


def scn_wg_clean(tmp_path):
    return run(tmp_path, wg_flow())


def scn_wg_stale(tmp_path):
    return run(tmp_path, wg_flow(data_until=200.0))


def scn_wg_replay(tmp_path):
    return run(tmp_path, wg_flow(data_until=60.0, dup=8))


def scn_wg_flood(tmp_path):
    a, b = ("203.0.113.1", 51820), ("203.0.113.2", 51820)
    return run(tmp_path, [(T0 + i, *a, *b, V.wg_init(0x100 + i)) for i in range(8)])


def scn_wg_cookie(tmp_path):
    a, b = ("203.0.113.1", 51820), ("203.0.113.2", 51820)
    return run(tmp_path, wg_flow(extra=[(T0 + 0.3, *b, *a, V.wg_cookie(0x11))]))


def scn_wg_roam(tmp_path):
    a, b = ("203.0.113.1", 51820), ("203.0.113.2", 51820)
    return run(tmp_path, wg_flow(extra=[(T0 + 5.5, "192.0.2.77", 40000, *b, V.wg_data(0x22, 1000))]))


SCENARIOS = {
    "dhe_small": scn_dhe_small, "null_suite": scn_null_suite, "alert": scn_alert, "no_reneg": scn_no_reneg, "legacy_offer": scn_legacy_offer,
    "cert_weak": lambda p: scn_cert(p, bits=1024), "wg_clean": scn_wg_clean, "wg_stale": scn_wg_stale, "wg_replay": scn_wg_replay,
    "wg_flood": scn_wg_flood, "wg_cookie": scn_wg_cookie, "wg_roam": scn_wg_roam,
}


# ----------------------------------------------------------------------------- OpenVPN wire-level
def test_dhe_prime_size_is_read_from_server_key_exchange(tmp_path):
    for bits, sev in ((512, "high"), (1024, "medium"), (2048, None)):
        res = scn_dhe_small(tmp_path, bits)
        neg = res.vpn[0].tunnel.facts["tls_negotiated"]
        assert neg["suite"] == "DHE-RSA-AES256-GCM-SHA384" and neg["dh_bits"] == bits
        assert fired(res).get("OVPN-DHE-WEAK") == sev


@pytest.mark.parametrize("suite,problem,sev", [(0x003B, "null_cipher", "critical"), (0x0005, "rc4", "critical"), (0x000A, "3des", "high"),
                                              (0x0004, "rc4", "critical"), (0x0008, "export", "critical")])
def test_broken_suites_are_graded(tmp_path, suite, problem, sev):
    res = scn_null_suite(tmp_path, suite)
    assert problem in res.vpn[0].tunnel.facts["tls_negotiated"]["issues"]
    assert fired(res)["OVPN-TLS-SUITE-WEAK"] == sev


def test_plaintext_alert_fails_the_handshake(tmp_path):
    res = scn_alert(tmp_path)
    t = res.vpn[0].tunnel
    assert t.status == "failed" and "protocol_version" in t.failure
    assert fired(res)["OVPN-TLS-ALERT"] == "low"


def test_tls13_hides_the_certificate_and_says_so(tmp_path):
    res = scn_legacy_offer(tmp_path)
    f = res.vpn[0].tunnel.facts
    assert f["tls_negotiated"]["version"] == "TLSv1.3" and f["tls_negotiated"]["suite"] == "TLS_AES_256_GCM_SHA384" and f["certificate"] is None
    assert "COV-OVPN-CERT-TLS13" in coverage(res)
    # the client still offers TLS 1.0 / 1.1 and RC4 / 3DES even though the server picked TLS 1.3
    assert fired(res)["OVPN-OFFERS-LEGACY"] == "low"
    off = f["tls_offered"]
    assert off["min_version"] == "TLSv1" and {"RC4-SHA", "DES-CBC3-SHA"} <= set(off["weak_suites"])


def test_certificate_checks(tmp_path):
    bad = scn_cert(tmp_path, bits=1024)
    assert fired(bad)["OVPN-CERT-WEAK"] == "high"  # 1024-bit RSA: below the 2048-bit minimum (critical is reserved for keys under 1024 bits)
    assert bad.vpn[0].tunnel.facts["certificate"]["key_bits"] == 1024
    assert "OVPN-CERT-WEAK" not in fired(scn_cert(tmp_path))
    expired = scn_cert(tmp_path, not_after=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc))
    assert fired(expired)["OVPN-CERT-WEAK"] == "medium"
    assert expired.vpn[0].tunnel.facts["certificate"]["expired_at_capture"]


def test_session_on_any_port_and_protection_detection(tmp_path):
    ch = [V.client_hello((0x0303,), (0xC02F,))]
    sh = [V.server_hello(0xC02F)]
    expect = {"none": "none", "tls-auth": "tls-auth", "tls-crypt": "tls-crypt", "tls-crypt-v2": "tls-crypt-v2"}
    for wrap, want in expect.items():
        res = run(tmp_path, V.ovpn_session(T0, ("10.1.1.1", 50000), ("10.2.2.2", 7777), ch, sh, wrap=wrap))
        f = res.vpn[0].tunnel.facts
        assert f["control_protection"] == want and f["port"] == 7777 and res.vpn[0].tunnel.status == "established", wrap
    for h in ("sha1", "sha256", "sha512"):  # all three tls-auth digest sizes, including the one that has the same length as a tls-crypt reset
        res = run(tmp_path, V.ovpn_session(T0, ("10.1.1.1", 50000), ("10.2.2.2", 7777), ch, sh, wrap="tls-auth", hmac=h))
        assert res.vpn[0].tunnel.facts["control_protection"] == "tls-auth", h
        assert res.vpn[0].tunnel.facts["tls_negotiated"]["suite"] == "ECDHE-RSA-AES128-GCM-SHA256", h


def test_wrapped_reset_is_only_claimed_with_a_reply_or_the_default_port(tmp_path):
    ch, sh = [V.client_hello()], [V.server_hello(0x1302, 0x0304)]
    off_port = V.ovpn_session(T0, ("10.1.1.1", 50000), ("10.2.2.2", 7777), ch, sh, wrap="tls-crypt", answered=False)
    assert run(tmp_path, off_port).vpn == []  # one tls-crypt-shaped datagram on a random port proves nothing
    on_default = V.ovpn_session(T0, ("10.1.1.1", 50000), ("10.2.2.2", 1194), ch, sh, wrap="tls-crypt", answered=False)
    res = run(tmp_path, on_default)
    assert res.vpn[0].tunnel.status == "failed" and "OVPN-NO-REPLY" in fired(res)
    plain = V.ovpn_session(T0, ("10.1.1.1", 50000), ("10.2.2.2", 7777), ch, sh, answered=False)
    assert run(tmp_path, plain).vpn[0].tunnel.facts["server_answered"] is False  # an unprotected reset is exact enough to claim anywhere


def test_random_udp_is_not_openvpn(tmp_path):
    import os
    pk = [(T0 + i * 0.01, "10.0.0.1", 40000, "10.0.0.2", 4444, bytes([0x38]) + os.urandom(13 + i % 3)) for i in range(20)]
    pk += [(T0 + 1 + i * 0.01, "10.0.0.2", 4444, "10.0.0.1", 40000, bytes([0x40]) + os.urandom(25)) for i in range(5)]
    res = run(tmp_path, pk)
    assert res.vpn == []


def test_repeated_unanswered_attempts_are_one_finding(tmp_path):
    pk = []
    for i in range(4):  # a client retries from a new socket and session id each time
        pk += V.ovpn_session(T0 + i * 5, ("198.51.100.1", 40000 + i), S, [], [], answered=False)
    res = run(tmp_path, pk)
    assert len(res.vpn) == 1
    t = res.vpn[0].tunnel
    assert t.facts["attempts"] == 4 and t.facts["client_resets"] == 4 and "4 connection attempts" in t.failure.replace("over ", "")
    assert "OVPN-NO-REPLY" in fired(res)


def test_handshake_split_across_packets_and_with_duplicates_and_gaps(tmp_path):
    ch = V.client_hello((0x0303,), (0xC02F,))
    sh = V.server_hello(0xC02F) + V.certificate_msg([_cert()]) + V.server_kx_ecdhe()
    cut = [sh[:100], sh[100:700], sh[700:]]  # records straddle packet boundaries
    pk = V.ovpn_session(T0, C, S, [ch], cut)
    dup = [p for p in pk if p[5][0] >> 3 == 4][-1]
    pk.append((dup[0] + 0.001, *dup[1:]))  # a retransmitted control packet
    res = run(tmp_path, pk)
    f = res.vpn[0].tunnel.facts
    assert f["tls_negotiated"]["suite"] == "ECDHE-RSA-AES128-GCM-SHA256" and f["certificate"]["key_bits"] == 2048 and f["tls_negotiated"]["group"] == "x25519"
    assert any(e["retransmit"] for e in res.vpn[0].tunnel.timeline)
    # a lost packet: the stream is read up to the gap, nothing crashes
    lost = V.ovpn_session(T0, C, S, [ch], cut)
    lost = [p for p in lost if not (p[5][0] >> 3 == 4 and p[1] == S[0] and int.from_bytes(p[5][-len(cut[1]) - 4:-len(cut[1])], "big") == 2)]
    res = run(tmp_path, lost)
    assert res.vpn[0].tunnel.facts["tls_negotiated"]["suite"] == "ECDHE-RSA-AES128-GCM-SHA256"


def test_long_lived_key_without_renegotiation(tmp_path):
    assert fired(scn_no_reneg(tmp_path))["OVPN-NO-RENEG"] == "low"
    res = scn_no_reneg(tmp_path, rekey=True)
    assert res.vpn[0].tunnel.facts["renegotiations"] == 1 and "OVPN-NO-RENEG" not in fired(res)


# ----------------------------------------------------------------------------- WireGuard wire-level
def test_wireguard_clean_session_has_no_violation(tmp_path):
    res = scn_wg_clean(tmp_path)
    f = res.vpn[0].tunnel.facts
    assert res.vpn[0].tunnel.status == "established" and f["handshakes_completed"] == 1 and f["transport_packets"]["i2r"] > 10
    assert set(fired(res)) == {"WG-NOT-FIPS"} and "COV-WG-PSK" in coverage(res)


def test_wireguard_key_used_past_reject_after_time(tmp_path):
    res = scn_wg_stale(tmp_path)
    assert fired(res)["WG-STALE-KEYS"] == "medium" and res.vpn[0].tunnel.facts["max_key_age_s"] >= 185


def test_wireguard_repeated_counters(tmp_path):
    res = scn_wg_replay(tmp_path)
    assert fired(res)["WG-REPLAY"] == "high" and res.vpn[0].tunnel.facts["counter_duplicates"] == 8
    assert "WG-REPLAY" not in fired(scn_wg_clean(tmp_path))


def test_wireguard_initiation_flood_and_silence(tmp_path):
    res = scn_wg_flood(tmp_path)
    assert fired(res)["WG-INIT-FLOOD"] == "medium" and fired(res)["WG-NO-RESPONSE"] == "low"
    assert res.vpn[0].tunnel.status == "failed"


def test_wireguard_cookie_replies_and_roaming(tmp_path):
    assert fired(scn_wg_cookie(tmp_path))["WG-COOKIE-LOAD"] == "low"
    res = scn_wg_roam(tmp_path)
    assert fired(res)["WG-ENDPOINT-CHANGE"] == "info" and res.vpn[0].tunnel.facts["roamed_endpoints"] == ["192.0.2.77:40000"]


def test_wireguard_lookalikes_and_a_response_without_its_initiation(tmp_path):
    a, b = ("203.0.113.1", 51820), ("203.0.113.2", 51820)
    # right type byte, wrong handshake length; and transport-shaped packets whose receiver index no handshake announced
    junk = [(T0, *a, *b, V.wg_init(1) + b"\x00"), (T0 + 1, *a, *b, V.wg_data(0x99, 1, 64)), (T0 + 2, *b, *a, V.wg_data(0x98, 1, 32))]
    assert run(tmp_path, junk).vpn == []
    res = run(tmp_path, [(T0, *b, *a, V.wg_resp(0x22, 0x11)), (T0 + 1, *a, *b, V.wg_data(0x22, 1)), (T0 + 1.1, *b, *a, V.wg_data(0x11, 1))])
    assert res.vpn[0].tunnel.facts["initiation_not_captured"] and "COV-WG-NO-INIT" in coverage(res)


# ----------------------------------------------------------------------------- the policy pack and coverage
def test_every_rule_in_the_pack_is_exercised_by_a_capture_or_a_synthetic_scenario(tmp_path):
    root = Path(__file__).resolve().parents[2] / "data"
    seen: set[str] = set()
    for name, fn in SCENARIOS.items():
        d = tmp_path / name
        d.mkdir()
        for r in fn(d).vpn:
            seen |= {f.rule_id for f in r.findings if f.category == "violation"}
    for pcap in sorted((root / "captures" / "vpn").glob("*.pcap")):
        for r in analyze(pcap).vpn:
            seen |= {f.rule_id for f in r.findings if f.category == "violation"}
    from ipsec_analyzer.pipeline import analyze_vpn_config
    for cfg in sorted((root / "configs").glob("*")):
        for r in analyze_vpn_config(cfg).vpn:
            seen |= {f.rule_id for f in r.findings if f.category == "violation"}
    # a private key inside a config cannot be shipped in the repository, and a DH block needs generating: both are built at run time in test_vpn_config.py
    exempt = {"OVPN-CFG-DH", "OVPN-CFG-SECRETS"}
    missing = {r["id"] for r in load_pack()["rules"]} - seen - exempt
    assert not missing, f"rules never fired by any test input: {sorted(missing)}"


def test_pack_is_consistent():
    pack = load_pack()
    ids = [r["id"] for r in pack["rules"]]
    assert len(ids) == len(set(ids))
    for r in pack["rules"]:
        assert r["refs"] and r["description"].strip() and pack["remediations"][r["remediation"]]["steps"], r["id"]
        assert all(m in pack["mitre_catalog"] for m in r.get("mitre", []))


def test_pack_loader_rejects_unknown_checks(tmp_path):
    from ipsec_analyzer.rules.policy import PolicyError
    bad = tmp_path / "bad.yaml"
    bad.write_text(Path(__file__).resolve().parents[1].joinpath("policy/other_vpn.yaml").read_text().replace("check: wg_replay", "check: nope"))
    with pytest.raises(PolicyError, match="unknown check"):
        load_pack(bad)
