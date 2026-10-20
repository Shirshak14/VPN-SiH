"""OpenVPN / WireGuard configuration analysis: what each directive triggers, that secrets never survive, and the upload endpoint."""
import importlib
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ipsec_analyzer.pipeline import analyze_vpn_config
from ipsec_analyzer.vpn import config as C

ROOT = Path(__file__).resolve().parents[2]
CFG = ROOT / "data" / "configs"
KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="  # 32 patterned bytes: not a secret


def rules_for(text, tmp_path, name="c.conf"):
    p = tmp_path / name
    p.write_text(text)
    res = analyze_vpn_config(p)
    return {f.rule_id: f.severity for f in res.vpn[0].findings if f.category == "violation"}, res


# a client that is fine except for what each case adds
OK_CLIENT = """client
remote vpn.example.com 1194
ca ca.crt
cert c.crt
key c.key
remote-cert-tls server
tls-version-min 1.2
tls-crypt tc.key
data-ciphers AES-256-GCM
"""
OK_SERVER = """server 10.8.0.0 255.255.255.0
ca ca.crt
cert s.crt
key s.key
dh none
tls-crypt tc.key
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305
crl-verify crl.pem
"""


def test_baselines_are_clean(tmp_path):
    assert rules_for(OK_CLIENT, tmp_path)[0] == {}
    assert rules_for(OK_SERVER, tmp_path)[0] == {}


@pytest.mark.parametrize("extra,rule,sev", [
    ("cipher none", "OVPN-CFG-CIPHER", "critical"),
    ("cipher BF-CBC", "OVPN-CFG-CIPHER", "high"),
    ("data-ciphers AES-256-GCM:DES-EDE3-CBC", "OVPN-CFG-CIPHER", "high"),
    ("cipher AES-256-CBC", "OVPN-CFG-CIPHER", "low"),
    ("cipher AES-256-CBC\nauth none", "OVPN-CFG-AUTH", "critical"),
    ("cipher AES-256-CBC\nauth MD5", "OVPN-CFG-AUTH", "high"),
    ("cipher AES-256-CBC\nauth SHA1", "OVPN-CFG-AUTH", "low"),
    ("tls-version-min 1.0", "OVPN-CFG-TLS-MIN", "high"),
    ('tls-cipher "DEFAULT:@SECLEVEL=0"', "OVPN-CFG-TLS-CIPHER", "medium"),
    ("tls-cipher RC4-SHA:AES128-SHA", "OVPN-CFG-TLS-CIPHER", "high"),
    ("comp-lzo", "OVPN-CFG-COMPRESS", "medium"),
    ("compress lz4-v2", "OVPN-CFG-COMPRESS", "medium"),
    ("allow-compression yes", "OVPN-CFG-COMPRESS", "medium"),
    ("reneg-sec 0", "OVPN-CFG-RENEG", "low"),
])
def test_client_directives(tmp_path, extra, rule, sev):
    base = OK_CLIENT.replace("tls-version-min 1.2\n", "") if extra.startswith("tls-version-min") else OK_CLIENT
    got, _ = rules_for(base + extra + "\n", tmp_path)
    assert got.get(rule) == sev, got


@pytest.mark.parametrize("edit,rule,sev", [
    (("tls-crypt tc.key", "tls-auth ta.key 0"), "OVPN-CFG-CTRL-PROT", "low"),
    (("tls-crypt tc.key", ""), "OVPN-CFG-CTRL-PROT", "medium"),
    (("tls-version-min 1.2", ""), "OVPN-CFG-TLS-MIN", "low"),  # unset: depends on the version in use
    (("crl-verify crl.pem", ""), "OVPN-CFG-CRL", "low"),
    (("crl-verify crl.pem", "crl-verify crl.pem\nclient-cert-not-required"), "OVPN-CFG-CLIENT-CERT", "medium"),
    (("crl-verify crl.pem", "crl-verify crl.pem\nverify-client-cert optional"), "OVPN-CFG-CLIENT-CERT", "medium"),
])
def test_server_directives(tmp_path, edit, rule, sev):
    got, _ = rules_for(OK_SERVER.replace(*edit), tmp_path)
    assert got.get(rule) == sev, got


def test_client_must_verify_the_server_certificate(tmp_path):
    got, _ = rules_for(OK_CLIENT.replace("remote-cert-tls server\n", ""), tmp_path)
    assert got["OVPN-CFG-SERVER-VERIFY"] == "high"
    for alt in ("verify-x509-name vpn.example.com name", "remote-cert-eku serverAuth", "ns-cert-type server"):
        assert "OVPN-CFG-SERVER-VERIFY" not in rules_for(OK_CLIENT.replace("remote-cert-tls server", alt), tmp_path)[0]


def test_aead_only_ciphers_make_auth_irrelevant(tmp_path):
    assert "OVPN-CFG-AUTH" not in rules_for(OK_CLIENT + "auth MD5\n", tmp_path)[0]  # --auth is ignored with GCM, so no false alarm


def test_inline_blocks_are_seen_and_secrets_are_flagged_but_never_kept(tmp_path):
    secret = "SECRETKEYMATERIAL0123456789"
    text = OK_CLIENT.replace("key c.key\n", "") + f"<key>\n-----BEGIN PRIVATE KEY-----\n{secret}\n-----END PRIVATE KEY-----\n</key>\n<tls-auth>\n{secret}2\n</tls-auth>\n"
    got, res = rules_for(text, tmp_path)
    assert got["OVPN-CFG-SECRETS"] == "info"
    assert secret not in json.dumps(res.vpn[0].tunnel.to_dict())
    red = C.redact(text)
    assert secret not in red and "<key>" in red and len(red.splitlines()) == len(text.splitlines())  # same line numbers, nothing secret
    assert C.parse_openvpn(red)["inline"]["key"]["line"] == C.parse_openvpn(text)["inline"]["key"]["line"]


def test_inline_dh_parameters_are_measured(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dh
    pem = dh.generate_parameters(generator=2, key_size=512).parameter_bytes(serialization.Encoding.PEM, serialization.ParameterFormat.PKCS3).decode()
    got, res = rules_for(OK_SERVER.replace("dh none\n", "") + f"<dh>\n{pem}</dh>\n", tmp_path)
    assert got["OVPN-CFG-DH"] == "high" and res.vpn[0].tunnel.facts["dh_bits"] == 512


def test_wireguard_rules(tmp_path):
    client = f"[Interface]\nPrivateKey = {KEY}\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = {KEY}\nPresharedKey = {KEY}\nAllowedIPs = 10.0.0.0/24\nEndpoint = vpn.example.com:51820\n"
    got, res = rules_for(client, tmp_path, "wg0.conf")
    assert set(got) == {"WG-NOT-FIPS", "WG-CFG-SECRETS"}
    assert "PrivateKey" not in json.dumps(res.vpn[0].tunnel.facts) or KEY not in json.dumps(res.vpn[0].tunnel.to_dict())
    got, _ = rules_for(client.replace(f"PresharedKey = {KEY}\n", ""), tmp_path, "wg1.conf")
    assert got["WG-CFG-NO-PSK"] == "low"
    server = f"[Interface]\nPrivateKey = {KEY}\nListenPort = 51820\n\n[Peer]\nPublicKey = {KEY}\nPresharedKey = {KEY}\nAllowedIPs = 0.0.0.0/0\n"
    assert rules_for(server, tmp_path, "wg2.conf")[0]["WG-CFG-WIDE-ALLOWEDIPS"] == "low"
    assert "WG-CFG-WIDE-ALLOWEDIPS" not in rules_for(client.replace("10.0.0.0/24", "0.0.0.0/0"), tmp_path, "wg3.conf")[0]  # a full-tunnel client is normal


def test_wireguard_keys_are_redacted_before_storage():
    text = f"[Interface]\nPrivateKey = {KEY}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {KEY}\nPresharedKey = {KEY}\nAllowedIPs = 10.0.0.0/24\n"
    red = C.redact(text)
    assert red.count(KEY) == 1 and "PublicKey" in red and red.count("<redacted>") == 2  # only the public key survives
    assert len(red.splitlines()) == len(text.splitlines())


def test_detection_rejects_other_files():
    assert C.detect("connections {\n  net {\n    version = 2\n  }\n}\n") is None  # a strongSwan swanctl.conf
    assert C.detect("hello world") is None and C.detect("") is None
    with pytest.raises(ValueError, match="not an OpenVPN or WireGuard"):
        C.parse_config("some: yaml\n")
    assert C.detect("[Interface]\nPrivateKey = x\n") == "wireguard" and C.detect("client\nremote a 1194\ndev tun\n") == "openvpn"


def test_malformed_input_never_crashes(tmp_path):
    for text in ('client\nremote "unterminated\ncipher\n', "[Interface]\n[Peer]\nbad line\nAllowedIPs\n", "client\n" + "x " * 100000, "\x00\x01client\nremote a\n"):
        try:
            rules_for(text, tmp_path)
        except ValueError:
            pass  # not recognisable is an acceptable answer; an unhandled exception is not


def test_sample_configs_say_what_they_were_written_to_say(tmp_path):
    def got(n):
        return set(rules_for((CFG / n).read_text(), tmp_path, n)[0])
    assert got("openvpn_hardened_server.conf") == set()
    assert {"OVPN-CFG-CIPHER", "OVPN-CFG-SERVER-VERIFY", "OVPN-CFG-COMPRESS", "OVPN-CFG-CTRL-PROT"} <= got("openvpn_legacy_client.ovpn")
    assert {"OVPN-CFG-TLS-MIN", "OVPN-CFG-AUTH", "OVPN-CFG-CLIENT-CERT", "OVPN-CFG-CRL", "OVPN-CFG-RENEG"} <= got("openvpn_permissive_server.conf")
    assert got("wireguard_site_gateway.conf") >= {"WG-CFG-NO-PSK", "WG-CFG-WIDE-ALLOWEDIPS"}
    assert "WG-CFG-NO-PSK" not in got("wireguard_hardened_client.conf")


# ----------------------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os
    d = tmp_path_factory.mktemp("data")
    os.environ["DATA_DIR"] = str(d)
    os.environ["DATABASE_URL"] = f"sqlite:///{d}/t.db"
    from ipsec_analyzer.api import db, gallery, main, service
    importlib.reload(db)
    importlib.reload(service)
    importlib.reload(gallery)
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c, d


def _wait(c, a):
    for _ in range(200):
        a = c.get(f"/api/analyses/{a['id']}").json()
        if a["status"] in ("done", "failed"):
            return a
        time.sleep(0.1)
    raise AssertionError("analysis did not finish")


def test_upload_a_config_end_to_end_and_no_secret_reaches_the_disk(client):
    c, d = client
    secret = "TOPSECRETPRIVATEKEYBYTES"
    text = (CFG / "openvpn_legacy_client.ovpn").read_text() + f"<key>\n{secret}\n</key>\n"
    r = c.post("/api/configs", files={"config": ("my.ovpn", text.encode())})
    assert r.status_code == 202
    a = _wait(c, r.json())
    assert a["status"] == "done" and a["summary"]["source"] == "config" and a["summary"]["tunnel_count"] == 1 and a["summary"]["vpn_tunnels"] == 1
    (t,) = c.get(f"/api/analyses/{a['id']}/tunnels").json()
    assert t["protocol"] == "OpenVPN" and {v["rule_id"] for v in t["violations"]} >= {"OVPN-CFG-CIPHER", "OVPN-CFG-SERVER-VERIFY"}
    detail = c.get(f"/api/analyses/{a['id']}/tunnels/{t['id']}").json()
    assert detail["tunnel"]["vpn"]["role"] == "client" and "OVPN-CFG-SECRETS" in {f["rule_id"] for f in detail["findings"]}
    blob = json.dumps(detail) + json.dumps(a)
    assert secret not in blob
    for f in (d / "uploads").rglob("*"):
        if f.is_file():
            assert secret not in f.read_text(errors="ignore"), f
    assert c.get(f"/api/analyses/{a['id']}/report.html").status_code == 200
    assert c.get(f"/api/analyses/{a['id']}/report.pdf").status_code == 200
    plan = c.get(f"/api/analyses/{a['id']}/remediation").json()
    assert plan and all(p["steps"] for p in plan)


def test_upload_rejects_what_is_not_a_vpn_config(client):
    c, _ = client
    r = c.post("/api/configs", files={"config": ("x.conf", b"connections {\n net {\n version = 2\n }\n}\n")})
    assert r.status_code == 400 and "OpenVPN or WireGuard" in r.json()["detail"]
    r = c.post("/api/configs", files={"config": ("big.conf", b"client\n" + b"#" * (2 << 20))})
    assert r.status_code == 413


def test_policy_endpoint_lists_both_packs(client):
    c, _ = client
    p = c.get("/api/policy").json()
    assert p["rules"] and {r["id"] for r in p["other_vpn"]["rules"]} >= {"OVPN-TLS-LEGACY", "WG-REPLAY", "OVPN-CFG-CIPHER"}
    assert all(r["remediation"]["title"] and r["refs"] for r in p["other_vpn"]["rules"])


def test_remediation_steps_are_plain_strings():
    """An unquoted 'a: b' in YAML becomes a mapping and breaks the UI; every step must be text."""
    import yaml
    from ipsec_analyzer.vpn import rules as R
    pack = yaml.safe_load(open(R.DEFAULT_PACK if hasattr(R, "DEFAULT_PACK") else "policy/other_vpn.yaml"))
    for rid, rem in (pack.get("remediations") or {}).items():
        for step in rem.get("steps", []):
            assert isinstance(step, str), (rid, step)
