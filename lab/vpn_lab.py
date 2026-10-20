"""Real WireGuard and OpenVPN traffic for the analyzer, with ground truth, on one Linux host (no Docker).

Two network namespaces joined by a veth pair stand in for two machines; `tcpdump` runs on the client side. WireGuard
uses `wireguard-go` (no kernel module needed), OpenVPN is the stock daemon. Every scenario writes a pcap plus its
ground truth, taken from what OpenVPN itself logged ("Control Channel: TLSv1.3, cipher ...", "Data Channel: cipher
...") or from the configuration this script wrote, to `data/captures/vpn/manifest.json`.

    sudo python lab/vpn_lab.py                    # all scenarios, ~6 minutes
    sudo python lab/vpn_lab.py ovpn_tls13_plain   # just one

Needs root and: openvpn (2.6), wireguard-go, wireguard-tools (`wg`), tcpdump, iproute2, iputils-ping, openssl.
Certificates and keys are throw-away and live in a temp directory; only pcaps, sanitised configs (no private keys) and the
manifest are written to the repository. Captures contain only the lab's own traffic.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "captures" / "vpn"
NS_A, NS_B = "vpn-a", "vpn-b"
IP_A, IP_B = "198.51.100.1", "198.51.100.2"


def sh(*a: str, ns: str | None = None, check: bool = True, **kw) -> subprocess.CompletedProcess:
    cmd = ["ip", "netns", "exec", ns, *a] if ns else list(a)
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(cmd)}\n{r.stdout}{r.stderr}")
    return r


def setup_net() -> None:
    teardown_net()
    sh("ip", "netns", "add", NS_A)
    sh("ip", "netns", "add", NS_B)
    sh("ip", "link", "add", "va", "type", "veth", "peer", "name", "vb")
    sh("ip", "link", "set", "va", "netns", NS_A)
    sh("ip", "link", "set", "vb", "netns", NS_B)
    for ns, dev, ip in ((NS_A, "va", IP_A), (NS_B, "vb", IP_B)):
        sh("ip", "addr", "add", f"{ip}/24", "dev", dev, ns=ns)
        sh("ip", "link", "set", dev, "up", ns=ns)
        sh("ip", "link", "set", "lo", "up", ns=ns)


def teardown_net() -> None:
    subprocess.run(["pkill", "-f", "wireguard-go"], capture_output=True)
    subprocess.run(["pkill", "-x", "openvpn"], capture_output=True)
    subprocess.run(["pkill", "-INT", "-x", "tcpdump"], capture_output=True)
    for ns in (NS_A, NS_B):
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
    time.sleep(0.3)


class Capture:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.p = subprocess.Popen(["ip", "netns", "exec", NS_A, "tcpdump", "-i", "va", "-U", "-w", str(path), "udp"],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)

    def stop(self) -> None:
        time.sleep(0.8)
        self.p.send_signal(signal.SIGINT)
        self.p.wait(timeout=10)
        subprocess.run(["chmod", "644", str(self.path)])


# ----------------------------------------------------------------------------- OpenVPN
def pki(d: Path) -> None:
    def run(*a: str) -> None:
        subprocess.run(a, cwd=d, check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=Lab CA", "-days", "30", "-sha256")
    for n in ("server", "client"):
        eku = f"{n}Auth"  # serverAuth / clientAuth extended key usage
        (d / f"{n}.ext").write_text(f"basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage={eku}\n")
        run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{n}.key", "-out", f"{n}.csr", "-subj", f"/CN={n}")
        run("openssl", "x509", "-req", "-in", f"{n}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", f"{n}.crt", "-days", "30", "-sha256", "-extfile", f"{n}.ext")
    run("openssl", "req", "-newkey", "rsa:1024", "-nodes", "-keyout", "server_weak.key", "-out", "server_weak.csr", "-subj", "/CN=server")
    run("openssl", "x509", "-req", "-in", "server_weak.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", "server_weak.crt", "-days", "30", "-sha1", "-extfile", "server.ext")
    run("openvpn", "--genkey", "secret", "ta.key")
    run("openvpn", "--genkey", "tls-crypt-v2-server", "tcv2-server.key")
    run("openvpn", "--tls-crypt-v2", "tcv2-server.key", "--genkey", "tls-crypt-v2-client", "tcv2-client.key")


@dataclass
class OvpnScenario:
    name: str
    description: str
    server: list[str] = field(default_factory=list)
    client: list[str] = field(default_factory=list)
    port: int = 1194
    server_up: bool = True  # False: the client talks to nothing
    expect: dict = field(default_factory=dict)  # control_protection etc. (what this script configured)
    seconds: int = 12
    server_cert: str = "server"  # basename of the server certificate / key pair in the lab PKI


OVPN: list[OvpnScenario] = [
    OvpnScenario("ovpn_tls13_plain", "OpenVPN 2.6, TLS 1.3, no tls-auth/tls-crypt: control channel readable", expect={"control_protection": "none"}),
    OvpnScenario("ovpn_tls13_tlscrypt", "OpenVPN 2.6, TLS 1.3, tls-crypt: control channel encrypted", ["tls-crypt ta.key"], ["tls-crypt ta.key"], expect={"control_protection": "tls-crypt"}),
    OvpnScenario("ovpn_tls13_tlscrypt_v2", "OpenVPN 2.6, TLS 1.3, tls-crypt-v2 (per-client key)", ["tls-crypt-v2 tcv2-server.key"], ["tls-crypt-v2 tcv2-client.key"], expect={"control_protection": "tls-crypt-v2"}),
    OvpnScenario("ovpn_tls12_tlsauth_gcm", "OpenVPN 2.6, TLS 1.2 ECDHE-RSA-AES256-GCM, tls-auth (HMAC only: control channel readable)",
                 ["tls-auth ta.key 0", "tls-version-max 1.2", "tls-cipher ECDHE-RSA-AES256-GCM-SHA384"], ["tls-auth ta.key 1", "tls-version-max 1.2"], expect={"control_protection": "tls-auth"}),
    OvpnScenario("ovpn_tls12_cbc_sha1", "OpenVPN 2.6, TLS 1.2 with ECDHE-RSA-AES128-SHA (CBC + SHA-1 suite)", ["tls-version-max 1.2", "tls-cipher ECDHE-RSA-AES128-SHA"], ["tls-version-max 1.2"], expect={"control_protection": "none"}),
    OvpnScenario("ovpn_tls12_rsa_kex", "OpenVPN 2.6, TLS 1.2 with AES128-SHA (static RSA key exchange: no forward secrecy)", ["tls-version-max 1.2", "tls-cipher AES128-SHA"], ["tls-version-max 1.2", "tls-cipher AES128-SHA"], expect={"control_protection": "none"}),
    OvpnScenario("ovpn_tls10_legacy", "OpenVPN 2.6 forced to TLS 1.0 (seclevel 0)", ["tls-version-min 1.0", "tls-version-max 1.0", "tls-cipher DEFAULT:@SECLEVEL=0"],
                 ["tls-version-min 1.0", "tls-version-max 1.0", "tls-cipher DEFAULT:@SECLEVEL=0"], expect={"control_protection": "none"}),
    OvpnScenario("ovpn_port_4443", "OpenVPN 2.6, TLS 1.3, plain control channel on UDP/4443 (not the default port)", port=4443, expect={"control_protection": "none"}),
    OvpnScenario("ovpn_tls_mismatch", "OpenVPN 2.6: client requires TLS 1.3, server is capped at TLS 1.2: the handshake never completes",
                 ["tls-version-max 1.2"], ["tls-version-min 1.3"], expect={"control_protection": "none"}),
    OvpnScenario("ovpn_weak_cert", "OpenVPN 2.6, TLS 1.2, server certificate with a 1024-bit RSA key signed with SHA-1 (security level lowered to 0)",
                 ["tls-version-max 1.2", "tls-cipher ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0"], ["tls-version-max 1.2", "tls-cipher ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0"],
                 server_cert="server_weak", expect={"control_protection": "none", "cert_key": "RSA 1024", "cert_signature": "sha1"}),
    OvpnScenario("ovpn_unanswered", "OpenVPN client whose server is not running: hard-reset retries only", server_up=False, seconds=14, expect={"control_protection": "none"}),
]


def run_ovpn(sc: OvpnScenario, tmp: Path) -> dict:
    d = tmp / "ovpn"
    server_conf = "\n".join(["dev tun", "proto udp", f"port {sc.port}", "server 10.8.0.0 255.255.255.0", "ca ca.crt", f"cert {sc.server_cert}.crt", f"key {sc.server_cert}.key",
                             *([] if any(x.startswith("dh ") for x in sc.server) else ["dh none"]), "keepalive 2 10", "verb 3", *sc.server])
    client_conf = "\n".join(["client", "dev tun", "proto udp", f"remote {IP_B} {sc.port}", "nobind", "ca ca.crt", "cert client.crt", "key client.key",
                             "remote-cert-tls server", "verb 3", "connect-retry 2", "connect-timeout 4", *sc.client])
    (d / "s.conf").write_text(server_conf)
    (d / "c.conf").write_text(client_conf)
    pcap = OUT / f"{sc.name}.pcap"
    cap = Capture(pcap)
    try:
        if sc.server_up:
            sh("openvpn", "--cd", str(d), "--config", "s.conf", "--daemon", "--log", str(d / "s.log"), ns=NS_B)
            time.sleep(1.0)
        sh("openvpn", "--cd", str(d), "--config", "c.conf", "--daemon", "--log", str(d / "c.log"), ns=NS_A)
        time.sleep(5)
        if sc.server_up:
            sh("ping", "-c", str(max(3, sc.seconds - 7)), "-i", "1", "-W", "1", "10.8.0.1", ns=NS_A, check=False)
        else:
            time.sleep(sc.seconds - 5)
    finally:
        cap.stop()
        subprocess.run(["pkill", "-x", "openvpn"], capture_output=True)
        time.sleep(0.5)
    log = (d / "c.log").read_text() if (d / "c.log").exists() else ""
    truth = dict(sc.expect)
    m = re.search(r"Control Channel: (TLSv[\d.]+), cipher (?:\S+ )?([^\s,]+)", log)
    if m:
        truth["tls_version"], truth["tls_cipher"] = m.group(1), m.group(2)
    m = re.search(r"Data Channel: cipher '([^']+)'", log)
    if m:
        truth["data_cipher"] = m.group(1)
    truth["connected"] = "Initialization Sequence Completed" in log
    (OUT / f"{sc.name}.client.conf").write_text(client_conf + "\n")
    (OUT / f"{sc.name}.server.conf").write_text(server_conf + "\n")
    return {"file": pcap.name, "protocol": "OpenVPN", "version": "2.6.19", "port": sc.port, "description": sc.description, "ground_truth": truth,
            "ground_truth_source": "client log lines 'Control Channel:' / 'Data Channel:' and the options this script wrote"}


# ----------------------------------------------------------------------------- WireGuard
@dataclass
class WgScenario:
    name: str
    description: str
    seconds: int = 25
    psk: bool = False
    peer_up: bool = True
    keepalive: int = 5
    allowed: str = "10.77.0.2/32"


WG: list[WgScenario] = [
    WgScenario("wg_basic", "WireGuard (wireguard-go), one handshake, ping through the tunnel", 22),
    WgScenario("wg_psk", "WireGuard with a PresharedKey: identical on the wire to wg_basic (the PSK is invisible)", 22, psk=True),
    WgScenario("wg_rekey", "WireGuard kept busy for 2+ minutes: the initiator re-handshakes after 120 s", 150),
    WgScenario("wg_unanswered", "WireGuard initiator whose peer is down: handshake initiations retried every 5 s, no response", 24, peer_up=False),
]


def run_wg(sc: WgScenario, tmp: Path) -> dict:
    d = tmp / "wg"
    d.mkdir(exist_ok=True)
    keys = {}
    for n in ("a", "b"):
        priv = sh("wg", "genkey").stdout.strip()
        keys[n] = (priv, subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True).stdout.strip())
    (d / "psk").write_text(sh("wg", "genpsk").stdout)
    for n in ("a", "b"):
        (d / f"{n}.key").write_text(keys[n][0] + "\n")
    pcap = OUT / f"{sc.name}.pcap"
    cap = Capture(pcap)
    try:
        for n, ns, ip, port, peer_ip, peer_port, peer in (("a", NS_A, "10.77.0.1", 51820, IP_B, 51820, "b"), ("b", NS_B, "10.77.0.2", 51820, IP_A, 51820, "a")):
            if n == "b" and not sc.peer_up:
                continue
            ifn = f"wg{n}"
            sh("wireguard-go", ifn, ns=ns)
            args = ["wg", "set", ifn, "private-key", str(d / f"{n}.key"), "listen-port", str(port), "peer", keys[peer][1],
                    "allowed-ips", sc.allowed if n == "a" else "10.77.0.1/32", "endpoint", f"{peer_ip}:{peer_port}"]
            if sc.keepalive and n == "a":
                args += ["persistent-keepalive", str(sc.keepalive)]
            if sc.psk:
                args += ["preshared-key", str(d / "psk")]
            sh(*args, ns=ns)
            sh("ip", "addr", "add", f"{ip}/24", "dev", ifn, ns=ns)
            sh("ip", "link", "set", ifn, "up", ns=ns)
        time.sleep(1)
        sh("ping", "-c", str(sc.seconds), "-i", "1", "-W", "1", "10.77.0.2", ns=NS_A, check=False)
    finally:
        cap.stop()
        subprocess.run(["pkill", "-f", "wireguard-go"], capture_output=True)
        time.sleep(0.5)
    conf = "[Interface]\nPrivateKey = (hidden: lab key)\nAddress = 10.77.0.1/24\nListenPort = 51820\n\n[Peer]\nPublicKey = (lab peer key)\n" \
           + ("PresharedKey = (hidden: lab key)\n" if sc.psk else "") + f"AllowedIPs = {sc.allowed}\nEndpoint = {IP_B}:51820\nPersistentKeepalive = {sc.keepalive}\n"
    (OUT / f"{sc.name}.conf").write_text(conf)
    return {"file": pcap.name, "protocol": "WireGuard", "version": "wireguard-go 0.0.20230223", "port": 51820, "description": sc.description,
            "ground_truth": {"suite": "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", "preshared_key": sc.psk, "peer_answered": sc.peer_up,
                             "min_handshakes": 1 if sc.seconds < 120 else 2, "persistent_keepalive": sc.keepalive},
            "ground_truth_source": "the configuration this script wrote (WireGuard has no negotiation; the suite is fixed by the protocol)"}


def main(argv: list[str]) -> int:
    if os.geteuid() != 0:
        print("run as root (network namespaces, tun devices)")
        return 2
    want = set(argv)
    names = [s.name for s in OVPN + WG]
    for w in want - set(names):
        print(f"unknown scenario {w}; choose from {', '.join(names)}")
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    manifest_path = OUT / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    tmp = Path(tempfile.mkdtemp(prefix="vpnlab-"))
    try:
        (tmp / "ovpn").mkdir()
        pki(tmp / "ovpn")
        for sc in OVPN + WG:
            if want and sc.name not in want:
                continue
            print(f"[{sc.name}] {sc.description}", flush=True)
            setup_net()
            try:
                manifest[sc.name] = run_ovpn(sc, tmp) if isinstance(sc, OvpnScenario) else run_wg(sc, tmp)
            finally:
                teardown_net()
            print(f"    -> {manifest[sc.name]['ground_truth']}", flush=True)
            manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=1) + "\n")
    finally:
        teardown_net()
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
