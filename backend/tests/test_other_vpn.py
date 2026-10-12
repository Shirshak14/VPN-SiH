"""WireGuard / OpenVPN inventory: detection only, with false-positive guards."""
import os
from pathlib import Path

from ipsec_analyzer.parser import parse_pcap
from synth import builder as B


def _pcap(tmp: Path, udp: list[tuple[int, int, bytes]], name="x.pcap") -> Path:
    pk = []
    for i, (sport, dport, data) in enumerate(udp):
        fr = B.ethernet(B.ipv4_udp_frame("10.0.0.1", "10.0.0.2", sport, dport, data, 100 + i), b"\x02" * 6, b"\x04" * 6)
        pk.append((1000.0 + i * 0.01, fr))
    B.write_pcap(str(tmp / name), pk)
    return tmp / name


def _wg(t: int, n: int) -> bytes:
    return bytes([t, 0, 0, 0]) + os.urandom(n - 4)


def test_wireguard_handshake_and_transport_are_inventoried(tmp_path):
    p = _pcap(tmp_path, [(51820, 51820, _wg(1, 148)), (51820, 51820, _wg(2, 92)), (51820, 51820, _wg(4, 96)), (51820, 51820, _wg(4, 144))])
    (v,) = parse_pcap(p).stats.other_vpn
    assert v["protocol"] == "WireGuard" and v["handshake_initiations"] == 1 and v["handshake_responses"] == 1 and v["packets"] == 4


def test_wireguard_lookalikes_are_not_claimed(tmp_path):
    # right prefix, wrong handshake length; and "transport-shaped" packets with no handshake on that flow
    p = _pcap(tmp_path, [(5000, 5001, _wg(1, 149)), (5000, 5001, _wg(4, 96)), (5000, 5001, b"\x04\x00\x00\x00" + b"x" * 60)])
    assert parse_pcap(p).stats.other_vpn == []


def test_openvpn_needs_port_1194_and_a_reset(tmp_path):
    reset_c, reset_s = bytes([7 << 3]) + os.urandom(13), bytes([8 << 3]) + os.urandom(25)
    p = _pcap(tmp_path, [(40000, 1194, reset_c), (1194, 40000, reset_s), (40000, 1194, bytes([4 << 3]) + b"tls" * 10)])
    (v,) = parse_pcap(p).stats.other_vpn
    assert v["protocol"] == "OpenVPN" and v["handshake_initiations"] == 1 and v["handshake_responses"] == 1 and v["packets"] == 3
    q = _pcap(tmp_path, [(40000, 4444, reset_c), (40000, 1194, bytes([4 << 3]) + b"tls" * 10)], "y.pcap")
    assert parse_pcap(q).stats.other_vpn == []  # wrong port / no reset on the flow


def test_ike_capture_has_no_other_vpn():
    demo = Path(__file__).resolve().parents[2] / "data/public/ikev1-certs.pcap"
    assert parse_pcap(demo).stats.other_vpn == []
