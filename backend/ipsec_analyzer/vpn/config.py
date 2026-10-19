"""Read OpenVPN (`.ovpn` / `.conf`) and WireGuard (`wg0.conf`) configuration files into facts the rules can check.

A configuration file is a different kind of evidence from a capture: it says what the operator asked for, not what two
peers ended up negotiating. These parsers therefore only extract directives and never decide anything.

Secrets: such files routinely contain private keys. `redact()` is applied to an upload before anything is written to disk,
`parse_*` keeps argument values only for the directives the rules read (never keys, passwords or inline blocks), and the
stored facts hold names and line numbers. Nothing in a stored analysis can reproduce a key.
"""
from __future__ import annotations

import re
import shlex
from typing import Any

from .model import VpnTunnel

MAX_BYTES = 1 << 20
_BLOCK_OPEN = re.compile(r"^<([A-Za-z0-9_-]+)>\s*$")
_BLOCK_CLOSE = re.compile(r"^</([A-Za-z0-9_-]+)>\s*$")
# inline blocks whose content is secret and must never be stored
SECRET_BLOCKS = {"key", "tls-crypt", "tls-auth", "tls-crypt-v2", "secret", "pkcs12", "auth-user-pass", "http-proxy-user-pass"}
# directives whose arguments the rules read (everything else is kept by name and line only)
KEEP_ARGS = {
    "client", "server", "mode", "tls-client", "tls-server", "pull", "proto", "port", "lport", "rport", "remote", "local", "dev",
    "cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "auth", "tls-version-min", "tls-version-max", "tls-cipher",
    "tls-ciphersuites", "tls-groups", "tls-auth", "tls-crypt", "tls-crypt-v2", "comp-lzo", "compress", "allow-compression",
    "remote-cert-tls", "remote-cert-eku", "remote-cert-ku", "ns-cert-type", "verify-x509-name", "tls-verify",
    "client-cert-not-required", "verify-client-cert", "crl-verify", "reneg-sec", "dh", "ca", "cert", "key", "keepalive", "verb",
}
# `tls-auth` / `tls-crypt` / `key` args are file names (and a direction digit), not secrets; the key bytes live in the file or a block.


def looks_like_openvpn(text: str) -> bool:
    lines = [ln.strip() for ln in text.splitlines()[:400] if ln.strip() and not ln.lstrip().startswith(("#", ";"))]
    words = {ln.split()[0] for ln in lines if ln.split()}
    return len(words & {"remote", "client", "dev", "proto", "cipher", "tls-auth", "tls-crypt", "ca", "cert", "key", "server", "port", "auth",
                        "data-ciphers", "tls-server", "tls-client", "persist-key", "nobind", "verb", "keepalive"}) >= 2


def looks_like_wireguard(text: str) -> bool:
    return bool(re.search(r"^\s*\[Interface\]\s*$", text, re.M | re.I)) and bool(re.search(r"^\s*(PrivateKey|ListenPort|Address)\s*=", text, re.M | re.I))


def detect(text: str) -> str | None:
    if looks_like_wireguard(text):
        return "wireguard"
    if looks_like_openvpn(text):
        return "openvpn"
    return None


# ----------------------------------------------------------------------------- redaction
def redact(text: str) -> str:
    """Return the file with every secret removed, line numbers unchanged. Safe to write to disk."""
    kind = detect(text)
    out: list[str] = []
    skipping: str | None = None
    for ln in text.splitlines():
        s = ln.strip()
        if skipping:
            m = _BLOCK_CLOSE.match(s)
            if m and m.group(1).lower() == skipping:
                skipping = None
                out.append(ln)
            else:
                out.append("")  # keep the line count
            continue
        if kind == "wireguard":
            out.append(re.sub(r"^(\s*(?:PrivateKey|PresharedKey)\s*=).*$", r"\1 <redacted>", ln, flags=re.I))
            continue
        m = _BLOCK_OPEN.match(s)
        if m and m.group(1).lower() in SECRET_BLOCKS:
            skipping = m.group(1).lower()
            out.append(ln)
            continue
        out.append(ln)
    return "\n".join(out) + "\n"


# ----------------------------------------------------------------------------- OpenVPN
def _tokens(line: str) -> list[str]:
    try:
        return shlex.split(line, comments=False, posix=True)
    except ValueError:
        return line.split()


def parse_openvpn(text: str) -> dict[str, Any]:
    directives: dict[str, list[dict[str, Any]]] = {}
    inline: dict[str, dict[str, Any]] = {}
    block: str | None = None
    block_lines: list[str] = []
    block_start = 0
    for no, raw in enumerate(text.splitlines(), 1):
        s = raw.strip()
        if block is not None:
            m = _BLOCK_CLOSE.match(s)
            if m and m.group(1).lower() == block:
                body = "\n".join(block_lines)
                inline[block] = {"line": block_start, "bytes": len(body.encode())}
                if block == "dh":
                    inline[block]["bits"] = _dh_bits(body)
                block = None
            else:
                block_lines.append(raw)
            continue
        if not s or s.startswith(("#", ";")):
            continue
        m = _BLOCK_OPEN.match(s)
        if m:
            block, block_lines, block_start = m.group(1).lower(), [], no
            continue
        parts = _tokens(s)
        if not parts:
            continue
        name = parts[0].lower().lstrip("-")  # tolerate "--cipher" spelling
        args = parts[1:] if name in KEEP_ARGS else []
        directives.setdefault(name, []).append({"line": no, "args": args})
    role = "unknown"
    has = directives.keys()
    if "server" in has or "server-bridge" in has or "tls-server" in has or any(d["args"][:1] == ["server"] for d in directives.get("mode", [])):
        role = "server"
    elif "client" in has or "tls-client" in has or "remote" in has:
        role = "client"
    facts: dict[str, Any] = {"protocol": "OpenVPN", "source": "config", "role": role, "directives": directives, "inline": inline}
    dh = inline.get("dh")
    if dh and dh.get("bits"):
        facts["dh_bits"] = dh["bits"]
    return facts


def _dh_bits(pem: str) -> int | None:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_parameters
        return int(load_pem_parameters(pem.encode()).parameter_numbers().p.bit_length())
    except Exception:  # noqa: BLE001 - missing library or malformed block: no DH size claim
        return None


def openvpn_tunnel(facts: dict[str, Any], filename: str) -> VpnTunnel:
    d = facts["directives"]
    role = facts["role"]
    remote = d.get("remote", [{}])[0].get("args", []) if d.get("remote") else []
    proto = (d.get("proto", [{}])[0].get("args") or ["udp"])[0] if d.get("proto") else "udp"
    port = (d.get("port", [{}])[0].get("args") or ["1194"])[0] if d.get("port") else (remote[1] if len(remote) > 1 else "1194")
    if role == "client":
        initiator, responder = "client", f"{remote[0]}:{remote[1] if len(remote) > 1 else port}" if remote else "(no remote)"
    elif role == "server":
        initiator, responder = "clients", f"server {proto}/{port}"
    else:
        initiator, responder = "peer", "peer"
    inline, blocks = facts["inline"], facts["inline"].keys()
    prot = ("tls-crypt-v2" if "tls-crypt-v2" in d or "tls-crypt-v2" in blocks else "tls-crypt" if "tls-crypt" in d or "tls-crypt" in blocks
            else "tls-auth" if "tls-auth" in d or "tls-auth" in blocks else "none")
    facts["control_protection"] = prot
    ciphers = [c for n in ("data-ciphers", "cipher") for x in d.get(n, []) for c in (x["args"][0].split(":") if x["args"] else [])]
    label = f"{role} config · data: {':'.join(ciphers[:3]) if ciphers else 'default'} · control: {prot}"
    t = VpnTunnel(id="ovpn-cfg-1", protocol="OpenVPN", source="config", initiator=initiator, responder=responder, status="configured",
                  summary=label, facts=facts, session_ref=filename[:40])
    t.notes.append(f"Configuration file {filename!r}; role {role}.")
    return t


# ----------------------------------------------------------------------------- WireGuard
_B64_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")


def parse_wireguard(text: str) -> dict[str, Any]:
    iface: dict[str, Any] = {}
    peers: list[dict[str, Any]] = []
    section: str | None = None
    cur: dict[str, Any] | None = None
    problems: list[str] = []
    for no, raw in enumerate(text.splitlines(), 1):
        s = raw.split("#", 1)[0].strip()
        if not s:
            continue
        low = s.lower()
        if low == "[interface]":
            section, cur = "interface", iface
            iface.setdefault("line", no)
            continue
        if low == "[peer]":
            section = "peer"
            cur = {"line": no, "has_psk": False, "allowed_ips": [], "endpoint": None, "keepalive": None, "public_key": "?"}
            peers.append(cur)
            continue
        if "=" not in s or cur is None:
            problems.append(f"line {no}: not a key = value line")
            continue
        k, v = (x.strip() for x in s.split("=", 1))
        k = k.lower()
        if section == "interface":
            if k == "privatekey":
                iface["has_private_key"], iface["private_key_line"] = True, no
                if not _B64_KEY.match(v) and v != "<redacted>":
                    problems.append(f"line {no}: PrivateKey is not a 32-byte base64 key")
            elif k == "listenport":
                iface["listen_port"] = int(v) if v.isdigit() else None
            elif k == "address":
                iface["address"] = [a.strip() for a in v.split(",")][:4]
            elif k == "mtu":
                iface["mtu"] = int(v) if v.isdigit() else None
        elif cur is not None:
            if k == "publickey":
                cur["public_key"] = (v[:6] + "…" + v[-4:]) if len(v) > 12 else v
                if not _B64_KEY.match(v):
                    problems.append(f"line {no}: PublicKey is not a 32-byte base64 key")
            elif k == "presharedkey":
                cur["has_psk"] = True
            elif k == "allowedips":
                cur["allowed_ips"] = [a.strip() for a in v.split(",") if a.strip()]
            elif k == "endpoint":
                cur["endpoint"] = v
            elif k == "persistentkeepalive":
                cur["keepalive"] = int(v) if v.isdigit() else None
    return {"protocol": "WireGuard", "source": "config", "interface": iface, "peers": peers, "problems": problems[:10],
            "suite": "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"}


def wireguard_tunnel(facts: dict[str, Any], filename: str) -> VpnTunnel:
    i, peers = facts["interface"], facts["peers"]
    ep = next((p["endpoint"] for p in peers if p["endpoint"]), None)
    if ep:
        initiator, responder = "this host", ep
    else:
        initiator, responder = "peers", f"this host udp/{i.get('listen_port') or 'random'}"
    with_psk = sum(1 for p in peers if p["has_psk"])
    label = f"{len(peers)} peer{'s' if len(peers) != 1 else ''} · {with_psk} with PresharedKey · Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    t = VpnTunnel(id="wg-cfg-1", protocol="WireGuard", source="config", initiator=initiator, responder=responder, status="configured",
                  summary=label, facts=facts, session_ref=filename[:40])
    t.notes.append(f"Configuration file {filename!r}.")
    t.notes.extend(facts["problems"])
    return t


def parse_config(text: str, filename: str = "config") -> VpnTunnel:
    """Detect the VPN, parse, and return the (not yet assessed) configuration tunnel. Raises ValueError for anything else."""
    kind = detect(text)
    if kind == "wireguard":
        return wireguard_tunnel(parse_wireguard(text), filename)
    if kind == "openvpn":
        return openvpn_tunnel(parse_openvpn(text), filename)
    raise ValueError("not an OpenVPN or WireGuard configuration file (expected directives like 'remote', 'cipher', 'tls-crypt' or an [Interface] section)")
