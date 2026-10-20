"""Rule engine for OpenVPN / WireGuard tunnels: `policy/other_vpn.yaml` + the checks below.

Same output type (`Finding`) and scoring as the IPsec engine, so tables, reports and the remediation plan need no
special cases. A check receives the tunnel's `facts`, the policy thresholds and the rule, and returns a list of
`(outcome key, evidence)`; an empty list means no violation. Where the observation is impossible the rule is silent and a
coverage note says so (`_coverage`), because "not seen" and "not wrong" are different statements.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

import yaml

from ..rules.engine import Finding
from ..rules.policy import SEV_ORDER, SEVERITIES, Policy, PolicyError
from .model import VpnTunnel

DEFAULT_PACK = Path(__file__).resolve().parents[2] / "policy" / "other_vpn.yaml"
Check = Callable[[dict, dict, dict], list[tuple[str, dict]]]
_CHECKS: dict[str, Check] = {}


def check(name: str) -> Callable[[Check], Check]:
    def deco(fn: Check) -> Check:
        _CHECKS[name] = fn
        return fn
    return deco


def load_pack(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else DEFAULT_PACK
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise PolicyError(f"cannot load VPN policy {p}: {e}") from e
    for key in ("policy", "thresholds", "rules", "remediations", "mitre_catalog"):
        if key not in raw:
            raise PolicyError(f"VPN policy missing top-level key '{key}'")
    seen: set[str] = set()
    for r in raw["rules"]:
        rid = r.get("id")
        if not rid or rid in seen:
            raise PolicyError(f"missing or duplicate VPN rule id: {rid!r}")
        seen.add(rid)
        if r.get("check") not in _CHECKS:
            raise PolicyError(f"rule {rid}: unknown check '{r.get('check')}'")
        if r.get("protocol") not in ("openvpn", "wireguard") or r.get("source") not in ("capture", "config", "any"):
            raise PolicyError(f"rule {rid}: bad protocol/source")
        for sev in list(r.get("severity_by_key", {}).values()) + ([r["severity"]] if "severity" in r else []):
            if sev not in SEVERITIES:
                raise PolicyError(f"rule {rid}: unknown severity '{sev}'")
        if "severity" not in r and "severity_by_key" not in r:
            raise PolicyError(f"rule {rid}: no severity")
        if r.get("remediation") not in raw["remediations"]:
            raise PolicyError(f"rule {rid}: unknown remediation '{r.get('remediation')}'")
        for m in r.get("mitre", []):
            if m not in raw["mitre_catalog"]:
                raise PolicyError(f"rule {rid}: MITRE id {m} not in mitre_catalog")
    return raw


class VpnRuleEngine:
    def __init__(self, base: Policy, path: str | Path | None = None) -> None:
        self.base = base  # severity weights and risk bands come from the IPsec pack
        self.pack = load_pack(path)

    @property
    def name(self) -> str:
        return f"{self.pack['policy']['name']} v{self.pack['policy']['version']}"

    def evaluate(self, t: VpnTunnel) -> list[Finding]:
        out: list[Finding] = []
        proto = t.protocol.lower()
        th = self.pack["thresholds"]
        for rule in self.pack["rules"]:
            if rule["protocol"] != proto or rule["source"] not in ("any", t.source):
                continue
            hits = _CHECKS[rule["check"]](t.facts, th, rule)
            if not hits:
                continue
            key, evidence = hits[0]
            if len(hits) > 1:
                evidence = {**evidence, "instances": [e for _k, e in hits]}
            sev = rule.get("severity_by_key", {}).get(key) or rule.get("severity")
            if sev:
                out.append(self._finding(rule, t, sev, evidence))
        out.extend(self._coverage(t))
        out.sort(key=lambda f: (SEV_ORDER[f.severity], f.rule_id))
        return out

    def _finding(self, rule: dict, t: VpnTunnel, sev: str, evidence: dict) -> Finding:
        cat = self.pack["mitre_catalog"]
        rem = self.pack["remediations"][rule["remediation"]]
        return Finding(rule_id=rule["id"], title=rule["title"], severity=sev, category="violation", tunnel_id=t.id,
                       description=" ".join(rule["description"].split()), evidence=evidence, refs=list(rule.get("refs", [])),
                       mitre=[{"id": m, **cat[m]} for m in rule.get("mitre", [])], remediation={"id": rule["remediation"], **rem})

    @staticmethod
    def _coverage(t: VpnTunnel) -> list[Finding]:
        """What could NOT be assessed. Reported, never scored."""
        out: list[Finding] = []

        def cov(rid: str, title: str, why: str) -> None:
            out.append(Finding(rid, title, "info", "coverage", t.id, why, {"reason": why}))

        f = t.facts
        if t.source == "config":
            cov("COV-CFG-INTENT", "A configuration file shows intent, not what was negotiated",
                "The peer, the OpenVPN/WireGuard version and compiled-in defaults decide what actually happens on the wire. "
                "Findings here are about this file; capture the handshake to confirm what the two ends really used.")
            return out
        if t.protocol == "OpenVPN":
            cov("COV-OVPN-DATA", "OpenVPN data-channel cipher, HMAC and compression not observable",
                "The data-channel cipher, its HMAC and compression are negotiated inside the TLS session and the data packets are "
                "encrypted, so no capture shows them. Upload the OpenVPN configuration file to assess them.")
            vis = f.get("tls_visibility")
            if vis == "hidden":
                cov("COV-OVPN-TLS-HIDDEN", "TLS parameters hidden by tls-crypt",
                    "The control channel is encrypted with tls-crypt, so the TLS version, suite and certificate cannot be seen. That is the "
                    "intended privacy gain; the price is that the TLS strength is only assessable from the configuration file.")
            elif vis == "hello_only":
                cov("COV-OVPN-CERT-TLS13", "Server certificate not visible (TLS 1.3)",
                    "TLS 1.3 encrypts the server certificate, so its key size, signature and validity could not be checked.")
            elif vis == "none" and f.get("server_answered"):
                cov("COV-OVPN-NO-TLS", "TLS handshake not captured",
                    "The server answered but no readable TLS handshake was reassembled (packets missing from the capture, or the capture began late).")
        else:
            cov("COV-WG-PSK", "WireGuard pre-shared key use not observable",
                "A PresharedKey is mixed into the key schedule and leaves no trace on the wire. Without one the handshake is secure against "
                "today's attackers but not against a future quantum computer reading recorded traffic. Check the peer's configuration file.")
            if f.get("initiation_not_captured"):
                cov("COV-WG-NO-INIT", "WireGuard initiation missing from the capture",
                    "A response was seen without its initiation, so which side started the session is inferred from the response.")
        return out


# ====================================================================== OpenVPN capture checks
@check("ovpn_tls_version")
def _tls_version(f: dict, th: dict, rule: dict) -> list:
    n = f.get("tls_negotiated")
    if n and n["version"] in rule["severity_by_key"]:
        return [(n["version"], {"version": n["version"], "suite": n["suite"], "frames": f.get("frames")})]
    return []


@check("ovpn_suite_issue")
def _suite_issue(f: dict, th: dict, rule: dict) -> list:
    n = f.get("tls_negotiated")
    if not n:
        return []
    return [(k, {"suite": n["suite"], "version": n["version"], "problem": k, "frames": f.get("frames")})
            for k in rule["severity_by_key"] if k in n["issues"]]  # YAML order is worst first


@check("ovpn_no_pfs")
def _no_pfs(f: dict, th: dict, rule: dict) -> list:
    n = f.get("tls_negotiated")
    if n and "no_pfs" in n["issues"]:
        return [("", {"suite": n["suite"], "key_exchange": n["kex"], "version": n["version"]})]
    return []


@check("ovpn_cbc_sha1")
def _cbc(f: dict, th: dict, rule: dict) -> list:
    n = f.get("tls_negotiated")
    if n and "cbc_sha1" in n["issues"]:
        return [("", {"suite": n["suite"], "cipher": n["cipher"], "mac": n["mac"]})]
    return []


@check("ovpn_dh_size")
def _dh(f: dict, th: dict, rule: dict) -> list:
    n = f.get("tls_negotiated")
    bits = n and n.get("dh_bits")
    if not bits:
        return []
    if bits < 1024:
        return [("under_1024", {"dh_prime_bits": bits, "suite": n["suite"]})]
    if bits < th["dh_min_bits"]:
        return [("under_2048", {"dh_prime_bits": bits, "suite": n["suite"]})]
    return []


@check("ovpn_cert")
def _cert(f: dict, th: dict, rule: dict) -> list:
    c = f.get("certificate")
    if not c:
        return []
    out: list = []
    base = {"subject": c["subject"], "key": f"{c['key_type']} {c['key_bits']}", "signature_hash": c["signature_hash"]}
    if c["key_type"] == "RSA" and c["key_bits"] and c["key_bits"] < 1024:
        out.append(("rsa_under_1024", base))
    elif c["key_type"] == "RSA" and c["key_bits"] and c["key_bits"] < th["rsa_min_bits"]:
        out.append(("rsa_under_2048", base))
    if c["signature_hash"] == "md5":
        out.append(("md5_signature", base))
    elif c["signature_hash"] == "sha1":
        out.append(("sha1_signature", base))
    if c.get("expired_at_capture"):
        out.append(("expired", {**base, "not_after": c["not_after"]}))
    order = list(rule["severity_by_key"])
    return sorted(out, key=lambda x: order.index(x[0]))


@check("ovpn_client_offers")
def _offers(f: dict, th: dict, rule: dict) -> list:
    o = f.get("tls_offered")
    if not o:
        return []
    ev: dict[str, Any] = {}
    legacy = [v for v in o["versions"] if v in ("SSLv3", "TLSv1", "TLSv1.1")]
    if legacy:
        ev["legacy_versions_offered"] = legacy
    if o["weak_suites"]:
        ev["weak_suites_offered"] = o["weak_suites"]
    return [("", ev)] if ev else []


@check("ovpn_ctrl")
def _ctrl(f: dict, th: dict, rule: dict) -> list:
    p = f.get("control_protection")
    if p in ("none", "tls-auth"):
        return [(p, {"control_protection": p, "port": f.get("port"), "frames": f.get("frames")})]
    return []


@check("ovpn_no_reply")
def _no_reply(f: dict, th: dict, rule: dict) -> list:
    if not f.get("server_answered"):
        return [("", {"client_hard_resets": f.get("client_resets"), "attempts": f.get("attempts", 1), "port": f.get("port")})]
    return []


@check("ovpn_alert")
def _alert(f: dict, th: dict, rule: dict) -> list:
    fatal = [a for a in f.get("alerts", []) if a["level"] == "fatal"]
    return [("", {"alert": fatal[0]["description"], "sent_by": fatal[0]["from"]})] if fatal else []


@check("ovpn_stalled")
def _stalled(f: dict, th: dict, rule: dict) -> list:
    if f.get("server_answered") and f["data_packets"]["c2s"] + f["data_packets"]["s2c"] == 0 and not f.get("alerts"):
        return [("", {"data_packets": f["data_packets"], "duration_s": f.get("duration_s")})]
    return []


@check("ovpn_no_reneg")
def _no_reneg(f: dict, th: dict, rule: dict) -> list:
    if f.get("single_key_s", 0) >= th["ovpn_single_key_s"]:
        return [("", {"key_in_use_s": f["single_key_s"], "threshold_s": th["ovpn_single_key_s"], "renegotiations": f["renegotiations"]})]
    return []


# ====================================================================== WireGuard capture checks
@check("wg_no_response")
def _wg_noresp(f: dict, th: dict, rule: dict) -> list:
    if f["responses"] == 0 and f["handshakes_completed"] == 0 and f["unanswered_initiations"] >= th["wg_unanswered_min"]:
        return [("", {"initiations": f["initiations"], "responses": 0, "frames": f.get("frames")})]
    return []


@check("wg_init_burst")
def _wg_burst(f: dict, th: dict, rule: dict) -> list:
    if f["initiation_burst_10s"] >= th["wg_burst_10s"]:
        return [("", {"initiations_in_10s": f["initiation_burst_10s"], "honest_retry_interval_s": 5, "initiations": f["initiations"]})]
    return []


@check("wg_stale_keys")
def _wg_stale(f: dict, th: dict, rule: dict) -> list:
    if f["max_key_age_s"] >= th["wg_stale_key_s"]:
        return [("", {"key_age_s": f["max_key_age_s"], "reject_after_s": f["reject_after_s"], "handshakes": f["handshakes_completed"]})]
    return []


@check("wg_replay")
def _wg_replay(f: dict, th: dict, rule: dict) -> list:
    d, n = f["counter_duplicates"], f["counter_packets"]
    if d >= th["wg_replay_min"] and n and d / n >= th["wg_replay_ratio"]:
        return [("", {"duplicate_counters": d, "transport_packets": n, "ratio": round(d / n, 4),
                      "note": "packets captured twice (e.g. tcpdump -i any) look the same"})]
    return []


@check("wg_cookie")
def _wg_cookie(f: dict, th: dict, rule: dict) -> list:
    if f["cookie_replies"]:
        return [("", {"cookie_replies": f["cookie_replies"], "initiations_carrying_cookie": f["initiations_with_cookie"]})]
    return []


@check("wg_roaming")
def _wg_roam(f: dict, th: dict, rule: dict) -> list:
    return [("", {"other_addresses": f["roamed_endpoints"]})] if f["roamed_endpoints"] else []


@check("wg_any")
def _wg_any(f: dict, th: dict, rule: dict) -> list:
    return [("", {"suite": f.get("suite", "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"), "negotiable": False})]


# ====================================================================== configuration checks
def _dirs(f: dict, name: str) -> list[dict]:
    return f.get("directives", {}).get(name, [])


def _present(f: dict, *names: str) -> bool:
    return any(_dirs(f, n) or n in f.get("inline", {}) for n in names)


_WEAK_CIPHER = re.compile(r"^(BF|DES|RC2|RC4|CAST|IDEA)", re.I)


def _cipher_class(c: str) -> str | None:
    u = c.upper()
    if u == "NONE":
        return "none"
    if _WEAK_CIPHER.match(u):
        return "weak"
    if u.endswith("-CBC") and u.startswith(("AES", "CAMELLIA", "ARIA")):
        return "cbc"
    return None


def _configured_ciphers(f: dict) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for name in ("cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers"):
        for d in _dirs(f, name):
            if d["args"]:
                for c in d["args"][0].split(":"):
                    out.append((c, d["line"]))
    return out


@check("cfg_ovpn_cipher")
def _cfg_cipher(f: dict, th: dict, rule: dict) -> list:
    found: dict[str, list] = {}
    for c, line in _configured_ciphers(f):
        k = _cipher_class(c)
        if k:
            found.setdefault(k, []).append({"cipher": c, "line": line})
    for k in ("none", "weak", "cbc"):  # worst first
        if k in found:
            return [(k, {"problem": k, "configured": found[k], "all_ciphers": [c for c, _ in _configured_ciphers(f)]})]
    return []


@check("cfg_ovpn_auth")
def _cfg_auth(f: dict, th: dict, rule: dict) -> list:
    ciphers = [c for c, _ in _configured_ciphers(f)]
    if ciphers and all(re.search(r"GCM|POLY1305", c, re.I) for c in ciphers):
        return []  # AEAD only: --auth is ignored
    for d in _dirs(f, "auth"):
        v = (d["args"][0] if d["args"] else "").upper()
        k = {"NONE": "none", "MD5": "md5", "SHA1": "sha1"}.get(v)
        if k:
            return [(k, {"auth": v, "line": d["line"], "ciphers": ciphers or "default"})]
    return []


@check("cfg_ovpn_tls_min")
def _cfg_tls_min(f: dict, th: dict, rule: dict) -> list:
    if not _is_tls(f):
        return []
    d = _dirs(f, "tls-version-min")
    if not d:
        return [("unset", {"tls-version-min": "not set"})]
    try:
        v = float(d[0]["args"][0])
    except (IndexError, ValueError):
        return []
    return [("legacy", {"tls-version-min": d[0]["args"][0], "line": d[0]["line"]})] if v < 1.2 else []


_WEAK_TLS = re.compile(r"(NULL|EXP|RC4|3DES|DES-CBC|DES-EDE|-MD5|^MD5|ADH|AECDH|ANON|^LOW$|^eNULL$|^aNULL$)", re.I)


@check("cfg_ovpn_tls_cipher")
def _cfg_tls_cipher(f: dict, th: dict, rule: dict) -> list:
    for d in _dirs(f, "tls-cipher"):
        spec = d["args"][0] if d["args"] else ""
        toks = [t for t in re.split(r"[:,]", spec) if t]
        weak = [t for t in toks if _WEAK_TLS.search(t.lstrip("!+-")) and not t.startswith("!")]
        if weak:
            return [("weak", {"tls-cipher": spec[:200], "weak_entries": weak[:8], "line": d["line"]})]
        if re.search(r"@SECLEVEL=0", spec, re.I):
            return [("seclevel0", {"tls-cipher": spec[:200], "line": d["line"]})]
    return []


def _is_tls(f: dict) -> bool:
    return _present(f, "client", "server", "tls-client", "tls-server", "ca")


@check("cfg_ovpn_ctrl")
def _cfg_ctrl(f: dict, th: dict, rule: dict) -> list:
    if not _is_tls(f):
        return []
    if _present(f, "tls-crypt", "tls-crypt-v2"):
        return []
    if _present(f, "tls-auth"):
        return [("tls-auth", {"tls-auth": "set", "tls-crypt": "not set"})]
    return [("none", {"tls-auth": "not set", "tls-crypt": "not set"})]


@check("cfg_ovpn_compress")
def _cfg_compress(f: dict, th: dict, rule: dict) -> list:
    hits: list[dict] = []
    for d in _dirs(f, "comp-lzo"):
        if not d["args"] or d["args"][0].lower() != "no":
            hits.append({"directive": "comp-lzo " + " ".join(d["args"]), "line": d["line"]})
    for d in _dirs(f, "compress"):
        if not d["args"] or not d["args"][0].lower().startswith("stub"):
            hits.append({"directive": ("compress " + " ".join(d["args"])).strip(), "line": d["line"]})
    for d in _dirs(f, "allow-compression"):
        if d["args"] and d["args"][0].lower() == "yes":
            hits.append({"directive": "allow-compression yes", "line": d["line"]})
    return [("", {"compression": hits})] if hits else []


@check("cfg_ovpn_server_verify")
def _cfg_verify(f: dict, th: dict, rule: dict) -> list:
    if f.get("role") != "client":
        return []
    if _present(f, "remote-cert-tls", "remote-cert-eku", "remote-cert-ku", "ns-cert-type", "verify-x509-name", "tls-verify"):
        return []
    return [("", {"remote-cert-tls": "not set", "verify-x509-name": "not set"})]


@check("cfg_ovpn_client_cert")
def _cfg_clientcert(f: dict, th: dict, rule: dict) -> list:
    if _dirs(f, "client-cert-not-required"):
        return [("", {"directive": "client-cert-not-required", "line": _dirs(f, "client-cert-not-required")[0]["line"]})]
    for d in _dirs(f, "verify-client-cert"):
        if d["args"] and d["args"][0].lower() in ("none", "optional"):
            return [("", {"directive": "verify-client-cert " + d["args"][0], "line": d["line"]})]
    return []


@check("cfg_ovpn_dh")
def _cfg_dh(f: dict, th: dict, rule: dict) -> list:
    bits = f.get("dh_bits")
    if not bits:
        return []
    if bits < 1024:
        return [("under_1024", {"dh_bits": bits})]
    return [("under_2048", {"dh_bits": bits})] if bits < th["dh_min_bits"] else []


@check("cfg_ovpn_crl")
def _cfg_crl(f: dict, th: dict, rule: dict) -> list:
    if f.get("role") == "server" and not _dirs(f, "crl-verify"):
        return [("", {"crl-verify": "not set"})]
    return []


@check("cfg_ovpn_reneg")
def _cfg_reneg(f: dict, th: dict, rule: dict) -> list:
    for d in _dirs(f, "reneg-sec"):
        if d["args"] and d["args"][0] == "0":
            return [("", {"directive": "reneg-sec 0", "line": d["line"]})]
    return []


@check("cfg_secrets")
def _cfg_secrets(f: dict, th: dict, rule: dict) -> list:
    if f.get("protocol") == "WireGuard":
        i = f.get("interface", {})
        if i.get("has_private_key"):
            return [("", {"PrivateKey": "present (discarded)", "line": i.get("private_key_line"),
                          "peers_with_PresharedKey": sum(1 for p in f.get("peers", []) if p.get("has_psk"))})]
        return []
    blocks = {k: v for k, v in f.get("inline", {}).items() if k in ("key", "tls-crypt", "tls-auth", "tls-crypt-v2", "secret", "pkcs12")}
    return [("", {"inline_blocks": {k: {"line": v["line"]} for k, v in blocks.items()}})] if blocks else []


@check("cfg_wg_psk")
def _cfg_wg_psk(f: dict, th: dict, rule: dict) -> list:
    missing = [p for p in f.get("peers", []) if not p.get("has_psk")]
    if missing:
        return [("", {"peers_without_psk": [{"public_key": p["public_key"], "line": p["line"]} for p in missing][:10],
                      "peers": len(f.get("peers", []))})]
    return []


@check("cfg_wg_allowedips")
def _cfg_wg_allowed(f: dict, th: dict, rule: dict) -> list:
    if not f.get("interface", {}).get("listen_port"):
        return []
    bad = [p for p in f.get("peers", []) if not p.get("endpoint") and any(a in ("0.0.0.0/0", "::/0") for a in p.get("allowed_ips", []))]
    return [("", {"peers": [{"public_key": p["public_key"], "allowed_ips": p["allowed_ips"], "line": p["line"]} for p in bad][:10]})] if bad else []
