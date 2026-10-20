import { Fragment, ReactNode } from "react";
import { Json } from "../api";

// What was observed (or configured) for an OpenVPN or WireGuard tunnel. Everything shown is read from the stored facts; a
// value that a capture cannot reveal says so instead of being left blank.

const PROTECTION: Record<string, string> = {
  none: "none: the TLS handshake and the server's TLS stack are exposed",
  "tls-auth": "tls-auth: HMAC only, authenticated but not encrypted",
  "tls-crypt": "tls-crypt: control channel encrypted",
  "tls-crypt-v2": "tls-crypt-v2: control channel encrypted, per-client key",
};

function Row({ k, children }: { k: string; children: ReactNode }) {
  return <Fragment><dt>{k}</dt><dd>{children}</dd></Fragment>;
}

const NA = (why: string) => <span className="muted">{why}</span>;
const yesno = (v: boolean | null | undefined) => (v == null ? "n/a" : v ? "yes" : <b>no</b>);

function OpenVpnCapture({ f }: { f: Json }) {
  const n = f.tls_negotiated, o = f.tls_offered, c = f.certificate;
  return (
    <dl className="kv">
      <Row k="Control channel">{PROTECTION[f.control_protection] ?? f.control_protection}</Row>
      <Row k="UDP port">{f.port}</Row>
      <Row k="Handshake">{f.client_resets} client hard reset{f.client_resets === 1 ? "" : "s"}{f.attempts > 1 ? ` over ${f.attempts} attempts` : ""} · server {f.server_answered ? "answered" : <b>did not answer</b>}</Row>
      <Row k="TLS">
        {n ? <><span className="mono">{n.version}</span> · <span className="mono">{n.suite}</span></> :
          f.tls_visibility === "hidden" ? NA("hidden by tls-crypt") : NA("no TLS handshake in the capture")}
      </Row>
      {n && <Row k="Key exchange">{n.kex}{n.group ? ` (${n.group})` : ""}{n.dh_bits ? ` · ${n.dh_bits}-bit prime` : ""} · forward secrecy {yesno(n.pfs)}</Row>}
      {n && <Row k="Record protection">{n.cipher ?? "?"} {n.mode ?? ""}{n.mac && n.mac !== "AEAD" ? ` with HMAC-${n.mac}` : n.aead ? " (AEAD)" : ""}</Row>}
      <Row k="Client offered">
        {o ? <>min <span className="mono">{o.min_version}</span> · {o.suite_count} suites{o.weak_suites.length ? <> · <b>weak:</b> <span className="mono">{o.weak_suites.join(", ")}</span></> : ""}</> : NA("not visible")}
      </Row>
      <Row k="Server certificate">
        {c ? <><span className="mono">{c.key_type} {c.key_bits}</span>, signed {c.signature_hash ?? "?"}{c.self_signed ? ", self-signed" : ""}{c.expired_at_capture ? <b> · expired at capture time</b> : ""}<div className="small muted mono">{c.subject}</div></> :
          f.tls_visibility === "hello_only" ? NA("encrypted by TLS 1.3") : NA("not visible")}
      </Row>
      <Row k="Data channel">{NA("cipher, HMAC and compression are negotiated inside TLS: not observable from a capture")} · {f.data_packets.c2s} packets out, {f.data_packets.s2c} in</Row>
      <Row k="Key renegotiations">{f.renegotiations}{f.single_key_s ? ` · one key in use for ${f.single_key_s} s` : ""}</Row>
      {f.alerts?.length > 0 && <Row k="TLS alerts">{f.alerts.map((a: Json, i: number) => <span key={i} className="chip">{a.level} {a.description} ({a.from})</span>)}</Row>}
    </dl>
  );
}

function WireGuardCapture({ f }: { f: Json }) {
  const tp = f.transport_packets, tb = f.transport_bytes;
  return (
    <dl className="kv">
      <Row k="Cipher suite"><span className="mono">{f.suite}</span> {NA("(fixed by the protocol; nothing is negotiated, so nothing can be downgraded)")}</Row>
      <Row k="Handshakes">{f.initiations} initiation{f.initiations === 1 ? "" : "s"} · {f.responses} response{f.responses === 1 ? "" : "s"} · {f.unanswered_initiations} unanswered · {f.handshakes_completed} completed</Row>
      <Row k="Round trip">{f.median_round_trip_ms == null ? NA("no completed handshake") : `${f.median_round_trip_ms} ms (median)`}</Row>
      <Row k="Rekeys">{f.rekey_intervals_s.length ? `${f.rekey_intervals_s.join(", ")} s apart (protocol timer: ${f.rekey_after_s} s)` : NA("none in this capture")}</Row>
      <Row k="Longest key use">{f.max_key_age_s} s {NA(`(a key is refused after ${f.reject_after_s} s)`)}</Row>
      <Row k="Transport data">{tp.i2r} packets / {tb.i2r} B to the responder · {tp.r2i} / {tb.r2i} B back · {f.keepalive_packets} keepalive{f.keepalive_packets === 1 ? "" : "s"}</Row>
      <Row k="Cookie replies">{f.cookie_replies}{f.cookie_replies ? " (responder under load)" : ""}</Row>
      <Row k="Counter repeats">{f.counter_duplicates} of {f.counter_packets} packets</Row>
      {f.roamed_endpoints.length > 0 && <Row k="Other addresses">{f.roamed_endpoints.join(", ")}</Row>}
      <Row k="Pre-shared key">{NA("not observable on the wire")}</Row>
    </dl>
  );
}

const SHOW = ["cipher", "data-ciphers", "data-ciphers-fallback", "auth", "tls-version-min", "tls-cipher", "tls-crypt", "tls-crypt-v2", "tls-auth", "compress", "comp-lzo",
  "allow-compression", "remote-cert-tls", "verify-x509-name", "verify-client-cert", "client-cert-not-required", "crl-verify", "reneg-sec", "dh"];

function OpenVpnConfig({ f }: { f: Json }) {
  const seen = SHOW.filter((k) => f.directives[k]);
  const missing = SHOW.filter((k) => !f.directives[k] && !f.inline[k]);
  return (
    <>
      <dl className="kv">
        <Row k="Role">{f.role}</Row>
        <Row k="Control channel">{PROTECTION[f.control_protection] ?? f.control_protection}</Row>
        {f.dh_bits && <Row k="Inline DH">{f.dh_bits}-bit</Row>}
        <Row k="Inline blocks">{Object.keys(f.inline).length ? Object.entries(f.inline).map(([k, v]) => <span key={k} className="chip" title={`line ${(v as Json).line}`}>&lt;{k}&gt;</span>) : NA("none")}</Row>
      </dl>
      <h3>Directives that matter</h3>
      <div className="tablewrap"><table>
        <thead><tr><th>Line</th><th>Directive</th></tr></thead>
        <tbody>
          {seen.flatMap((k) => f.directives[k].map((d: Json) => <tr key={k + d.line}><td>{d.line}</td><td className="mono">{k} {d.args.join(" ")}</td></tr>))}
          {seen.length === 0 && <tr><td colSpan={2} className="muted">None of the security-relevant directives are set.</td></tr>}
        </tbody>
      </table></div>
      <div className="small muted">Not set: <span className="mono">{missing.join(", ") || "none"}</span></div>
    </>
  );
}

function WireGuardConfig({ f }: { f: Json }) {
  const i = f.interface;
  return (
    <>
      <dl className="kv">
        <Row k="Listen port">{i.listen_port ?? NA("not set (client)")}</Row>
        <Row k="Address">{(i.address ?? []).join(", ") || NA("not set")}</Row>
        <Row k="Private key">{i.has_private_key ? "present (discarded, never stored)" : NA("not in this file")}</Row>
        <Row k="Cipher suite"><span className="mono">{f.suite}</span> {NA("(fixed by the protocol)")}</Row>
      </dl>
      <h3>Peers ({f.peers.length})</h3>
      <div className="tablewrap"><table>
        <thead><tr><th>Line</th><th>Public key</th><th>PresharedKey</th><th>AllowedIPs</th><th>Endpoint</th></tr></thead>
        <tbody>{f.peers.map((p: Json) => (
          <tr key={p.line}><td>{p.line}</td><td className="mono">{p.public_key}</td><td>{p.has_psk ? "yes" : <b>no</b>}</td><td className="mono">{p.allowed_ips.join(", ")}</td><td className="mono">{p.endpoint ?? "–"}</td></tr>
        ))}</tbody>
      </table></div>
    </>
  );
}

export default function VpnFacts({ t }: { t: Json }) {
  const f = t.vpn;
  const body = t.source === "config" ? (t.protocol === "OpenVPN" ? <OpenVpnConfig f={f} /> : <WireGuardConfig f={f} />)
    : t.protocol === "OpenVPN" ? <OpenVpnCapture f={f} /> : <WireGuardCapture f={f} />;
  return (
    <div className="card">
      <h2>{t.protocol} {t.source === "config" ? "configuration" : "session"}</h2>
      {body}
    </div>
  );
}
