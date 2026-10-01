import { useEffect, useRef, useState } from "react";
import { Json, api, fmtTs } from "../api";
import { Empty, ErrorBox, Loading, Meter, Sev } from "../ui";

const SEVS = ["critical", "high", "medium", "low", "info"];

function Timeline({ events }: { events: Json[] }) {
  const [shown, setShown] = useState(events.length);
  const timer = useRef<number | null>(null);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); }, []);
  const replay = () => {
    if (timer.current) window.clearInterval(timer.current);
    setShown(0);
    let n = 0;
    timer.current = window.setInterval(() => {
      n += 1;
      setShown(n);
      if (n >= events.length && timer.current) window.clearInterval(timer.current);
    }, 350);
  };
  const t0 = events[0]?.ts ?? 0;
  return (
    <div>
      <div className="row spread">
        <span className="small muted">{events.length} IKE messages · times relative to first packet</span>
        <button onClick={replay} aria-label="Replay handshake capture">▶ Replay capture</button>
      </div>
      <ol className="timeline" aria-live="polite">
        {events.slice(0, shown).map((e, i) => (
          <li key={i}>
            <span className="mono muted">{fmtTs(e.ts, t0)}</span>
            <span className="dir">{e.direction === "I->R" ? "I → R" : "R → I"}</span>
            <span>
              <b>{e.label}</b> <span className="muted small">{e.size} B</span>
              {e.retransmit && <span className="retx"> · retransmission</span>}
              {e.encrypted && <span className="chip" style={{ marginLeft: "var(--sp-2)" }}>encrypted</span>}
              <div className="small muted">{(e.notes ?? []).join(" · ")}</div>
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function Shap({ items }: { items: Json[] }) {
  const max = Math.max(...items.map((i) => Math.abs(i.shap)), 1e-9);
  return (
    <div>
      {items.map((f) => (
        <div className="shapbar" key={f.feature}>
          <span title={`observed ${f.value}, benign median ${f.baseline_median}`}>{f.label}</span>
          <div className="track">
            <span className="mid" />
            <span className={`fill ${f.shap > 0 ? "up" : "down"}`} style={{ width: `${(Math.abs(f.shap) / max) * 50}%` }} />
          </div>
          <span className="mono" style={{ textAlign: "right" }}>{f.shap > 0 ? "+" : ""}{f.shap}</span>
        </div>
      ))}
      <div className="small muted">Right (orange) pushes toward anomalous; left (green) toward normal. Hover a label for observed value vs benign median.</div>
    </div>
  );
}

export default function TunnelDetail({ aid, tid }: { aid: number; tid: string }) {
  const [d, setD] = useState<Json | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () => { setError(null); api.tunnel(aid, tid).then(setD).catch((e) => setError(e.message)); };
  useEffect(load, [aid, tid]);

  if (error) return <ErrorBox error={error} retry={load} />;
  if (!d) return <Loading what="Loading tunnel" />;
  const t = d.tunnel, risk = d.risk, an = d.anomaly;
  const viol = d.findings.filter((f: Json) => f.category === "violation");
  const cov = d.findings.filter((f: Json) => f.category === "coverage");

  return (
    <div className="stack">
      <a href={`#/a/${aid}`} className="small">← All tunnels</a>
      <div className="card">
        <div className="row spread">
          <div>
            <h1 className="mono">{t.initiator} → {t.responder}</h1>
            <div className="muted small">{t.exchange_mode} · status <b>{t.status}</b>{t.failure ? ` (${t.failure})` : ""} · SPI <span className="mono">{t.ispi}</span></div>
          </div>
          <div style={{ minWidth: 220 }}>
            <div className="row" style={{ gap: "var(--sp-3)" }}><span className="big">{risk.score}</span><Sev level={risk.band} /></div>
            <Meter score={risk.score} band={risk.band} />
          </div>
        </div>
        <h3>How this score was computed</h3>
        <div className="small">
          <code>{risk.formula}</code>
          <div style={{ marginTop: "var(--sp-2)" }}>
            R (rules) = <b>{risk.rules_component}</b> from {risk.contributions.length ? risk.contributions.map((c: Json) => `${c.rule_id} (${c.severity}, w=${c.weight})`).join(", ") : "no violations"}
            {" · "}A (anomaly) = <b>{risk.anomaly_component}</b>{risk.anomaly_score == null ? " (model not loaded)" : ` (score ${risk.anomaly_score} × weight)`}
          </div>
        </div>
      </div>

      <div className="grid g2">
        <div className="card">
          <h2>Security Association</h2>
          <dl className="kv">
            <dt>Negotiated IKE</dt><dd className="mono">{t.chosen?.label ?? "—"}</dd>
            <dt>Offered</dt><dd className="mono">{t.offered.length ? t.offered.map((s: Json) => s.label).join("  |  ") : "—"}</dd>
            <dt>Authentication</dt><dd>{t.auth_observable ? t.auth_method : <span className="muted">not observable (encrypted; supply keys)</span>}</dd>
            <dt>NAT-T</dt><dd>{t.natt ? "yes (UDP/4500)" : "no"}</dd>
            <dt>IKE lifetime</dt><dd>{t.chosen?.lifetime_s ? `${t.chosen.lifetime_s} s` : <span className="muted">not on the wire (IKEv2)</span>}</dd>
            <dt>Rekeys</dt><dd>{t.create_child_exchanges} CREATE_CHILD_SA / Quick Mode{t.decrypted ? ` (${t.child_rekeys} child, ${t.ike_rekeys} IKE)` : ""}</dd>
            <dt>Retransmits</dt><dd>{t.retransmits} (longest streak {t.max_retransmit_streak}) · cookies {t.cookie_challenges}</dd>
            <dt>DPD / liveness</dt><dd>{t.dpd_messages} messages</dd>
            <dt>Fragments</dt><dd>{t.fragments}</dd>
            <dt>Capabilities</dt><dd>{t.vendor_capabilities.map((c: string) => <span key={c} className="chip">{c}</span>)}</dd>
          </dl>
          <h3>Child SAs</h3>
          {t.child_sas.length === 0 ? <div className="small muted">None visible{t.ike_version === 2 && !t.decrypted ? " — IKE_AUTH is encrypted; upload the key file to reveal ESP algorithms and PFS." : "."}</div> : (
            <div className="tablewrap"><table><thead><tr><th>Proto</th><th>Suite</th><th>Via</th><th>PFS</th></tr></thead><tbody>
              {t.child_sas.map((c: Json, i: number) => (
                <tr key={i}><td>{c.protocol}</td><td className="mono">{c.suite.label}</td><td>{c.via}{c.rekey ? " (rekey)" : ""}</td><td>{c.via === "CREATE_CHILD_SA" ? (c.pfs ? "yes" : <b>no</b>) : <span className="muted">n/a (initial)</span>}</td></tr>
              ))}</tbody></table></div>
          )}
        </div>
        <div className="card">
          <h2>Handshake timeline</h2>
          {t.timeline.length === 0 ? <Empty>No IKE messages.</Empty> : <Timeline events={t.timeline} />}
        </div>
      </div>

      <div className="card">
        <h2>Rule-engine findings ({viol.length})</h2>
        {viol.length > 0 && (
          <div className="bands" aria-label="Findings by severity">
            {SEVS.filter((sv) => viol.some((f: Json) => f.severity === sv)).map((sv) => (
              <span key={sv} className={`badge ${sv}`}>{viol.filter((f: Json) => f.severity === sv).length} {sv}</span>
            ))}
          </div>
        )}
        {viol.length === 0 ? <div className="banner pass-banner" role="status"><b>✓ No policy violations</b> for this tunnel among the checks that could be assessed.</div> : (
          <div className="stack">
            {viol.map((f: Json, i: number) => (
              <div key={f.rule_id + i} className={`finding ${f.severity}`}>
                <div className="row"><Sev level={f.severity} /><b>{f.rule_id}</b><span>{f.title}</span></div>
                <p className="small" style={{ margin: "var(--sp-2) 0" }}>{f.description}</p>
                <pre className="mono">{Object.entries(f.evidence).filter(([k]) => k !== "all_offenders").map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : v}`).join("\n")}</pre>
                <div className="small" style={{ marginTop: "var(--sp-2)" }}>
                  <b>MITRE ATT&amp;CK:</b>{" "}
                  {f.mitre.length ? f.mitre.map((m: Json) => <a key={m.id} className="chip" href={m.url} target="_blank" rel="noreferrer">{m.id} {m.name}</a>) : <span className="muted">no direct technique mapped</span>}
                </div>
                <div className="small"><b>Standards:</b> {f.refs.join(" · ")}</div>
                <details style={{ marginTop: "var(--sp-2)" }}>
                  <summary className="small"><b>Remediation:</b> {f.remediation.title}</summary>
                  <ol className="small">{f.remediation.steps.map((s: string) => <li key={s}>{s}</li>)}</ol>
                  {f.remediation.example && <pre className="mono">{f.remediation.example}</pre>}
                </details>
              </div>
            ))}
          </div>
        )}
        {cov.length > 0 && (
          <>
            <h3>Not assessable from this capture</h3>
            {cov.map((f: Json) => <div key={f.rule_id} className="banner small" style={{ marginBottom: "var(--sp-2)" }}><b>{f.title}.</b> {f.description}</div>)}
          </>
        )}
      </div>

      <div className="card">
        <h2>Behavioural anomaly model</h2>
        {!an ? <Empty>The anomaly model is not trained on this server. Run <code>python -m ipsec_analyzer.ml.train</code>.</Empty> : (
          <>
            <div className="row">
              <span className="big">{an.score}</span>
              {an.is_anomalous ? <span className="badge high">anomalous</span> : <span className="badge ok">within benign baseline</span>}
              <span className="small muted">0.5 = benign 99th percentile · dominant group: <b>{an.dominant_group}</b></span>
            </div>
            <h3>Group scores</h3>
            {an.groups.map((g: Json) => (
              <div className="shapbar" key={g.group} style={{ gridTemplateColumns: "160px 1fr 50px" }}>
                <span>{g.group}</span>
                <div className="track"><span className="fill" style={{ left: 0, width: `${g.score * 100}%`, background: g.score > 0.5 ? "var(--high)" : "var(--low)" }} /></div>
                <span className="mono">{g.score}</span>
              </div>
            ))}
            <h3>Why — {an.explanation.method}</h3>
            {an.explanation.top_features?.length ? <Shap items={an.explanation.top_features} /> : <div className="small muted">{an.explanation.error ?? "No attribution available."}</div>}
          </>
        )}
      </div>

      <div className="card">
        <h2>ESP / AH flows</h2>
        {t.esp_flows.length === 0 ? <Empty>No ESP traffic attributed to this tunnel.</Empty> : (
          <div className="tablewrap"><table>
            <thead><tr><th>SPI</th><th>Direction</th><th>Packets</th><th>Bytes</th><th>Seq range</th><th>Gaps</th><th>Replays</th><th>Mean IAT</th></tr></thead>
            <tbody>{t.esp_flows.map((f: Json) => (
              <tr key={f.spi + f.src}><td className="mono">0x{f.spi}</td><td className="mono">{f.src} → {f.dst}{f.udp_encap ? " (UDP-encap)" : ""}</td><td>{f.packets}</td><td>{f.bytes}</td>
                <td className="mono">{f.seq_first}–{f.seq_last}</td><td>{f.seq_gaps}</td><td>{f.seq_replays > 0 ? <b>{f.seq_replays}</b> : 0}</td><td>{f.mean_iat_ms.toFixed(1)} ms</td></tr>
            ))}</tbody></table></div>
        )}
      </div>
    </div>
  );
}
