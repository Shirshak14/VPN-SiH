import { useEffect, useState } from "react";
import { Analysis, Json, api } from "../api";
import { ErrorBox, Loading, Meter, Prov, ProvBanner, Sev } from "../ui";

const BANDS = ["critical", "high", "medium", "low", "info"];
const VISIBLE_FINDINGS = 2;

// One chip per distinct rule; repeats (e.g. one per ESP flow) collapse into a ×n count so nothing is lost.
function groupViolations(vs: Json[]): { rule_id: string; severity: string; n: number }[] {
  const m = new Map<string, { rule_id: string; severity: string; n: number }>();
  for (const v of vs) {
    const g = m.get(v.rule_id);
    if (g) g.n += 1;
    else m.set(v.rule_id, { rule_id: v.rule_id, severity: v.severity, n: 1 });
  }
  return [...m.values()];
}

export default function Tunnels({ aid }: { aid: number }) {
  const [a, setA] = useState<Analysis | null>(null);
  const [tunnels, setTunnels] = useState<Json[] | null>(null);
  const [plan, setPlan] = useState<Json[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const load = () => {
    setError(null);
    Promise.all([api.analysis(aid), api.tunnels(aid), api.remediation(aid)])
      .then(([an, t, r]) => { setA(an); setTunnels(t); setPlan(r); })
      .catch((e) => setError(e.message));
  };
  useEffect(load, [aid]);

  if (error) return <ErrorBox error={error} retry={load} />;
  if (!a || !tunnels) return <Loading what="Loading results" />;
  const s = a.summary;
  const top = tunnels.reduce<Json | null>((m, t) => (m == null || t.risk.score > m.risk.score ? t : m), null);
  const withViol = tunnels.filter((t) => t.violations.length > 0).length;
  const totalViol = tunnels.reduce((n, t) => n + t.violations.length, 0);
  const scored = tunnels.filter((t) => t.anomaly_score != null).length;
  const anomalous = tunnels.filter((t) => t.anomaly_score != null && t.anomaly_score > 0.5).length;
  const topRules = top ? groupViolations(top.violations) : [];
  const href = (id: string) => `#/a/${aid}/t/${encodeURIComponent(id)}`;
  const open = (id: string) => { window.location.hash = href(id); };
  const toggle = (id: string) => setExpanded((prev) => { const n = new Set(prev); if (!n.delete(id)) n.add(id); return n; });

  return (
    <div className="res">
      <header className="res-head">
        <a href="#/" className="small">← New analysis</a>
        <h1 className="mono">{a.filename} <Prov p={a.provenance} /></h1>
        <div className="res-meta small muted">
          <span className={`status ${a.status === "failed" ? "bad" : "ok"}`}>{a.status === "done" ? "Analysis complete" : a.status}</span>
          <span>Policy: {s.policy}{a.has_keys ? " · decryption keys supplied" : " · no decryption keys"}</span>
        </div>
        <div className="res-actions" aria-label="Report actions">
          <a className="btn sm primary" href={api.url(aid, "report.pdf")}>Download PDF report</a>
          <a className="btn sm" href={api.url(aid, "export.json")}>JSON</a>
          <a className="btn sm" href={api.url(aid, "export.syslog")}>Syslog / CEF</a>
        </div>
      </header>

      <ProvBanner p={a.provenance} compact />
      {s.parse_errors?.length > 0 && <div className="banner compact">{s.ike_malformed} malformed IKE datagram(s) skipped, e.g. {s.parse_errors[0]}</div>}

      <section className="card res-summary" aria-label="Analysis summary">
        <div className="hero">
          <div className="score-row">
            <span className="hero-score">{top ? top.risk.score : "n/a"}</span>
            {top && <Sev level={top.risk.band} />}
          </div>
          <div className="small muted">Highest risk across {tunnels.length} tunnel{tunnels.length === 1 ? "" : "s"}</div>
          {top && <Meter score={top.risk.score} band={top.risk.band} />}
        </div>
        <div className="facts">
          <ul className="kpis">
            <li><b>{tunnels.length}</b> tunnels</li>
            <li><b>{withViol}</b> with violations</li>
            <li><b>{tunnels.length - withViol}</b> without violations</li>
            <li>{scored === 0 ? <span className="muted">anomaly model not loaded</span> : <><b>{anomalous}</b> anomalous</>}</li>
          </ul>
          <p className="key">
            {totalViol === 0 || !top ? (
              <>No rule violations were raised among the checks that could be assessed.</>
            ) : (
              <>
                <span className="label">Key finding</span>{" "}
                <a className="mono" href={href(top.id)}>{top.initiator} → {top.responder}</a> has {top.violations.length} violation{top.violations.length === 1 ? "" : "s"}:{" "}
                {topRules.slice(0, 3).map((g) => g.rule_id).join(", ")}{topRules.length > 3 ? ` +${topRules.length - 3}` : ""}
              </>
            )}
          </p>
          <p className="foot small muted">
            {s.decrypted_tunnels ?? 0} decrypted · {totalViol} violation{totalViol === 1 ? "" : "s"} in total · {s.ike_messages} IKE messages · {s.esp_packets} ESP packets · analysed in {a.seconds}s
          </p>
        </div>
      </section>

      <section className="res-section">
        <div className="sec-head"><h2>Tunnels — highest risk first</h2><span className="small muted">select a row for full details</span></div>
        {tunnels.length === 0 ? <div className="empty">No IKE or ESP tunnels were found in this capture.</div> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Risk</th><th>Peers</th><th>Mode</th><th>Negotiated IKE suite</th><th>Findings</th><th>Anomaly</th></tr></thead>
              <tbody>
                {tunnels.map((t) => {
                  const g = groupViolations(t.violations);
                  const isOpen = expanded.has(t.id);
                  const shown = isOpen ? g : g.slice(0, VISIBLE_FINDINGS);
                  const hidden = g.length - VISIBLE_FINDINGS;
                  return (
                    <tr key={t.id} className="click" tabIndex={0} onClick={() => open(t.id)}
                        onKeyDown={(e) => e.key === "Enter" && e.target === e.currentTarget && open(t.id)}>
                      <td style={{ minWidth: 120 }}>
                        <div className="row" style={{ gap: "var(--sp-2)", flexWrap: "nowrap" }}>
                          <span className="score">{t.risk.score}</span><Sev level={t.risk.band} />
                        </div>
                        <Meter score={t.risk.score} band={t.risk.band} />
                      </td>
                      <td className="mono">{t.initiator} → {t.responder}<div className="muted">{t.status}</div></td>
                      <td>{t.exchange_mode}</td>
                      <td className="mono">{t.chosen?.label ?? <span className="muted">none negotiated</span>}</td>
                      <td>
                        {g.length === 0 ? <span className="pass">✓ no violations</span> : (
                          <>
                            {shown.map((v) => (
                              <span key={v.rule_id} className={`chip ${v.severity}`} title={`${v.severity} severity${v.n > 1 ? `, raised ${v.n} times` : ""}`}>
                                {v.rule_id}{v.n > 1 && <span className="times"> ×{v.n}</span>}
                              </span>
                            ))}
                            {hidden > 0 && (
                              <button className="linkbtn" aria-expanded={isOpen}
                                      onClick={(e) => { e.stopPropagation(); toggle(t.id); }}>
                                {isOpen ? "show less" : `+${hidden} more`}
                              </button>
                            )}
                          </>
                        )}
                      </td>
                      <td>{t.anomaly_score == null ? <span className="muted">n/a</span> : t.anomaly_score > 0.5 ? <span className="badge high">anomalous {t.anomaly_score}</span> : <span className="muted">{t.anomaly_score}</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        <div className="bands dist" aria-label="Risk distribution">
          <span className="label">Risk distribution</span>
          {BANDS.filter((b) => s.bands?.[b]).map((b) => <span key={b} className={`badge ${b}`}>{s.bands[b]} {b}</span>)}
        </div>
      </section>

      <section className="res-section">
        <div className="sec-head"><h2>Remediation plan{plan.length > 0 ? ` (${plan.length})` : ""}</h2>{plan.length > 0 && <span className="small muted">expand an item for steps and examples</span>}</div>
        {plan.length === 0 ? <p className="small muted">No violations to remediate.</p> : (
          <div className="rem">
            {plan.map((r) => (
              <details key={r.id}>
                <summary>
                  <Sev level={r.severity} /><b>{r.title}</b>
                  <span className="small muted">addresses {r.rules.join(", ")} · {r.tunnels.length} tunnel{r.tunnels.length === 1 ? "" : "s"}</span>
                </summary>
                <ol className="small">{r.steps.map((st: string) => <li key={st}>{st}</li>)}</ol>
                {r.example && <pre className="mono">{r.example}</pre>}
              </details>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
