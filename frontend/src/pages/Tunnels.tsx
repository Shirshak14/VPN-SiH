import { useEffect, useState } from "react";
import { Analysis, Json, api } from "../api";
import { Empty, ErrorBox, Loading, Meter, Prov, ProvBanner, Sev } from "../ui";

export default function Tunnels({ aid }: { aid: number }) {
  const [a, setA] = useState<Analysis | null>(null);
  const [tunnels, setTunnels] = useState<Json[] | null>(null);
  const [plan, setPlan] = useState<Json[]>([]);
  const [error, setError] = useState<string | null>(null);

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

  return (
    <div className="stack">
      <div className="row spread">
        <div>
          <a href="#/" className="small">← New analysis</a>
          <h1 className="mono" style={{ fontSize: 18 }}>{a.filename} <Prov p={a.provenance} /></h1>
          <div className="muted small">Policy: {s.policy}{a.has_keys ? " · decryption keys supplied" : " · no decryption keys"}</div>
        </div>
        <div className="row" aria-label="Report actions">
          <a className="btn primary" href={api.url(aid, "report.pdf")}>Download PDF report</a>
          <a className="btn" href={api.url(aid, "export.json")}>JSON</a>
          <a className="btn" href={api.url(aid, "export.syslog")}>Syslog / CEF</a>
        </div>
      </div>
      <ProvBanner p={a.provenance} />

      <div className="grid g4">
        {[
          ["Tunnels", s.tunnel_count],
          ["IKE messages", s.ike_messages],
          ["ESP packets", s.esp_packets],
          ["Analysis time", `${a.seconds}s`],
        ].map(([l, v]) => (
          <div className="card kpi" key={l as string}><div className="label">{l}</div><div className="val">{v}</div></div>
        ))}
      </div>
      {s.parse_errors?.length > 0 && <div className="banner">{s.ike_malformed} malformed IKE datagram(s) skipped, e.g. {s.parse_errors[0]}</div>}

      <div className="card">
        <h2>Tunnels — highest risk first</h2>
        {tunnels.length === 0 ? <Empty>No IKE or ESP tunnels were found in this capture.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>Risk</th><th>Peers</th><th>Mode</th><th>Negotiated IKE suite</th><th>Findings</th><th>Anomaly</th></tr></thead>
              <tbody>
                {tunnels.map((t) => (
                  <tr key={t.id} className="click" tabIndex={0} onClick={() => (window.location.hash = `#/a/${aid}/t/${encodeURIComponent(t.id)}`)}
                      onKeyDown={(e) => e.key === "Enter" && (window.location.hash = `#/a/${aid}/t/${encodeURIComponent(t.id)}`)}>
                    <td style={{ minWidth: 120 }}>
                      <div className="row" style={{ gap: 8, flexWrap: "nowrap" }}>
                        <span className="score">{t.risk.score}</span><Sev level={t.risk.band} />
                      </div>
                      <Meter score={t.risk.score} band={t.risk.band} />
                    </td>
                    <td className="mono">{t.initiator} → {t.responder}<div className="muted">{t.status}</div></td>
                    <td>{t.exchange_mode}</td>
                    <td className="mono">{t.chosen?.label ?? <span className="muted">none negotiated</span>}</td>
                    <td>{t.violations.length === 0 ? <span className="muted">none</span> : t.violations.map((v: Json) => <span key={v.rule_id} className="chip">{v.rule_id}</span>)}</td>
                    <td>{t.anomaly_score == null ? <span className="muted">n/a</span> : t.anomaly_score > 0.5 ? <span className="badge high">anomalous {t.anomaly_score}</span> : <span className="muted">{t.anomaly_score}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2>Remediation plan</h2>
        {plan.length === 0 ? <Empty>No violations to remediate.</Empty> : (
          <div className="stack">
            {plan.map((r) => (
              <div key={r.id} className={`finding ${r.severity}`}>
                <div className="row"><Sev level={r.severity} /><b>{r.title}</b></div>
                <div className="small muted">Addresses {r.rules.join(", ")} · {r.tunnels.length} tunnel(s)</div>
                <ol className="small" style={{ margin: "6px 0 0", paddingLeft: 20 }}>{r.steps.map((st: string) => <li key={st}>{st}</li>)}</ol>
                {r.example && <pre className="mono">{r.example}</pre>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
