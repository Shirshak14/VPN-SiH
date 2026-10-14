import { Fragment, useEffect, useState } from "react";
import { Analysis, Json, api } from "../api";
import { ErrorBox, Loading, Sev } from "../ui";

const TIERS = ["prohibited", "deprecated", "acceptable", "recommended"];
const TIER_CLS: Record<string, string> = { prohibited: "critical", deprecated: "medium", acceptable: "info", recommended: "ok" };
const COMPONENTS: [string, string][] = [["encryption", "Encryption"], ["integrity", "Integrity / PRF"], ["dh", "Diffie-Hellman group"]];

function Severity({ r }: { r: Json }) {
  if (r.severity) return <Sev level={r.severity} />;
  return (
    <div className="pol-tiers">
      {Object.entries(r.severity_by_tier ?? {}).map(([tier, sev]) => <div key={tier} className="small"><Sev level={sev as string} /> <span className="muted">if {tier}</span></div>)}
    </div>
  );
}

export default function Policy({ aid }: { aid?: number }) {
  const [p, setP] = useState<Json | null>(null);
  const [a, setA] = useState<Analysis | null>(null);
  const [fired, setFired] = useState<Map<string, number> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setError(null);
    api.policy().then(setP).catch((e) => setError(e.message));
    if (aid) {
      Promise.all([api.analysis(aid), api.tunnels(aid)]).then(([an, ts]) => {
        const m = new Map<string, number>();  // rule -> number of tunnels it fired on
        for (const t of ts) for (const id of new Set<string>(t.violations.map((v: Json) => v.rule_id))) m.set(id, (m.get(id) ?? 0) + 1);
        setA(an);
        setFired(m);
      }).catch((e) => setError(e.message));
    }
  };
  useEffect(load, [aid]);

  if (error) return <ErrorBox error={error} retry={load} />;
  if (!p || (aid && !fired)) return <Loading what="Loading policy pack" />;
  const nFired = fired ? p.rules.filter((r: Json) => fired.has(r.id)).length : 0;

  return (
    <div className="res">
      <header className="res-head">
        {a && <a href={`#/a/${a.id}`} className="small">← Back to {a.filename}</a>}
        <h1>Policy pack</h1>
        <div className="res-meta small muted">
          <span>{p.name}</span>
          <span>{p.rules.length} rules</span>
          {a && <span><b className="fired-dot" /> {nFired} fired in analysis #{a.id}</span>}
        </div>
        <p className="small muted">Every check the analyzer runs, the standard it comes from, the ATT&CK technique it maps to and the fix it recommends. Rules marked "if prohibited / if deprecated" take their severity from the algorithm tiers below.</p>
      </header>

      <section className="res-section">
        <div className="sec-head"><h2>Rules</h2>{a && <span className="small muted">highlighted rows fired in this analysis</span>}</div>
        <div className="tablewrap">
          <table className="pol-rules">
            <thead><tr><th>Rule</th><th>Severity</th><th>Sources</th><th>ATT&CK</th><th>Fix</th>{fired && <th>Fired</th>}</tr></thead>
            <tbody>
              {p.rules.map((r: Json) => {
                const n = fired?.get(r.id);
                return (
                  <tr key={r.id} className={n ? "fired" : ""}>
                    <td>
                      <div className="mono"><b>{r.id}</b></div>
                      <div>{r.title}</div>
                      <div className="small muted">{r.description}</div>
                    </td>
                    <td><Severity r={r} /></td>
                    <td className="small">{r.refs.map((ref: string) => <div key={ref}>{ref}</div>)}</td>
                    <td>{r.mitre_detail.length === 0 ? <span className="muted small">none mapped</span> : r.mitre_detail.map((m: Json) => (
                      <a key={m.id} className="chip" href={m.url} target="_blank" rel="noreferrer" title={m.tactic}>{m.id} {m.name}</a>
                    ))}</td>
                    <td className="small">{r.remediation.title}</td>
                    {fired && <td>{n ? <span className="badge high">{n} tunnel{n === 1 ? "" : "s"}</span> : <span className="muted small">–</span>}</td>}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>

      <section className="res-section">
        <div className="sec-head"><h2>Algorithm tiers</h2><span className="small muted">how a negotiated algorithm is graded (RFC 8221 / RFC 8247 / NIST SP 800-77r1)</span></div>
        <div className="pol-grid">
          {COMPONENTS.map(([k, label]) => (
            <div key={k} className="card">
              <h3>{label}</h3>
              {TIERS.map((tier) => (
                <div key={tier} className="pol-tier">
                  <span className={`badge ${TIER_CLS[tier]}`}>{tier}</span>
                  <div>{(p.tiers[k]?.[tier] ?? []).map((alg: string | null) => <span key={alg ?? "NULL"} className="chip mono">{alg ?? "NULL"}</span>)}</div>
                </div>
              ))}
            </div>
          ))}
        </div>
      </section>

      <section className="res-section">
        <div className="sec-head"><h2>Risk scoring</h2></div>
        <div className="grid g2">
          <div className="card">
            <h3>Risk bands (score from 0 to 100)</h3>
            <div className="bands">
              {Object.entries(p.risk.bands).map(([band, min]) => <span key={band} className={`badge ${band}`}>{band} ≥ {min as number}</span>)}
              <span className="badge info">info &lt; {Math.min(...(Object.values(p.risk.bands) as number[]))}</span>
            </div>
            <p className="mono small">{p.formula}</p>
            <p className="small muted">Severity weights: {Object.entries(p.severity_weight).map(([s, w]) => `${s} ${w}`).join(", ")}. anomaly_weight = {p.risk.anomaly_weight}.</p>
          </div>
          <div className="card">
            <h3>Thresholds</h3>
            <dl className="kv small">
              {Object.entries(p.thresholds).map(([k, v]) => <Fragment key={k}><dt className="mono">{k}</dt><dd>{String(v)}</dd></Fragment>)}
            </dl>
          </div>
        </div>
      </section>
    </div>
  );
}
