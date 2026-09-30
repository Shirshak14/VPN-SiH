import { useEffect, useState } from "react";
import { Json, api, pct } from "../api";
import { ErrorBox, Loading } from "../ui";

function Det({ title, d }: { title: string; d: Json }) {
  return (
    <tr>
      <td>{title}</td><td>{pct(d.precision)}</td><td>{pct(d.recall)}</td><td>{d.f1 == null ? "n/a" : d.f1.toFixed(3)}</td><td>{pct(d.false_positive_rate)}</td>
      <td className="mono">{d.tp}/{d.fp}/{d.fn}/{d.tn}</td>
    </tr>
  );
}

export default function Evaluation() {
  const [m, setM] = useState<Json | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () => { setError(null); api.metrics().then(setM).catch((e) => setError(e.message)); };
  useEffect(load, []);
  if (error) return <ErrorBox error={error} retry={load} />;
  if (!m) return <Loading what="Loading evaluation" />;
  const s = m.synthetic, pub = m.real_public, tp = m.throughput;

  return (
    <div className="stack">
      <div>
        <h1>Evaluation</h1>
        <div className="muted small">Generated {m.generated_at}. Recomputed from labelled captures by <code>python -m ipsec_analyzer.evaluation</code>.</div>
      </div>
      <div className="banner">
        <b>Read this first.</b> Detection numbers are on a <b>held-out split of simulated captures</b> whose labels come from the generator's own configuration.
        Both the simulator and the parser were written by the same team, so parse accuracy on this corpus mainly proves internal consistency. Independent
        evidence is the real-capture validation below. None of these figures are field detection rates.
      </div>

      <div className="card">
        <h2>Detection — held-out simulated tunnels ({s.tunnels_evaluated}) <span className="muted small">alert = rules risk in medium band or above, or anomaly &gt; 0.5</span></h2>
        <div className="tablewrap"><table>
          <thead><tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th><th>False-positive rate</th><th>TP/FP/FN/TN</th></tr></thead>
          <tbody>
            <Det title="Rules + AI (combined)" d={s.detection.combined} />
            <Det title="Rule engine only" d={s.detection.rules} />
            <Det title="Anomaly model only" d={s.detection.ml} />
          </tbody></table></div>
        <h3>Per scenario family (alerts / tunnels)</h3>
        <div className="tablewrap"><table>
          <thead><tr><th>Family</th><th>Tunnels</th><th>Combined</th><th>Rules</th><th>AI</th></tr></thead>
          <tbody>{Object.entries(s.per_family).map(([k, v]: [string, Json]) => (
            <tr key={k}><td className="mono">{k}{k.startsWith("b_") ? " (benign)" : ""}</td><td>{v.n}</td><td>{v.combined}</td><td>{v.rules}</td><td>{v.ml}</td></tr>
          ))}</tbody></table></div>
      </div>

      <div className="grid g2">
        <div className="card">
          <h2>Parse accuracy — simulated (consistency check)</h2>
          <table><tbody>{Object.entries(s.parse_accuracy).map(([k, v]: [string, Json]) => (
            <tr key={k}><td className="mono">{k}</td><td>{v.ok}/{v.total}</td><td>{pct(v.accuracy)}</td></tr>
          ))}</tbody></table>
          <div className="small muted" style={{ marginTop: 8 }}>Rule-level (assessable rules): TP {s.rule_level.tp} · FP {s.rule_level.fp} · FN {s.rule_level.fn}</div>
        </div>
        <div className="card">
          <h2>Parser vs independent oracles — real captures</h2>
          <div className="big">{pub.total_ok}/{pub.total}</div>
          <div className="small muted">checks passed on real Wireshark public captures</div>
          <table style={{ marginTop: 8 }}><tbody>{Object.entries(pub.summary).map(([k, v]: [string, Json]) => (
            <tr key={k}><td className="mono small">{k}</td><td>{v.ok}/{v.total}</td></tr>
          ))}</tbody></table>
        </div>
      </div>

      <div className="grid g2">
        <div className="card">
          <h2>Throughput</h2>
          <dl className="kv">
            <dt>Parse only</dt><dd>{tp.parse_packets_per_s.toLocaleString()} packets/s · {tp.parse_mb_per_s} MB/s</dd>
            <dt>End-to-end</dt><dd>{tp.end_to_end_packets_per_s.toLocaleString()} packets/s (parse → rules → AI incl. SHAP)</dd>
            <dt>Corpus</dt><dd>{tp.captures} captures · {tp.packets.toLocaleString()} packets · {tp.megabytes} MB</dd>
          </dl>
          <div className="small muted">Single-thread Python on a laptop; demo-sized captures only.</div>
        </div>
        <div className="card">
          <h2>Without decryption keys</h2>
          <p className="small muted" style={{ marginTop: 0 }}>IKEv2 encrypts authentication and child SAs, so ESP/PFS rules are not assessable without keys.</p>
          <table><tbody>
            <tr><td>Recall (combined)</td><td>{pct(m.synthetic_no_keys.detection.combined.recall)}</td></tr>
            <tr><td>Precision (combined)</td><td>{pct(m.synthetic_no_keys.detection.combined.precision)}</td></tr>
            <tr><td>False-positive rate</td><td>{pct(m.synthetic_no_keys.detection.combined.false_positive_rate)}</td></tr>
          </tbody></table>
        </div>
      </div>
    </div>
  );
}
