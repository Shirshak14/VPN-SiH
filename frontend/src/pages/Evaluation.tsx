import { useEffect, useState } from "react";
import { Json, api, pct } from "../api";
import { ErrorBox, Loading } from "../ui";

// A number with a proportional bar. The bar is a visual of the exact value shown next to it; it carries no ranking or "good/bad" meaning.
function MetricBar({ ratio, text }: { ratio: number | null | undefined; text: string }) {
  return (
    <div className="mbar">
      <span className="mval">{text}</span>
      <span className="mtrack" aria-hidden="true">{ratio != null && <i style={{ width: `${Math.max(0, Math.min(1, ratio)) * 100}%` }} />}</span>
    </div>
  );
}

function Det({ title, d }: { title: string; d: Json }) {
  return (
    <tr>
      <td className="det-name">{title}</td>
      <td><MetricBar ratio={d.precision} text={pct(d.precision)} /></td>
      <td><MetricBar ratio={d.recall} text={pct(d.recall)} /></td>
      <td><MetricBar ratio={d.f1} text={d.f1 == null ? "n/a" : d.f1.toFixed(3)} /></td>
      <td><MetricBar ratio={d.false_positive_rate} text={pct(d.false_positive_rate)} /></td>
      <td className="mono counts">
        <span title="true positives">{d.tp}</span> / <span title="false positives">{d.fp}</span> / <span title="false negatives">{d.fn}</span> / <span title="true negatives">{d.tn}</span>
      </td>
    </tr>
  );
}

function AlertCell({ n, of }: { n: number; of: number }) {
  return <MetricBar ratio={of > 0 ? n / of : null} text={String(n)} />;
}

export default function Evaluation() {
  const [m, setM] = useState<Json | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = () => { setError(null); api.metrics().then(setM).catch((e) => setError(e.message)); };
  useEffect(load, []);
  if (error) return <ErrorBox error={error} retry={load} />;
  if (!m) return <Loading what="Loading evaluation" />;
  const s = m.synthetic, pub = m.real_public, tp = m.throughput, c = s.detection.combined;

  return (
    <div className="ev">
      <header>
        <h1>Evaluation</h1>
        <div className="ev-meta small muted">
          <span>Generated: {m.generated_at}</span>
          <span>Source: recomputed from labelled captures by <code>python -m ipsec_analyzer.evaluation</code>
            {m.corpus ? ` · ${m.corpus.captures} captures, ${m.corpus.provenance}` : ""}</span>
        </div>
      </header>

      <div className="banner compact method">
        <b>Read this first.</b> Detection numbers are on a <b>held-out split of simulated captures</b> whose labels come from the generator's own configuration.
        Both the simulator and the parser were written by the same team, so parse accuracy on this corpus mainly proves internal consistency. Independent
        evidence is the real-capture validation below. None of these figures are field detection rates.
      </div>

      <section aria-label="Evaluation summary">
        <div className="sec-head"><h2>Evaluation summary</h2><span className="small muted">combined detector (rules + AI) · held-out simulated tunnels · controlled evaluation, not field rates</span></div>
        <div className="metrics">
          {[
            [String(s.tunnels_evaluated), "Held-out simulated tunnels"],
            [pct(c.precision), "Precision"],
            [pct(c.recall), "Recall"],
            [c.f1 == null ? "n/a" : c.f1.toFixed(3), "F1"],
            [pct(c.false_positive_rate), "False-positive rate"],
          ].map(([v, l]) => (
            <div className="metric" key={l}><div className="v">{v}</div><div className="l">{l}</div></div>
          ))}
        </div>
      </section>

      <section aria-label="Detector comparison">
        <div className="sec-head"><h2>Detector comparison</h2><span className="small muted">alert = rules risk in medium band or above, or anomaly &gt; 0.5</span></div>
        <div className="tablewrap"><table className="evt">
          <thead><tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th><th>False-positive rate</th>
            <th><abbr title="true positives / false positives / false negatives / true negatives">TP / FP / FN / TN</abbr></th></tr></thead>
          <tbody>
            <Det title="Rules + AI (combined)" d={s.detection.combined} />
            <Det title="Rule engine only" d={s.detection.rules} />
            <Det title="Anomaly model only" d={s.detection.ml} />
          </tbody></table></div>
        <p className="small muted legend">TP = true positives · FP = false positives · FN = false negatives · TN = true negatives. Bars show each value on a 0–100% scale; they are not a ranking.</p>
      </section>

      <section aria-label="Per scenario family">
        <div className="sec-head"><h2>Per scenario family</h2><span className="small muted">alerts / tunnels · bars show alerts out of the family's tunnels</span></div>
        <div className="tablewrap"><table className="evt">
          <thead><tr><th>Family</th><th>Tunnels</th><th>Combined</th><th>Rules</th><th>AI</th></tr></thead>
          <tbody>{Object.entries(s.per_family).map(([k, v]: [string, Json]) => (
            <tr key={k}>
              <td className="mono fam">{k}{k.startsWith("b_") ? <span className="muted"> (benign)</span> : ""}</td>
              <td className="num">{v.n}</td>
              <td><AlertCell n={v.combined} of={v.n} /></td>
              <td><AlertCell n={v.rules} of={v.n} /></td>
              <td><AlertCell n={v.ml} of={v.n} /></td>
            </tr>
          ))}</tbody></table></div>
      </section>

      <div className="grid g2">
        <div className="card">
          <h2>Parse accuracy — simulated (consistency check)</h2>
          <table><tbody>{Object.entries(s.parse_accuracy).map(([k, v]: [string, Json]) => (
            <tr key={k}><td className="mono">{k}</td><td>{v.ok}/{v.total}</td><td>{pct(v.accuracy)}</td></tr>
          ))}</tbody></table>
          <div className="small muted" style={{ marginTop: "var(--sp-2)" }}>Rule-level (assessable rules): TP {s.rule_level.tp} · FP {s.rule_level.fp} · FN {s.rule_level.fn}</div>
        </div>
        <div className="card">
          <h2>Parser vs independent oracles — real captures</h2>
          <div className="big">{pub.total_ok}/{pub.total}</div>
          <div className="small muted">checks passed on real Wireshark public captures</div>
          <table style={{ marginTop: "var(--sp-2)" }}><tbody>{Object.entries(pub.summary).map(([k, v]: [string, Json]) => (
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
