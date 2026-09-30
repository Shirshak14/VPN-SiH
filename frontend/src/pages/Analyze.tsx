import { DragEvent, useCallback, useEffect, useRef, useState } from "react";
import { Analysis, Sample, api } from "../api";
import { Empty, ErrorBox, Loading, Prov } from "../ui";

const STEPS = [
  { key: "capture", title: "PCAP / capture", sub: "upload or pick a sample" },
  { key: "parsing IKE/ESP", title: "IKE & ESP parsing", sub: "handshake, transforms, SPIs" },
  { key: "reconstructing SAs", title: "SA reconstruction", sub: "tunnel lifecycle, retransmits" },
  { key: "rules + anomaly model", title: "Rules + AI detection", sub: "policy pack · Isolation Forest" },
  { key: "done", title: "Score, map, remediate", sub: "risk 0–100 · MITRE · PDF" },
];

function Pipeline({ stage }: { stage: string | null }) {
  const idx = stage == null ? -1 : stage === "done" ? STEPS.length : STEPS.findIndex((s) => s.key === stage);
  return (
    <div className="pipeline" aria-label="Analysis pipeline">
      {STEPS.map((s, i) => (
        <div key={s.key} className={`step ${i < idx ? "done" : i === idx ? "active" : ""}`}>
          <b>{s.title}</b>
          <span>{s.sub}</span>
        </div>
      ))}
    </div>
  );
}

export default function Analyze() {
  const [samples, setSamples] = useState<Sample[] | null>(null);
  const [history, setHistory] = useState<Analysis[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<Analysis | null>(null);
  const [pcap, setPcap] = useState<File | null>(null);
  const [keys, setKeys] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const timer = useRef<number | null>(null);

  const load = useCallback(() => {
    api.samples().then(setSamples).catch((e) => setError(e.message));
    api.analyses().then(setHistory).catch(() => undefined);
  }, []);
  useEffect(load, [load]);
  useEffect(() => () => { if (timer.current) window.clearTimeout(timer.current); }, []);

  const poll = useCallback((a: Analysis) => {
    setRunning(a);
    if (a.status === "done") { window.location.hash = `#/a/${a.id}`; return; }
    if (a.status === "failed") { setError(a.error ?? "analysis failed"); return; }
    timer.current = window.setTimeout(() => api.analysis(a.id).then(poll).catch((e) => { setError(e.message); setRunning(null); }), 400);
  }, []);

  const start = async (fn: () => Promise<Analysis>) => {
    setError(null);
    try { poll(await fn()); } catch (e) { setError((e as Error).message); setRunning(null); }
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files[0];
    if (f) setPcap(f);
  };
  const busy = running != null && running.status !== "failed";

  return (
    <div className="stack">
      <section>
        <h1>From manual audit to automated assessment</h1>
        <p className="muted" style={{ margin: 0 }}>
          Upload an IPsec capture; the analyzer reconstructs every tunnel, checks it against NIST SP 800-77r1 / RFC 8221 policy, scores anomalies, and
          produces a remediation report.
        </p>
      </section>

      <div className="ba">
        <div className="card before">
          <h2>Before — manual, reactive</h2>
          <ul className="small">
            <li>Open the capture in a packet viewer and read IKE packets one by one</li>
            <li>Expert knowledge needed to decode transforms and DH groups</li>
            <li>No view of the whole tunnel lifecycle (init → auth → child SA → rekey)</li>
            <li>Weak ciphers and aggressive-mode PSK stay hidden until exploited</li>
          </ul>
        </div>
        <div className="card after">
          <h2>After — automated assessment</h2>
          <ul className="small">
            <li>One upload → every tunnel reconstructed and risk-ranked</li>
            <li>YAML policy pack + behavioural anomaly model with SHAP explanations</li>
            <li>Findings mapped to MITRE ATT&amp;CK with concrete remediation</li>
            <li>Audit-ready PDF plus JSON / syslog export for SIEM</li>
          </ul>
        </div>
      </div>

      <div className="card">
        <h2>Pipeline</h2>
        <Pipeline stage={running ? (running.status === "queued" ? "capture" : running.stage) : null} />
        {running && running.status !== "failed" && (
          <p className="small muted" role="status" style={{ margin: "10px 0 0" }}>
            <span className="spinner" /> {running.filename}: {running.stage}…
          </p>
        )}
      </div>

      {error && <ErrorBox error={error} retry={() => setError(null)} />}

      <div className="grid g2">
        <div className="card">
          <h2>Analyze a capture</h2>
          <div className={`drop ${over ? "over" : ""}`} onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={onDrop}>
            {pcap ? <b>{pcap.name}</b> : <span className="muted">Drop a .pcap / .pcapng here</span>}
            <div style={{ marginTop: 10 }}>
              <label className="btn">
                Choose capture…
                <input type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => setPcap(e.target.files?.[0] ?? null)} />
              </label>
            </div>
          </div>
          <p className="small muted" style={{ margin: "10px 0 6px" }}>
            Optional: IKEv2 decryption keys (Wireshark <code>ikev2_decryption_table</code> format). Without them IKEv2 authentication and child SAs
            are encrypted and reported as <i>not assessable</i>.
          </p>
          <div className="row">
            <label className="btn">
              {keys ? keys.name : "Add key file…"}
              <input type="file" hidden onChange={(e) => setKeys(e.target.files?.[0] ?? null)} />
            </label>
            <button className="primary" disabled={!pcap || busy} onClick={() => pcap && start(() => api.upload(pcap, keys))}>
              Analyze
            </button>
          </div>
        </div>

        <div className="card">
          <h2>Or use a bundled capture</h2>
          {samples == null && !error ? <Loading what="Loading samples" /> : samples && samples.length === 0 ? (
            <Empty>No bundled captures found. Run <code>python -m synth.generate</code>.</Empty>
          ) : (
            <div className="stack">
              {samples?.map((s) => (
                <div key={s.name} className="row spread" style={{ alignItems: "flex-start" }}>
                  <div>
                    <b className="mono">{s.name}</b> <Prov p={s.provenance} />
                    <div className="small muted">{s.description}</div>
                  </div>
                  <button disabled={busy} onClick={() => start(() => api.analyzeSample(s.name))}>Analyze</button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="card">
        <h2>Recent analyses</h2>
        {history.length === 0 ? <Empty>Nothing analysed yet.</Empty> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>#</th><th>Capture</th><th>Provenance</th><th>Status</th><th>Tunnels</th><th /></tr></thead>
              <tbody>
                {history.map((a) => (
                  <tr key={a.id} className={a.status === "done" ? "click" : ""} onClick={() => a.status === "done" && (window.location.hash = `#/a/${a.id}`)}>
                    <td>{a.id}</td>
                    <td className="mono">{a.filename}</td>
                    <td><Prov p={a.provenance} /></td>
                    <td>{a.status === "failed" ? <span className="badge critical">failed</span> : a.status === "done" ? <span className="badge ok">done</span> : <span className="spinner" />}</td>
                    <td>{a.summary?.tunnel_count ?? "–"}</td>
                    <td><button onClick={(e) => { e.stopPropagation(); api.remove(a.id).then(load); }} aria-label={`Delete analysis ${a.id}`}>Delete</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
