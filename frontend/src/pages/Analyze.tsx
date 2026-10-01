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
    <ol className="az-flow" aria-label="Analysis pipeline">
      {STEPS.map((s, i) => (
        <li key={s.key} className={i < idx ? "done" : i === idx ? "active" : ""}>
          <span className="n" aria-hidden="true">{i + 1}</span>
          <span><b>{s.title}</b><small>{s.sub}</small></span>
        </li>
      ))}
    </ol>
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
    <div className="az">
      <header className="az-hero">
        <h1>Automate IPsec/IKE security assessment</h1>
        <p>
          Upload a packet capture to reconstruct tunnels, check them against NIST SP 800-77r1 and RFC 8221, score behavioural anomalies, and
          export an audit-ready report (PDF, JSON, syslog).
        </p>
      </header>

      {error && <ErrorBox error={error} retry={() => setError(null)} />}

      <div className="az-work">
        <section className="az-primary" aria-label="Analyze a capture">
          <div className={`az-drop ${over ? "over" : ""}`} onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={onDrop}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V5m0 0l-4 4m4-4l4 4M5 19h14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
            {pcap ? <b className="mono az-file">{pcap.name}</b> : <span>Drop a .pcap / .pcapng here</span>}
            <label className="btn">
              {pcap ? "Choose a different capture…" : "Choose capture…"}
              <input type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => setPcap(e.target.files?.[0] ?? null)} />
            </label>
          </div>
          <div className="az-actions">
            <div className="az-keys">
              <label className="btn">
                {keys ? keys.name : "Add key file…"}
                <input type="file" hidden onChange={(e) => setKeys(e.target.files?.[0] ?? null)} />
              </label>
              <p className="small muted">
                Optional IKEv2 decryption keys (Wireshark <code>ikev2_decryption_table</code>). Without them IKEv2 authentication and child SAs
                are reported as <i>not assessable</i>.
              </p>
            </div>
            <button className="primary az-go" disabled={!pcap || busy} onClick={() => pcap && start(() => api.upload(pcap, keys))}>
              Analyze capture →
            </button>
          </div>
          {running && running.status !== "failed" && (
            <p className="small az-status" role="status"><span className="spinner" /> {running.filename}: {running.stage}…</p>
          )}
        </section>

        <section className="az-samples" aria-label="Bundled captures">
          <h2>Or try a bundled capture</h2>
          {samples == null && !error ? <Loading what="Loading samples" /> : samples && samples.length === 0 ? (
            <Empty>No bundled captures found. Run <code>python -m synth.generate</code>.</Empty>
          ) : (
            <ul tabIndex={0} aria-label="Bundled captures list">
              {samples?.map((s) => (
                <li key={s.name}>
                  <div className="name"><b className="mono">{s.name}</b><Prov p={s.provenance} /></div>
                  <div className="desc small muted" title={s.description}>{s.description}</div>
                  <div className="meta">
                    {s.has_keys && <span className="chip" title="A decryption key file ships with this capture">decryption keys included</span>}
                  </div>
                  <button disabled={busy} onClick={() => start(() => api.analyzeSample(s.name))} aria-label={`Analyze ${s.name}`}>Analyze →</button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <section className="az-pipeline" aria-label="How it works">
        <Pipeline stage={running ? (running.status === "queued" ? "capture" : running.stage) : null} />
      </section>

      <section className="az-recent">
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
      </section>
    </div>
  );
}
