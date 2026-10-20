import { DragEvent, useCallback, useEffect, useRef, useState } from "react";
import { Analysis, Json, Sample, User, api, isCapture } from "../api";
import { Empty, ErrorBox, Loading, Prov, Sev } from "../ui";

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

const KINDS: [string, string][] = [
  ["all", "All"], ["tour", "Full audit"], ["weak", "Weak crypto"], ["downgrade", "Downgrade"], ["anomaly", "Behaviour"], ["baseline", "Clean"], ["real", "Third-party"], ["log", "Daemon logs"],
];

function Card({ s, busy, active, onOpen }: { s: Sample; busy: boolean; active: boolean; onOpen: () => void }) {
  const p = s.preview;
  const shown = p?.rules.slice(0, 3) ?? [];
  return (
    <li className={`gal-card${s.order === 0 ? " featured" : ""}`}>
      <div className="gal-top"><Prov p={s.provenance} />{s.has_keys && <span className="chip" title="A decryption key file ships with this capture">keys included</span>}</div>
      <h3>{s.title}</h3>
      <p className="small muted gal-story">{s.story}</p>
      <div className="gal-result" aria-label="Result preview">
        {p == null ? <span className="small muted"><span className="spinner" /> scoring…</span> : (
          <>
            <span className="gal-score">{p.top_score ?? "n/a"}</span>
            {p.top_band && <Sev level={p.top_band} />}
            <span className="small muted">{p.tunnels} tunnel{p.tunnels === 1 ? "" : "s"} · {p.violations === 0 ? "no violations" : `${p.violations} violation${p.violations === 1 ? "" : "s"}`}{p.anomalous > 0 ? ` · ${p.anomalous} anomalous` : ""}</span>
          </>
        )}
      </div>
      <div className="gal-rules">
        {shown.map((r) => <span key={r.rule_id} className={`chip ${r.severity}`}>{r.rule_id}</span>)}
        {p && p.rule_count > shown.length && <span className="small muted">+{p.rule_count - shown.length} more</span>}
      </div>
      <button className={s.order === 0 ? "primary" : ""} disabled={busy} onClick={onOpen} aria-label={`Analyze ${s.name}`}>
        {active ? <><span className="spinner" /> Analysing…</> : "See the analysis →"}
      </button>
    </li>
  );
}

function LiveIngest({ status }: { status: Json | null }) {
  if (!status) return null;
  const w = status.watch, sl = status.syslog;
  const open = (id: number | null) => id != null && (window.location.hash = `#/a/${id}`);
  return (
    <section className="az-live card" aria-label="Live ingest">
      <h2>Live ingest</h2>
      {!w.enabled && !sl.enabled ? (
        <p className="small muted">
          Off. Set <code>WATCH_DIR</code> on the server to analyse every capture or strongSwan log dropped into a folder, and/or <code>SYSLOG_LISTEN=0.0.0.0:5514</code> to
          receive a gateway's charon log over UDP syslog. Neither is on by default; see the README.
        </p>
      ) : (
        <>
          {w.enabled && (
            <p className="small">
              <b>Watching</b> <code>{w.dirs.join(", ")}</code> every {w.interval_s}s; a file is read once it has been unchanged for {w.stable_s}s.
              {w.files.length === 0 ? " Nothing seen yet." : ` ${w.files.length} file${w.files.length === 1 ? "" : "s"} tracked.`}
            </p>
          )}
          {sl.enabled && (
            <p className="small">
              <b>Syslog</b> listening on <code>{sl.listen}</code> (UDP){sl.allow.length ? `, only from ${sl.allow.join(", ")}` : ", any source"}.{" "}
              {sl.sources.length === 0 ? "No gateway has sent anything yet." : sl.sources.map((x: Json) => `${x.source}: ${x.lines} lines`).join("; ")}
              {sl.ignored > 0 && ` · ${sl.ignored} datagram${sl.ignored === 1 ? "" : "s"} ignored (not charon lines, or a source not allowed)`}
            </p>
          )}
          {w.files.length > 0 && (
            <div className="tablewrap">
              <table>
                <thead><tr><th>File</th><th>Kind</th><th>Last read</th><th /></tr></thead>
                <tbody>
                  {w.files.slice(0, 8).map((f: Json) => (
                    <tr key={f.path} className={f.analysis_id != null ? "click" : ""} onClick={() => open(f.analysis_id)}>
                      <td className="mono">{f.path}</td>
                      <td>{f.kind}</td>
                      <td>{f.at ? new Date(f.at * 1000).toLocaleTimeString() : "–"}</td>
                      <td>{f.error ? <span className="badge critical" title={f.error}>{f.error.slice(0, 60)}</span> : <span className="badge ok">analysed</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </section>
  );
}

export default function Analyze() {
  const [samples, setSamples] = useState<Sample[] | null>(null);
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [history, setHistory] = useState<Analysis[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<Analysis | null>(null);
  const [pcap, setPcap] = useState<File | null>(null);
  const [keys, setKeys] = useState<File | null>(null);
  const [over, setOver] = useState(false);
  const [kind, setKind] = useState("all");
  const [ingest, setIngest] = useState<Json | null>(null);
  const timer = useRef<number | null>(null);

  const load = useCallback(() => {
    api.samples().then(setSamples).catch((e) => setError(e.message));
    api.analyses().then(setHistory).catch(() => undefined);
    api.account().then((a) => setUser(a.user)).catch(() => setUser(null));
    api.ingest().then(setIngest).catch(() => undefined);
  }, []);
  useEffect(load, [load]);
  useEffect(() => () => { if (timer.current) window.clearTimeout(timer.current); }, []);
  // The server scores the bundled captures in the background right after it starts; refresh until every card has its numbers.
  const waiting = samples != null && samples.some((x) => x.preview == null);
  useEffect(() => {
    if (!waiting) return;
    const t = window.setTimeout(() => api.samples().then(setSamples).catch(() => undefined), 1500);
    return () => window.clearTimeout(t);
  }, [waiting, samples]);

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
  const isLog = pcap != null && !isCapture(pcap.name);

  return (
    <div className="az">
      <header className="az-hero">
        <h1>Automate IPsec/IKE security assessment</h1>
        <p>
          Upload a packet capture, or a strongSwan daemon log, to reconstruct tunnels, check them against NIST SP 800-77r1 and RFC 8221, score behavioural anomalies, and
          export an audit-ready report (PDF, JSON, syslog).
        </p>
      </header>

      {error && <ErrorBox error={error} retry={() => setError(null)} />}

      <section className="az-gallery" aria-label="Sample gallery">
        <div className="gal-head">
          <div>
            <h2>Try it now, no capture needed</h2>
            <p className="small muted">One click analyses a bundled capture end to end. Each card shows the result computed from that capture.</p>
          </div>
          <div className="gal-filter" role="group" aria-label="Filter samples">
            {KINDS.filter(([k]) => k === "all" || samples?.some((x) => x.kind === k)).map(([k, label]) => (
              <button key={k} aria-pressed={kind === k} className={kind === k ? "on" : ""} onClick={() => setKind(k)}>{label}</button>
            ))}
          </div>
        </div>
        {samples == null && !error ? <Loading what="Loading samples" /> : samples && samples.length === 0 ? (
          <Empty>No bundled captures found. Run <code>python -m synth.generate</code>.</Empty>
        ) : (
          <ul className="gal-grid" aria-label="Bundled captures">
            {samples?.filter((x) => kind === "all" || x.kind === kind).map((x) => (
              <Card key={x.name} s={x} busy={busy} active={running?.filename === x.name && running.status !== "failed"} onOpen={() => start(() => api.analyzeSample(x.name))} />
            ))}
          </ul>
        )}
        {running && running.status !== "failed" && (
          <p className="small az-status" role="status"><span className="spinner" /> {running.filename}: {running.stage}…</p>
        )}
      </section>

      <div className="az-work">
        <section className="az-primary" aria-label="Analyze a capture">
          <h2>Or analyze your own capture or log</h2>
          <div className={`az-drop ${over ? "over" : ""}`} onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)} onDrop={onDrop}>
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 16V5m0 0l-4 4m4-4l4 4M5 19h14" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
            {pcap ? <b className="mono az-file">{pcap.name}</b> : <span>Drop a .pcap / .pcapng, or a strongSwan .log, here</span>}
            <label className="btn">
              {pcap ? "Choose a different capture…" : "Choose capture…"}
              <input type="file" accept=".pcap,.pcapng,.cap,.log,.txt" hidden onChange={(e) => setPcap(e.target.files?.[0] ?? null)} />
            </label>
          </div>
          <div className="az-actions">
            <div className="az-keys">
              <label className="btn">
                {keys ? keys.name : "Add key file…"}
                <input type="file" hidden onChange={(e) => setKeys(e.target.files?.[0] ?? null)} />
              </label>
              <p className="small muted">
                Optional decryption keys for captures (Wireshark <code>ikev2_decryption_table</code> or <code>ikev1_decryption_table</code>, one file can hold both). Without them IKEv2 authentication
                and child SAs, and IKEv1 Quick Mode, are reported as <i>not assessable</i>. A daemon log needs no keys: it already states what was negotiated.
              </p>
            </div>
            <button className="primary az-go" disabled={!pcap || busy} onClick={() => pcap && start(() => (isLog ? api.uploadLog(pcap) : api.upload(pcap, keys)))}>
              {isLog ? "Analyze log →" : "Analyze capture →"}
            </button>
          </div>
        </section>
      </div>

      <LiveIngest status={ingest} />

      <section className="az-pipeline" aria-label="How it works">
        <Pipeline stage={running ? (running.status === "queued" ? "capture" : running.stage) : null} />
      </section>

      <section className="az-recent">
        <h2>{user ? "Your recent analyses" : "Recent analyses"}</h2>
        {user === null && (
          <p className="small muted az-note">
            These are shared demo analyses. <a href="#/account">Sign in</a> to keep your own private and saved between visits.
          </p>
        )}
        {user && <p className="small muted az-note">Saved to {user.email}. <a href="#/history">Open full history</a></p>}
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
