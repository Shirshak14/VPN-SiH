import { useCallback, useEffect, useState } from "react";
import { AccountState, Analysis, api } from "../api";
import { Empty, ErrorBox, Loading, Prov } from "../ui";

function Name({ a, onSaved }: { a: Analysis; onSaved: () => void }) {
  const [editing, setEditing] = useState(false);
  const [v, setV] = useState(a.label ?? "");
  const save = async () => {
    setEditing(false);
    if (v.trim() !== (a.label ?? "")) await api.rename(a.id, v).catch(() => undefined);
    onSaved();
  };
  if (!editing) {
    return (
      <button className="linklike name-btn" style={{ marginLeft: 0 }} onClick={(e) => { e.stopPropagation(); setV(a.label ?? ""); setEditing(true); }}
        aria-label={`Rename analysis ${a.id}`}>
        {a.label ?? <span className="muted">add a name</span>}
      </button>
    );
  }
  return (
    <input className="name-input" value={v} maxLength={120} autoFocus aria-label={`Name for analysis ${a.id}`} onClick={(e) => e.stopPropagation()}
      onChange={(e) => setV(e.target.value)} onBlur={save}
      onKeyDown={(e) => { if (e.key === "Enter") (e.target as HTMLInputElement).blur(); if (e.key === "Escape") { setV(a.label ?? ""); setEditing(false); } }} />
  );
}

export default function History({ account }: { account: AccountState }) {
  const [rows, setRows] = useState<Analysis[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<number[]>([]);
  const [confirmDel, setConfirmDel] = useState<number | null>(null);
  const load = useCallback(() => api.analyses().then(setRows).catch((e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load, account.user?.id]);
  // keep polling while something is still running so the list settles on its own
  useEffect(() => {
    if (!rows?.some((a) => a.status === "queued" || a.status === "running")) return;
    const t = window.setTimeout(load, 1500);
    return () => window.clearTimeout(t);
  }, [rows, load]);

  if (!account.user) {
    return (
      <div className="card login" style={{ textAlign: "center" }}>
        <h2>Saved analyses</h2>
        <p className="small muted">Sign in to keep your analyses private and find them again next time.</p>
        <a className="btn primary" href="#/account">Sign in or create an account</a>
      </div>
    );
  }
  const toggle = (id: number) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : p.length >= 2 ? [p[1], id] : [...p, id]));
  const done = (rows ?? []).filter((a) => a.status === "done");
  return (
    <div className="stack">
      <div className="row spread">
        <div>
          <h1>Saved analyses</h1>
          <p className="small muted">Private to {account.user.email}. Everything you analyse while signed in is kept here until you delete it.</p>
        </div>
        <div className="row">
          <button className="primary" disabled={picked.length !== 2}
            onClick={() => { const [x, y] = [...picked].sort((m, n) => m - n); window.location.hash = `#/compare/${x}/${y}`; }}>
            Compare selected{picked.length === 2 ? " (older → newer)" : ` (${picked.length}/2)`}
          </button>
          <a className="btn" href="#/">New analysis</a>
        </div>
      </div>
      {error && <ErrorBox error={error} retry={() => { setError(null); load(); }} />}
      {rows == null && !error ? <Loading what="Loading your analyses" /> : rows && rows.length === 0 ? (
        <Empty>No saved analyses yet. <a href="#/">Analyse a capture</a> while signed in and it will appear here.</Empty>
      ) : rows && (
        <div className="card tablewrap">
          <table>
            <thead><tr><th><span className="sr">Select</span></th><th>#</th><th>Name</th><th>Capture</th><th>Provenance</th><th>Saved</th><th>Status</th><th>Tunnels</th><th>Highest risk</th><th /></tr></thead>
            <tbody>
              {rows.map((a) => {
                const bands = a.summary?.bands as Record<string, number> | undefined;
                const worst = bands ? ["critical", "high", "medium", "low"].find((b) => bands[b]) : undefined;
                return (
                  <tr key={a.id} className={a.status === "done" ? "click" : ""} onClick={() => a.status === "done" && (window.location.hash = `#/a/${a.id}`)}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" aria-label={`Select analysis ${a.id} for comparison`} disabled={a.status !== "done"} checked={picked.includes(a.id)} onChange={() => toggle(a.id)} />
                    </td>
                    <td>{a.id}</td>
                    <td><Name a={a} onSaved={load} /></td>
                    <td className="mono">{a.filename}</td>
                    <td><Prov p={a.provenance} /></td>
                    <td className="small" title={a.created_at}>{new Date(a.created_at).toLocaleString()}</td>
                    <td>{a.status === "failed" ? <span className="badge critical" title={a.error ?? ""}>failed</span> : a.status === "done" ? <span className="badge ok">done</span> : <span className="spinner" />}</td>
                    <td>{a.summary?.tunnel_count ?? "–"}</td>
                    <td>{worst ? <span className={`badge ${worst}`}>{worst}</span> : "–"}</td>
                    <td>
                      {confirmDel === a.id ? (
                        <span className="row" onClick={(e) => e.stopPropagation()}>
                          <button className="danger-btn" aria-label={`Confirm delete analysis ${a.id}`}
                            onClick={() => api.remove(a.id).then(() => { setPicked((p) => p.filter((x) => x !== a.id)); setConfirmDel(null); load(); })}>Delete?</button>
                          <button onClick={() => setConfirmDel(null)}>Keep</button>
                        </span>
                      ) : (
                        <button onClick={(e) => { e.stopPropagation(); setConfirmDel(a.id); }} aria-label={`Delete analysis ${a.id}`}>Delete</button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {done.length === 1 && <p className="small muted">Save a second analysis to compare before/after a configuration change.</p>}
    </div>
  );
}
