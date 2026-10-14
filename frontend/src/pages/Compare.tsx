import { useEffect, useState } from "react";
import { Analysis, Json, api } from "../api";
import { Empty, ErrorBox, Loading, Meter, Prov, Sev } from "../ui";

const go = (b?: number, a?: number) => { window.location.hash = `#/compare/${b ?? 0}/${a ?? 0}`; };

function Picker({ label, value, options, onChange }: { label: string; value?: number; options: Analysis[]; onChange: (id: number) => void }) {
  const id = `cmp-${label.toLowerCase()}`;
  return (
    <div className="cmp-pick">
      <label className="small muted" htmlFor={id}>{label}</label>
      <select id={id} value={value ?? ""} onChange={(e) => onChange(Number(e.target.value))}>
        <option value="" disabled>Choose an analysis…</option>
        {options.map((a) => <option key={a.id} value={a.id}>#{a.id} · {a.filename} ({a.summary?.tunnel_count ?? 0} tunnel{a.summary?.tunnel_count === 1 ? "" : "s"})</option>)}
      </select>
    </div>
  );
}

function Side({ title, a, s }: { title: string; a: Analysis; s: Json }) {
  return (
    <div className="cmp-side">
      <div className="small muted">{title}</div>
      <div className="row" style={{ gap: "var(--sp-2)" }}><a className="mono" href={`#/a/${a.id}`}>#{a.id} · {a.filename}</a><Prov p={a.provenance} /></div>
      <div className="score-row">
        <span className="hero-score">{s.max_score ?? "n/a"}</span>
        {s.max_band && <Sev level={s.max_band} />}
      </div>
      {s.max_band && <Meter score={s.max_score} band={s.max_band} />}
      <div className="small muted">highest risk · {s.tunnels} tunnel{s.tunnels === 1 ? "" : "s"} · {s.violations} violation{s.violations === 1 ? "" : "s"}</div>
    </div>
  );
}

function Delta({ d }: { d: number | null }) {
  if (d == null) return <span className="muted">–</span>;
  if (d === 0) return <span className="muted">no change</span>;
  return <span className={d < 0 ? "delta down" : "delta up"}>{d < 0 ? "▼" : "▲"} {Math.abs(d)}</span>;
}

function RuleList({ title, rules, cls, empty }: { title: string; rules: Json[]; cls: string; empty: string }) {
  return (
    <div className={`cmp-rules ${cls}`}>
      <h3>{title} ({rules.length})</h3>
      {rules.length === 0 ? <p className="small muted">{empty}</p> : (
        <ul>{rules.map((r) => <li key={r.rule_id}><Sev level={r.severity} /> <span className="mono">{r.rule_id}</span> <span className="small muted">{r.title}</span></li>)}</ul>
      )}
    </div>
  );
}

export default function Compare({ before, after }: { before?: number; after?: number }) {
  const [list, setList] = useState<Analysis[] | null>(null);
  const [res, setRes] = useState<Json | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => { api.analyses().then((l) => setList(l.filter((a) => a.status === "done"))).catch((e) => setError(e.message)); }, []);
  const load = () => {
    setRes(null);
    setError(null);
    if (before && after) api.compare(before, after).then(setRes).catch((e) => setError(e.message));
  };
  useEffect(load, [before, after]);

  if (!list) return error ? <ErrorBox error={error} /> : <Loading what="Loading analyses" />;
  const s = res;
  const drop = s && s.before.max_score != null && s.after.max_score != null ? Math.round((s.before.max_score - s.after.max_score) * 10) / 10 : null;

  return (
    <div className="res">
      <header className="res-head">
        <h1>Compare two analyses</h1>
        <p className="small muted">Pick a capture taken before a configuration change and one taken after. Tunnels are matched by their peer addresses.</p>
      </header>
      {list.length < 2 ? <Empty>Run at least two analyses first, for example a weak lab capture and a strong one.</Empty> : (
        <div className="card cmp-pickers">
          <Picker label="Before" value={before} options={list} onChange={(id) => go(id, after)} />
          <button onClick={() => go(after, before)} disabled={!before || !after} aria-label="Swap before and after">⇄ Swap</button>
          <Picker label="After" value={after} options={list} onChange={(id) => go(before, id)} />
        </div>
      )}
      {error && <ErrorBox error={error} retry={load} />}
      {before && after && !s && !error && <Loading what="Comparing" />}
      {s && (
        <>
          <section className="card cmp-summary" aria-label="Comparison summary">
            <Side title="Before" a={s.before_analysis} s={s.before} />
            <div className="cmp-mid">
              {drop == null ? <span className="muted">n/a</span> : drop > 0
                ? <><span className="big delta down">▼ {drop}</span><span className="small muted">risk reduced</span></>
                : drop < 0 ? <><span className="big delta up">▲ {-drop}</span><span className="small muted">risk increased</span></>
                : <><span className="big muted">0</span><span className="small muted">no change in highest risk</span></>}
              <span className="small muted">{s.rules.fixed.length} rule{s.rules.fixed.length === 1 ? "" : "s"} fixed · {s.rules.new.length} new · {s.rules.remaining.length} remaining</span>
            </div>
            <Side title="After" a={s.after_analysis} s={s.after} />
          </section>

          <section className="res-section">
            <div className="sec-head"><h2>Policy rules</h2><span className="small muted">rules violated by any tunnel in each capture</span></div>
            <div className="cmp-rulegrid">
              <RuleList title="Fixed" rules={s.rules.fixed} cls="fixed" empty="None of the earlier violations went away." />
              <RuleList title="New" rules={s.rules.new} cls="new" empty="No new violations." />
              <RuleList title="Still present" rules={s.rules.remaining} cls="remaining" empty="Nothing left over." />
            </div>
          </section>

          <section className="res-section">
            <div className="sec-head"><h2>Tunnels</h2><span className="small muted">matched by peer pair, biggest improvement first</span></div>
            {s.tunnels.length === 0 ? <Empty>Neither capture contains tunnels.</Empty> : (
              <div className="tablewrap">
                <table>
                  <thead><tr><th>Peers</th><th>Before</th><th>After</th><th>Change</th><th>Rules fixed / new</th></tr></thead>
                  <tbody>
                    {s.tunnels.map((r: Json, i: number) => (
                      <tr key={i}>
                        <td className="mono">{r.initiator} → {r.responder}</td>
                        {[["before", s.before_analysis.id], ["after", s.after_analysis.id]].map(([k, aid]) => {
                          const t = r[k as string];
                          return (
                            <td key={k as string}>
                              {t ? (
                                <a href={`#/a/${aid}/t/${encodeURIComponent(t.id)}`} className="cmp-cell">
                                  <span className="score">{t.score}</span> <Sev level={t.band} />
                                  <div className="mono small muted">{t.suite ?? "none negotiated"}</div>
                                </a>
                              ) : <span className="muted small">not in this capture</span>}
                            </td>
                          );
                        })}
                        <td><Delta d={r.delta} /></td>
                        <td>
                          {r.fixed.map((id: string) => <span key={id} className="chip fixed" title="fixed">✓ {id}</span>)}
                          {r.new.map((id: string) => <span key={id} className="chip new" title="new">+ {id}</span>)}
                          {r.fixed.length + r.new.length === 0 && <span className="muted small">{r.before && r.after ? "same rules" : "–"}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
