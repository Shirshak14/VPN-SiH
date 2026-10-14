import { useEffect, useState } from "react";
import { Json, api } from "../api";
import { Sev } from "../ui";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const MIN_GAP = 2.2; // % of the axis; closer dots stack into the next row

// Risk strip: one dot per tunnel on the 0-100 risk axis, over the policy's band zones.
function RiskStrip({ tunnels, bands, href }: { tunnels: Json[]; bands: Record<string, number>; href: (id: string) => string }) {
  const [hover, setHover] = useState<{ t: Json; x: number; row: number } | null>(null);
  const zones = Object.entries(bands).sort((a, b) => a[1] - b[1]); // low -> critical
  const edges: [string, number, number][] = [["info", 0, zones[0]?.[1] ?? 100]];
  zones.forEach(([band, lo], i) => edges.push([band, lo, zones[i + 1]?.[1] ?? 100]));
  const lastX: number[] = [];
  const dots = [...tunnels].sort((a, b) => a.risk.score - b.risk.score).map((t) => {
    const x = Math.max(0, Math.min(100, t.risk.score));
    let row = lastX.findIndex((lx) => x - lx >= MIN_GAP);
    if (row < 0) row = lastX.length;
    lastX[row] = x;
    return { t, x, row };
  });
  const rows = Math.max(1, lastX.length);
  return (
    <div className="ov-strip" role="img" aria-label={`Risk of ${tunnels.length} tunnels on a 0 to 100 scale; the table below lists every value`}>
      <div className="ov-plot" style={{ height: Math.max(40, rows * 16 + 16) }}>
        {edges.map(([band, lo, hi]) => <div key={band} className={`ov-zone ${band}`} style={{ left: `${lo}%`, width: `${hi - lo}%` }} />)}
        {dots.map((d) => (
          <a key={d.t.id} href={href(d.t.id)} className={`ov-dot ${d.t.risk.band}`} style={{ left: `${d.x}%`, bottom: 8 + d.row * 16 }}
             aria-label={`${d.t.initiator} to ${d.t.responder}, risk ${d.t.risk.score}`}
             onMouseEnter={() => setHover(d)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(d)} onBlur={() => setHover(null)} />
        ))}
        {hover && (
          <div className="ov-tip" style={{ left: `${hover.x}%`, bottom: 8 + hover.row * 16 + 20 }}>
            <div className="mono">{hover.t.initiator} → {hover.t.responder}</div>
            <div><b>{hover.t.risk.score}</b> <Sev level={hover.t.risk.band} /> · {hover.t.violations.length} violation{hover.t.violations.length === 1 ? "" : "s"}</div>
          </div>
        )}
      </div>
      <div className="ov-axis">
        {edges.map(([band, lo, hi]) => (
          <span key={band} style={{ left: `${lo}%`, width: `${hi - lo}%` }}>{hi - lo >= 12 ? band : ""}</span>
        ))}
      </div>
      <div className="ov-ticks small muted">{[0, ...zones.map(([, v]) => v), 100].filter((v, i, a) => i === 0 || v - a[i - 1] >= 6 || v === 100).map((v) => <span key={v} style={{ left: `${v}%` }}>{v}</span>)}</div>
    </div>
  );
}

// ATT&CK coverage: each technique the rule findings map to, with how many tunnels it touches.
function Attack({ tunnels }: { tunnels: Json[] }) {
  const m = new Map<string, { tech: Json; tunnels: number; sev: string }>();
  for (const t of tunnels) {
    for (const tech of t.mitre ?? []) {
      const sev = t.violations.filter((v: Json) => v.mitre?.includes(tech.id)).reduce((s: string, v: Json) => (SEV_RANK[v.severity] < SEV_RANK[s] ? v.severity : s), "info");
      const e = m.get(tech.id);
      if (e) { e.tunnels += 1; if (SEV_RANK[sev] < SEV_RANK[e.sev]) e.sev = sev; }
      else m.set(tech.id, { tech, tunnels: 1, sev });
    }
  }
  const rows = [...m.values()].sort((a, b) => b.tunnels - a.tunnels || SEV_RANK[a.sev] - SEV_RANK[b.sev]);
  if (rows.length === 0) return <p className="small muted">No rule finding in this capture maps to an ATT&CK technique.</p>;
  return (
    <ul className="ov-attack">
      {rows.map((r) => (
        <li key={r.tech.id}>
          <a href={r.tech.url} target="_blank" rel="noreferrer" className="mono">{r.tech.id}</a>
          <span><span>{r.tech.name}</span><span className="small muted" style={{ display: "block" }}>{r.tech.tactic}</span></span>
          <span className="ov-bar" title={`${r.tunnels} of ${tunnels.length} tunnels`}><i style={{ width: `${(r.tunnels / tunnels.length) * 100}%` }} /></span>
          <span className="small"><b>{r.tunnels}</b>/{tunnels.length}</span>
          <Sev level={r.sev} />
        </li>
      ))}
    </ul>
  );
}

export default function Overview({ tunnels, href }: { tunnels: Json[]; href: (id: string) => string }) {
  const [bands, setBands] = useState<Record<string, number> | null>(null);
  useEffect(() => { api.policy().then((p) => setBands(p.risk.bands)).catch(() => setBands({ low: 5, medium: 15, high: 33, critical: 55 })); }, []);
  if (tunnels.length === 0) return null;
  return (
    <section className="res-section">
      <div className="sec-head"><h2>Overview</h2><span className="small muted">hover or focus a dot for the tunnel, select it to open</span></div>
      <div className="ov-grid">
        <div className="card">
          <h3>Risk of every tunnel</h3>
          {bands && <RiskStrip tunnels={tunnels} bands={bands} href={href} />}
        </div>
        <div className="card">
          <h3>MITRE ATT&CK techniques</h3>
          <Attack tunnels={tunnels} />
        </div>
      </div>
    </section>
  );
}
