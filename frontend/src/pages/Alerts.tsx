import { useCallback, useEffect, useState } from "react";
import { AccountState, AlertEvent, AlertSettings, api } from "../api";
import { ErrorBox, Loading } from "../ui";

const bandFor = (v: number) => (v >= 55 ? "critical" : v >= 33 ? "high" : v >= 15 ? "medium" : "low");

function Switch({ id, checked, onChange, label }: { id: string; checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <label className="switch" htmlFor={id}>
      <input id={id} type="checkbox" role="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

export default function Alerts({ account }: { account: AccountState }) {
  const [cfg, setCfg] = useState<AlertSettings | null>(null);
  const [events, setEvents] = useState<AlertEvent[]>([]);
  const [url, setUrl] = useState("");
  const [urlDirty, setUrlDirty] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [showSecret, setShowSecret] = useState(false);

  const load = useCallback(() => {
    api.alerts().then((r) => { setCfg(r.settings); setEvents(r.events); }).catch((e) => setError(e.message));
  }, []);
  useEffect(() => { if (account.user) load(); }, [load, account.user?.id]);

  if (!account.user) {
    return (
      <div className="card login" style={{ textAlign: "center" }}>
        <h2>Alerts</h2>
        <p className="small muted">Sign in to be emailed, or get a webhook call, when one of your analyses finds a high-risk tunnel.</p>
        <a className="btn primary" href="#/account">Sign in or create an account</a>
      </div>
    );
  }
  if (error) return <ErrorBox error={error} retry={() => { setError(null); load(); }} />;
  if (!cfg) return <Loading what="Loading alert settings" />;

  const patch = (p: Parameters<typeof api.saveAlerts>[0]) => setCfg({ ...cfg, ...(p as Partial<AlertSettings>) });
  const save = async (extra: Parameters<typeof api.saveAlerts>[0] = {}): Promise<boolean> => {
    setBusy(true);
    setMsg(null);
    try {
      const body = { enabled: cfg.enabled, min_risk: cfg.min_risk, email_enabled: cfg.email_enabled, email_to: cfg.email_to,
        webhook_enabled: cfg.webhook_enabled, ...(urlDirty ? { webhook_url: url.trim() } : {}), ...extra };
      setCfg(await api.saveAlerts(body));
      setUrlDirty(false);
      setUrl("");
      setMsg({ ok: true, text: "Saved." });
      return true;
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
      return false;
    } finally {
      setBusy(false);
    }
  };
  const test = async () => {
    setBusy(true);
    setMsg(null);
    try {
      if (!(await save())) return;  // keep the save error (e.g. a blocked address) on screen instead of testing stale settings
      const r = await api.testAlerts();
      const bad = r.results.filter((x) => x.status === "failed");
      setMsg(bad.length ? { ok: false, text: bad.map((b) => `${b.channel}: ${b.detail}`).join(" · ") }
        : { ok: true, text: `Test sent via ${r.results.map((x) => x.channel).join(" and ")}.` });
      load();
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const nothingOn = !cfg.email_enabled && !cfg.webhook_enabled;
  const band = bandFor(cfg.min_risk);

  return (
    <div className="stack alerts">
      <div>
        <h1>Alerts</h1>
        <p className="small muted">
          Get told when an analysis you run while signed in contains a tunnel at or above your risk threshold. Alerts fire once per analysis, after the
          results are saved, and only for your own analyses.
        </p>
      </div>

      <form className="card stack" onSubmit={(e) => { e.preventDefault(); save(); }} aria-label="Alert settings">
        <Switch id="al-on" checked={cfg.enabled} onChange={(v) => patch({ enabled: v })} label="Send alerts for my analyses" />

        <fieldset disabled={!cfg.enabled} className="al-fs">
          <legend>Threshold</legend>
          <div className="row">
            <input id="al-risk" type="range" min={1} max={100} step={1} value={cfg.min_risk} aria-label="Risk threshold"
              onChange={(e) => patch({ min_risk: Number(e.target.value) })} />
            <b className="al-val" aria-live="polite">{cfg.min_risk}</b>
            <span className={`badge ${band}`}>{band}+</span>
          </div>
          <p className="small muted">Alert when any tunnel's risk score (0–100) is at least this. 33 is the policy's <i>high</i> band, 55 is <i>critical</i>.</p>
        </fieldset>

        <fieldset disabled={!cfg.enabled} className="al-fs">
          <legend>Email</legend>
          {!cfg.smtp_available && (
            <div className="banner small">This server has no mail server configured (<code>SMTP_HOST</code>), so email alerts cannot be delivered here. Use a webhook, or ask whoever runs it to set SMTP.</div>
          )}
          <Switch id="al-email" checked={cfg.email_enabled} onChange={(v) => patch({ email_enabled: v })} label="Email me" />
          <label className="small" htmlFor="al-to">Send to</label>
          <input id="al-to" type="email" value={cfg.email_to} onChange={(e) => patch({ email_to: e.target.value })} disabled={!cfg.email_enabled} />
        </fieldset>

        <fieldset disabled={!cfg.enabled} className="al-fs">
          <legend>Webhook</legend>
          <Switch id="al-hook" checked={cfg.webhook_enabled} onChange={(v) => patch({ webhook_enabled: v })} label="Call a webhook" />
          <label className="small" htmlFor="al-url">Receiver URL</label>
          <input id="al-url" type="url" inputMode="url" autoComplete="off" spellCheck={false} value={urlDirty ? url : ""}
            placeholder={cfg.webhook_url ? `${cfg.webhook_url} (saved, hidden)` : "https://hooks.example.com/…"}
            onChange={(e) => { setUrl(e.target.value); setUrlDirty(true); }} />
          <p className="small muted">
            The body is JSON with <code>text</code> and <code>content</code> fields, so Slack, Teams and Discord incoming webhooks work as-is. Every request carries
            <code> X-Signature: sha256=&lt;HMAC-SHA256 of the raw body&gt;</code> using the secret below. Private and internal addresses are blocked{cfg.allow_private ? " (this server allows them)" : ""}.
          </p>
          {cfg.webhook_secret && (
            <div className="row al-secret">
              <span className="small muted">Signing secret</span>
              <code>{showSecret ? cfg.webhook_secret : "•".repeat(16)}</code>
              <button type="button" onClick={() => setShowSecret(!showSecret)}>{showSecret ? "Hide" : "Show"}</button>
              <button type="button" onClick={() => navigator.clipboard?.writeText(cfg.webhook_secret ?? "")}>Copy</button>
              <button type="button" onClick={() => save({ rotate_secret: true })}>Rotate</button>
            </div>
          )}
        </fieldset>

        {msg && <div className={`banner small ${msg.ok ? "" : "err"}`} role={msg.ok ? "status" : "alert"}>{msg.text}</div>}
        <div className="row">
          <button className="primary" disabled={busy}>Save</button>
          <button type="button" disabled={busy || nothingOn} onClick={test} title={nothingOn ? "Turn on email or a webhook first" : "Saves, then sends a clearly labelled test message"}>Save and send test</button>
        </div>
      </form>

      <section className="card" aria-label="Delivery log">
        <h2>Recent deliveries</h2>
        {events.length === 0 ? <p className="small muted">Nothing sent yet. Alerts and tests show up here, including failures and why.</p> : (
          <div className="tablewrap">
            <table>
              <thead><tr><th>When</th><th>Channel</th><th>Result</th><th>For</th><th>Detail</th></tr></thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id}>
                    <td className="small">{new Date(e.created_at).toLocaleString()}</td>
                    <td>{e.channel}</td>
                    <td><span className={`badge ${e.status === "sent" ? "ok" : "critical"}`}>{e.status}</span></td>
                    <td className="small">{e.test ? "test message" : <a href={`#/a/${e.analysis_id}`}>analysis {e.analysis_id} · {e.tunnels} tunnel{e.tunnels === 1 ? "" : "s"} · top {e.top_risk}</a>}</td>
                    <td className="small muted">{e.detail}</td>
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
