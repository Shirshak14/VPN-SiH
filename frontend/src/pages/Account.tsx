import { useState } from "react";
import { AccountState, api } from "../api";

function Field({ id, label, hint, ...p }: { id: string; label: string; hint?: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <>
      <label className="small" htmlFor={id}>{label}</label>
      <input id={id} {...p} />
      {hint && <span className="small muted">{hint}</span>}
    </>
  );
}

function AuthForm({ open, onDone }: { open: boolean; onDone: () => void }) {
  const [mode, setMode] = useState<"in" | "up">("in");
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const up = mode === "up";
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await (up ? api.register(email, pw) : api.signIn(email, pw));
      onDone();
    } catch (x) {
      setErr(x instanceof Error ? x.message : "Something went wrong");
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card login" onSubmit={submit} aria-label={up ? "Create account" : "Sign in to your account"}>
      <h2>{up ? "Create an account" : "Sign in"}</h2>
      <p className="small muted">
        An account keeps your analyses private and saved between visits. Without one you can still analyse captures; those land in the shared demo space.
      </p>
      <Field id="acct-email" label="Email" type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus required />
      <Field id="acct-pw" label="Password" type="password" autoComplete={up ? "new-password" : "current-password"} value={pw}
        onChange={(e) => setPw(e.target.value)} required minLength={up ? 10 : undefined} hint={up ? "At least 10 characters." : undefined} />
      {err && <div className="banner err small" role="alert">{err}</div>}
      <button className="primary" disabled={!email || !pw || busy}>{up ? "Create account" : "Sign in"}</button>
      {open ? (
        <p className="small muted">
          {up ? "Already have an account?" : "New here?"}{" "}
          <button type="button" className="linklike" style={{ marginLeft: 0 }} onClick={() => { setMode(up ? "in" : "up"); setErr(""); }}>
            {up ? "Sign in" : "Create an account"}
          </button>
        </p>
      ) : (
        <p className="small muted">Registration is closed on this server.</p>
      )}
    </form>
  );
}

function Settings({ account, onChange }: { account: AccountState; onChange: () => void }) {
  const u = account.user!;
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [del, setDel] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [err, setErr] = useState("");

  const change = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.changePassword(cur, next);
      setCur("");
      setNext("");
      setMsg({ ok: true, text: "Password changed. Other browsers have been signed out." });
    } catch (x) {
      setMsg({ ok: false, text: (x as Error).message });
    }
  };
  const erase = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await api.deleteAccount(del);
      onChange();
      window.location.hash = "#/";
    } catch (x) {
      setErr((x as Error).message);
    }
  };
  return (
    <div className="stack acct">
      <div className="card">
        <h2>Account</h2>
        <p>Signed in as <b>{u.email}</b> <span className="muted small">· since {new Date(u.created_at).toLocaleDateString()}</span></p>
        <div className="row">
          <a className="btn" href="#/history">Saved analyses</a>
          <button onClick={() => api.signOut().then(onChange)}>Sign out</button>
        </div>
      </div>
      <form className="card login acct-form" onSubmit={change} aria-label="Change password">
        <h2>Change password</h2>
        <Field id="pw-cur" label="Current password" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} required />
        <Field id="pw-new" label="New password" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required minLength={10} hint="At least 10 characters." />
        {msg && <div className={`banner small ${msg.ok ? "" : "err"}`} role={msg.ok ? "status" : "alert"}>{msg.text}</div>}
        <button disabled={!cur || next.length < 10}>Change password</button>
      </form>
      <form className="card login acct-form danger" onSubmit={erase} aria-label="Delete account">
        <h2>Delete account</h2>
        <p className="small muted">Permanently removes your account, every saved analysis and the uploaded captures. This cannot be undone.</p>
        {!confirming ? (
          <button type="button" onClick={() => setConfirming(true)}>Delete my account…</button>
        ) : (
          <>
            <Field id="pw-del" label="Confirm with your password" type="password" autoComplete="current-password" value={del} onChange={(e) => setDel(e.target.value)} autoFocus required />
            {err && <div className="banner err small" role="alert">{err}</div>}
            <div className="row">
              <button className="danger-btn" disabled={!del}>Permanently delete</button>
              <button type="button" onClick={() => { setConfirming(false); setDel(""); setErr(""); }}>Cancel</button>
            </div>
          </>
        )}
      </form>
    </div>
  );
}

export default function Account({ account, onChange }: { account: AccountState; onChange: () => void }) {
  return account.user ? <Settings account={account} onChange={onChange} /> : (
    <AuthForm open={account.registration_open} onDone={() => { onChange(); window.location.hash = "#/history"; }} />
  );
}
