import { useEffect, useState } from "react";
import { AccountState, api, AUTH_EVENT, AuthState } from "./api";
import Account from "./pages/Account";
import Alerts from "./pages/Alerts";
import Analyze from "./pages/Analyze";
import Compare from "./pages/Compare";
import Evaluation from "./pages/Evaluation";
import History from "./pages/History";
import Policy from "./pages/Policy";
import TunnelDetail from "./pages/TunnelDetail";
import Tunnels from "./pages/Tunnels";

function useHash(): string[] {
  const parse = () => window.location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const [parts, setParts] = useState(parse);
  useEffect(() => {
    const on = () => setParts(parse());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return parts;
}

function Login({ onDone }: { onDone: () => void }) {
  const [key, setKey] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.login(key);
      onDone();
    } catch (x) {
      setErr(x instanceof Error ? x.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card login" onSubmit={submit} aria-label="Sign in">
      <h2>Sign in</h2>
      <p className="small muted">This server requires an access key. Ask whoever deployed it (<code>API_KEY</code> or <code>READONLY_API_KEY</code>).</p>
      <label className="small" htmlFor="api-key">Access key</label>
      <input id="api-key" type="password" autoComplete="current-password" value={key} onChange={(e) => setKey(e.target.value)} autoFocus />
      {err && <div className="banner err small" role="alert">{err}</div>}
      <button className="primary" disabled={!key || busy}>Sign in</button>
    </form>
  );
}

export default function App() {
  const p = useHash();
  const [auth, setAuth] = useState<AuthState | null>(null);
  const refresh = () => api.auth().then(setAuth).catch(() => setAuth({ required: false, authenticated: true, role: "admin" }));
  useEffect(() => {
    refresh();
    refreshAccount();
    const on = () => setAuth((a) => (a ? { ...a, authenticated: false, role: null } : a));
    window.addEventListener(AUTH_EVENT, on);
    return () => window.removeEventListener(AUTH_EVENT, on);
  }, []);
  const [account, setAccount] = useState<AccountState>({ registration_open: true, user: null });
  const [acctReady, setAcctReady] = useState(false);
  const refreshAccount = () => api.account().then(setAccount).catch(() => undefined).finally(() => setAcctReady(true));
  const locked = auth !== null && auth.required && !auth.authenticated;
  useEffect(() => { if (!locked) refreshAccount(); }, [locked]);  // after the API-key sign-in the account endpoint becomes reachable
  let page = <Analyze />;
  let active = "analyze";
  if (p[0] === "a" && p[1] && p[2] === "t" && p[3]) {
    page = <TunnelDetail key={p[1] + p[3]} aid={Number(p[1])} tid={decodeURIComponent(p[3])} />;
    active = "results";
  } else if (p[0] === "a" && p[1]) {
    page = <Tunnels key={p[1]} aid={Number(p[1])} />;
    active = "results";
  } else if (p[0] === "compare") {
    page = <Compare before={Number(p[1]) || undefined} after={Number(p[2]) || undefined} />;
    active = "compare";
  } else if (p[0] === "policy") {
    page = <Policy key={p[1] ?? ""} aid={Number(p[1]) || undefined} />;
    active = "policy";
  } else if (p[0] === "history") {
    page = <History account={account} />;
    active = "history";
  } else if (p[0] === "alerts") {
    page = <Alerts account={account} />;
    active = "alerts";
  } else if (p[0] === "account") {
    page = <Account account={account} onChange={refreshAccount} />;
    active = "account";
  } else if (p[0] === "eval") {
    page = <Evaluation />;
    active = "eval";
  }
  return (
    <div className="shell">
      <header className="topbar">
        <a className="brand" href="#/">
          <svg viewBox="0 0 32 32" aria-hidden="true">
            <rect width="32" height="32" rx="7" fill="var(--brand)" />
            <path d="M16 6l8 3v7c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V9z" fill="none" stroke="var(--brand-ink)" strokeWidth="2" />
          </svg>
          IPsec VPN Analyzer
        </a>
        <nav className="nav" aria-label="Main">
          <a href="#/" className={active === "analyze" ? "active" : ""} aria-current={active === "analyze" ? "page" : undefined}>Analyze</a>
          {account.user && <a href="#/history" className={active === "history" ? "active" : ""} aria-current={active === "history" ? "page" : undefined}>History</a>}
          {account.user && <a href="#/alerts" className={active === "alerts" ? "active" : ""} aria-current={active === "alerts" ? "page" : undefined}>Alerts</a>}
          <a href="#/compare" className={active === "compare" ? "active" : ""} aria-current={active === "compare" ? "page" : undefined}>Compare</a>
          <a href="#/policy" className={active === "policy" ? "active" : ""} aria-current={active === "policy" ? "page" : undefined}>Policy</a>
          <a href="#/eval" className={active === "eval" ? "active" : ""} aria-current={active === "eval" ? "page" : undefined}>Evaluation</a>
        </nav>
        <span className="muted small">
          SIH26160 · prototype
          {acctReady && !locked && (account.user ? (
            <a href="#/account" className={`acct-link ${active === "account" ? "active" : ""}`} title="Account settings">{account.user.email}</a>
          ) : (
            <a href="#/account" className="acct-link">Sign in</a>
          ))}
          {auth?.required && auth.authenticated && (
            <>
              {auth.role === "readonly" && <span className="chip" style={{ marginLeft: "var(--sp-2)" }}>read-only</span>}
              <button className="linklike" onClick={() => api.logout().then(() => { refresh(); setAccount((a) => ({ ...a, user: null })); })}>Sign out</button>
            </>
          )}
        </span>
      </header>
      <main>{auth === null ? null : locked ? <Login onDone={refresh} /> : page}</main>
    </div>
  );
}
