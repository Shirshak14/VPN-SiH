import { useEffect, useState } from "react";
import Analyze from "./pages/Analyze";
import Evaluation from "./pages/Evaluation";
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

export default function App() {
  const p = useHash();
  let page = <Analyze />;
  let active = "analyze";
  if (p[0] === "a" && p[1] && p[2] === "t" && p[3]) {
    page = <TunnelDetail key={p[1] + p[3]} aid={Number(p[1])} tid={decodeURIComponent(p[3])} />;
    active = "results";
  } else if (p[0] === "a" && p[1]) {
    page = <Tunnels key={p[1]} aid={Number(p[1])} />;
    active = "results";
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
          <a href="#/" className={active === "analyze" ? "active" : ""}>Analyze</a>
          <a href="#/eval" className={active === "eval" ? "active" : ""}>Evaluation</a>
        </nav>
        <span className="muted small">SIH26160 · prototype</span>
      </header>
      <main>{page}</main>
    </div>
  );
}
