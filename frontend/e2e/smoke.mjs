// Browser smoke test for the whole UI. No dependencies: it drives a locally installed Chrome/Chromium/Edge over the DevTools protocol.
//
//   1. start the API   (cd backend && uvicorn ipsec_analyzer.api.main:app --port 8000)
//   2. start the UI    (cd frontend && npm run dev)
//   3. run             (cd frontend && npm run e2e)
//
// Needs Node >= 22 (global WebSocket). Environment: APP_URL (default http://localhost:5173), CHROME_PATH (override browser lookup).
// It uploads data/captures/synthetic/demo_gateway_audit.pcap and clicks a bundled scenario, so it creates two analyses; both are deleted at the end.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

const BASE = (process.env.APP_URL || "http://localhost:5173").replace(/\/$/, "");
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PCAP = path.resolve(HERE, "../../data/captures/synthetic/demo_gateway_audit.pcap");

function findBrowser() {
  const c = [process.env.CHROME_PATH,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"];
  return c.find((p) => p && existsSync(p));
}

if (typeof WebSocket === "undefined") { console.error("Node >= 22 is required (global WebSocket)."); process.exit(2); }
if (!existsSync(PCAP)) { console.error("Missing fixture " + PCAP); process.exit(2); }
const browser = findBrowser();
if (!browser) { console.error("No Chrome/Chromium/Edge found. Set CHROME_PATH."); process.exit(2); }
try { await fetch(BASE + "/api/health"); } catch { console.error(`App not reachable at ${BASE} (start the API and the UI first).`); process.exit(2); }

const profile = mkdtempSync(path.join(tmpdir(), "ipsec-smoke-"));
const chrome = spawn(browser, ["--headless=new", "--disable-gpu", "--remote-debugging-port=0", "--user-data-dir=" + profile, "--window-size=1366,900", "about:blank"], { stdio: "ignore" });
const created = [];
let ws, failures = 0;
const problems = [];

async function cleanup() {
  for (const id of created) { try { await fetch(`${BASE}/api/analyses/${id}`, { method: "DELETE" }); } catch { /* best effort */ } }
  try { ws?.close(); } catch { /* ignore */ }
  chrome.kill();
  await sleep(300);
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* ignore */ }
}

try {
  let port;
  for (let i = 0; i < 80 && !port; i++) {
    try { port = readFileSync(path.join(profile, "DevToolsActivePort"), "utf8").split("\n")[0].trim(); } catch { await sleep(250); }
  }
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  ws = new WebSocket(targets.find((t) => t.type === "page").webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let id = 0;
  const pending = new Map();
  ws.onmessage = (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
    if (d.method === "Runtime.exceptionThrown") problems.push("exception: " + d.params.exceptionDetails.exception?.description?.slice(0, 200));
    if (d.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(d.params.type)) problems.push("console." + d.params.type + ": " + d.params.args.map((a) => a.value ?? a.description).join(" ").slice(0, 200));
    if (d.method === "Log.entryAdded" && d.params.entry.level === "error") problems.push("log: " + d.params.entry.text);
  };
  const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
  // Run a real function in the page (no string escaping). Arguments must be JSON-serialisable.
  const run = async (fn, ...args) => {
    const r = await send("Runtime.evaluate", { expression: `(${fn.toString()})(...${JSON.stringify(args)})`, awaitPromise: true, returnByValue: true });
    if (r.result.exceptionDetails) throw new Error(r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text);
    return r.result.result.value;
  };
  const waitFor = async (fn, args = [], ms = 20000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { try { if (await run(fn, ...args)) return true; } catch { /* page not ready */ } await sleep(200); } return false; };
  const check = (name, ok, extra = "") => { if (!ok) failures++; console.log((ok ? "PASS " : "FAIL ") + name + (extra ? "  " + extra : "")); };
  const nav = async (url) => { await send("Page.navigate", { url }); await sleep(300); };
  const api = async (p) => (await fetch(BASE + p)).json();
  const pct = (v) => (v == null ? "n/a" : (v * 100).toFixed(1) + "%");
  const hash = () => run(() => location.hash);
  const clickNav = (label) => run((l) => [...document.querySelectorAll("nav a")].find((a) => a.textContent === l).click(), label);

  await send("Runtime.enable"); await send("Page.enable"); await send("Log.enable"); await send("DOM.enable");

  // ---- 1. root URL and navigation
  await nav(BASE + "/");
  check("root renders the Analyze page", await waitFor(() => document.querySelector("h1")?.textContent.includes("Automate IPsec/IKE")));
  check("root URL is exactly the app URL", (await run(() => location.href)) === BASE + "/", await run(() => location.href));
  await clickNav("Evaluation");
  check("Evaluation page opens", await waitFor(() => document.querySelector("h1")?.textContent === "Evaluation"));
  check("Evaluation URL is clean", (await run(() => location.href)) === BASE + "/#/eval");
  check("active nav link has aria-current=page", (await run(() => document.querySelector("nav a[aria-current=page]")?.textContent)) === "Evaluation");
  await clickNav("Analyze");
  check("Analyze page opens again", await waitFor(() => document.querySelectorAll(".az-samples li").length > 5));
  check("Analyze URL is clean", (await run(() => location.href)) === BASE + "/#/");
  check("synthetic scenarios carry the SYNTHETIC (SIMULATED) label", await run(() => [...document.querySelectorAll(".az-samples li")].filter((l) => l.querySelector(".prov-synthetic")).every((l) => l.querySelector(".prov-synthetic").textContent.toLowerCase().includes("synthetic (simulated)"))));
  check("Analyze capture is disabled until a file is chosen", await run(() => document.querySelector(".az-go").disabled));

  // ---- 2. real file upload -> results
  const doc = await send("DOM.getDocument", { depth: 1 });
  const input = await send("DOM.querySelector", { nodeId: doc.result.root.nodeId, selector: ".az-drop input[type=file]" });
  await send("DOM.setFileInputFiles", { nodeId: input.result.nodeId, files: [PCAP] });
  check("chosen file name is shown", await waitFor(() => document.querySelector(".az-file")?.textContent === "demo_gateway_audit.pcap"));
  await run(() => document.querySelector(".az-go").click());
  check("upload opens the results page", await waitFor(() => /^#\/a\/\d+$/.test(location.hash) && !!document.querySelector(".res-summary .hero-score"), [], 40000), await hash());
  const aid = Number((await hash()).split("/")[2]);
  created.push(aid);

  const A = await api(`/api/analyses/${aid}`);
  const T = await api(`/api/analyses/${aid}/tunnels`);
  const top = Math.max(...T.map((t) => t.risk.score));
  const withViol = T.filter((t) => t.violations.length).length;
  const anomalous = T.filter((t) => t.anomaly_score != null && t.anomaly_score > 0.5).length;
  check("hero score is the highest tunnel risk", (await run(() => document.querySelector(".hero-score").textContent)) === String(top), `api=${top}`);
  const kpis = await run(() => [...document.querySelectorAll(".kpis li")].map((l) => l.textContent.trim()));
  check("stats row matches the API", JSON.stringify(kpis) === JSON.stringify([`${T.length} tunnels`, `${withViol} with violations`, `${T.length - withViol} without violations`, `${anomalous} anomalous`]), kpis.join(" | "));
  const bandsApi = Object.entries(A.summary.bands).filter(([, n]) => n).map(([b, n]) => `${n} ${b}`);
  check("risk distribution matches the API and sits below the table", JSON.stringify(await run(() => [...document.querySelectorAll(".dist .badge")].map((b) => b.textContent.trim().toLowerCase()))) === JSON.stringify(bandsApi)
    && await run(() => !!(document.querySelector("table").compareDocumentPosition(document.querySelector(".dist")) & Node.DOCUMENT_POSITION_FOLLOWING)));
  check("an uploaded capture is labelled user upload, not synthetic", await run(() => document.querySelector("h1 .badge")?.textContent.toLowerCase() === "user upload" && !document.querySelector(".banner.compact")));
  check("table keeps all six columns", (await run(() => [...document.querySelectorAll("thead th")].map((t) => t.textContent).join("|"))) === "Risk|Peers|Mode|Negotiated IKE suite|Findings|Anomaly");
  for (const [file, type] of [["report.pdf", "pdf"], ["export.json", "json"], ["export.syslog", "text"]]) {
    const r = await fetch(`${BASE}/api/analyses/${aid}/${file}`); await r.arrayBuffer();
    check(`download ${file} works`, r.status === 200 && (r.headers.get("content-type") || "").includes(type), r.headers.get("content-type"));
  }

  // findings column: collapsed by default, every finding reachable, toggle does not navigate
  const distinct = [...new Set(T[0].violations.map((v) => v.rule_id))];
  check("worst tunnel shows 2 chips plus a '+N more' toggle", await run((n) => { const r = document.querySelector("tbody tr.click"); return r.querySelectorAll(".chip").length === 2 && r.querySelector(".linkbtn")?.textContent === `+${n} more`; }, distinct.length - 2));
  await run(() => document.querySelector("tbody tr.click .linkbtn").click());
  const shown = await run(() => [...document.querySelectorAll("tbody tr.click")[0].querySelectorAll(".chip")].map((c) => c.textContent.replace(/ ×\d+$/, "").trim()));
  check("expanding reveals every distinct finding", JSON.stringify([...shown].sort()) === JSON.stringify([...distinct].sort()), `${shown.length} chips`);
  await run(() => document.querySelector("tbody tr.click .linkbtn").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })));
  check("expand toggle and Enter on it do not open the tunnel", (await hash()) === `#/a/${aid}`);
  const rem = await api(`/api/analyses/${aid}/remediation`);
  check("remediation plan lists every API item, collapsed", await run((n) => document.querySelectorAll(".rem details").length === n && ![...document.querySelectorAll(".rem details")].some((d) => d.open), rem.length), `${rem.length} items`);

  // ---- 3. tunnel detail
  await run(() => document.querySelector("tbody tr.click").click());
  check("row click opens the tunnel detail", await waitFor(() => location.hash.startsWith("#/a/") && [...document.querySelectorAll("h2")].some((h) => h.textContent.startsWith("Rule-engine findings"))));
  const D = await api(`/api/analyses/${aid}/tunnels/${encodeURIComponent(T[0].id)}`);
  const viol = D.findings.filter((f) => f.category === "violation").length;
  check("findings heading count matches the API", await run((n) => document.body.innerText.includes(`Rule-engine findings (${n})`), viol), `api=${viol}`);
  check("raw evidence blocks are still available", await run(() => document.querySelectorAll(".finding pre").length > 0));

  // ---- 4. bundled scenario button
  await nav(BASE + "/#/");
  await waitFor(() => document.querySelectorAll(".az-samples li button").length > 0);
  const before = (await api("/api/analyses")).map((a) => a.id);
  await run(() => document.querySelector(".az-samples li button").click());
  check("bundled scenario opens the results page", await waitFor(() => /^#\/a\/\d+$/.test(location.hash) && !!document.querySelector(".res-summary"), [], 40000), await hash());
  for (const a of await api("/api/analyses")) if (!before.includes(a.id)) created.push(a.id);
  check("synthetic scenario results show the compact SYNTHETIC notice with its original wording", await run(() => { const b = document.querySelector(".banner.compact"); return !!b && b.textContent.includes("Simulated capture.") && b.textContent.includes("not a captured real-world incident") && document.querySelector("h1 .badge")?.textContent.toLowerCase().includes("synthetic (simulated)"); }));

  // ---- 5. Evaluation page: every number comes from /api/metrics
  const M = await api("/api/metrics");
  const c = M.synthetic.detection.combined;
  await nav(BASE + "/#/eval");
  check("Evaluation page renders", await waitFor(() => document.querySelector("h1")?.textContent === "Evaluation" && document.querySelectorAll(".metric").length === 5));
  check("methodology notice keeps its honest wording", await run(() => { const t = document.querySelector(".banner.method")?.textContent || ""; return t.includes("held-out split of simulated captures") && t.includes("None of these figures are field detection rates"); }));
  const cards = await run(() => [...document.querySelectorAll(".metric")].map((m) => m.querySelector(".v").textContent));
  check("summary cards match the API", JSON.stringify(cards) === JSON.stringify([String(M.synthetic.tunnels_evaluated), pct(c.precision), pct(c.recall), c.f1.toFixed(3), pct(c.false_positive_rate)]), cards.join(" | "));
  const D3 = M.synthetic.detection;
  const wantRows = [["Rules + AI (combined)", D3.combined], ["Rule engine only", D3.rules], ["Anomaly model only", D3.ml]].map(([n, d]) => [n, pct(d.precision), pct(d.recall), d.f1.toFixed(3), pct(d.false_positive_rate), `${d.tp} / ${d.fp} / ${d.fn} / ${d.tn}`]);
  const gotRows = await run(() => [...document.querySelectorAll('section[aria-label="Detector comparison"] tbody tr')].map((r) => [...r.children].map((td) => td.textContent.replace(/ +/g, " ").trim())));
  check("detector rows: exact values, original order", JSON.stringify(gotRows) === JSON.stringify(wantRows));
  const wantFam = Object.entries(M.synthetic.per_family).map(([k, v]) => [k + (k.startsWith("b_") ? " (benign)" : ""), String(v.n), String(v.combined), String(v.rules), String(v.ml)]);
  const gotFam = await run(() => [...document.querySelectorAll('section[aria-label="Per scenario family"] tbody tr')].map((r) => [...r.children].map((td) => td.textContent.replace(/ +/g, " ").trim())));
  check("scenario family table is complete and in order", JSON.stringify(gotFam) === JSON.stringify(wantFam), `${gotFam.length}/${wantFam.length} rows`);
  check("Evaluation page does not overflow the viewport", await run(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth));

  check("no console errors or exceptions during the whole run", problems.length === 0, problems.slice(0, 3).join(" || "));
} catch (e) {
  failures++;
  console.log("FAIL test run aborted: " + (e?.stack || e));
} finally {
  await cleanup();
}
console.log(failures ? `\n${failures} check(s) FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
