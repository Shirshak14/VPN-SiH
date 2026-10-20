// Browser smoke test for the whole UI. No dependencies: it drives a locally installed Chrome/Chromium/Edge over the DevTools protocol.
//
//   1. start the API   (cd backend && uvicorn ipsec_analyzer.api.main:app --port 8000)
//   2. start the UI    (cd frontend && npm run dev)
//   3. run             (cd frontend && npm run e2e)
//
// Needs Node >= 22 (global WebSocket). Environment: APP_URL (default http://localhost:5173), CHROME_PATH (override browser lookup),
// API_KEY (set it when the API runs with API_KEY: the test then also exercises the sign-in form, with a wrong key first).
// It uploads data/captures/synthetic/demo_gateway_audit.pcap and clicks a bundled scenario, so it creates two analyses; both are deleted at the end.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

const BASE = (process.env.APP_URL || "http://localhost:5173").replace(/\/$/, "");
const HERE = path.dirname(fileURLToPath(import.meta.url));
const KEY = process.env.API_KEY || "";
const AUTH = KEY ? { "X-API-Key": KEY } : {};  // node-side requests; the browser signs in through the UI
const PCAP = path.resolve(HERE, "../../data/captures/synthetic/demo_gateway_audit.pcap");
const LOG = path.resolve(HERE, "../../data/logs/strongswan_gateway.log");
const OVPN_PCAP = path.resolve(HERE, "../../data/captures/vpn/ovpn_tls10_legacy.pcap");
const OVPN_CONF = path.resolve(HERE, "../../data/configs/openvpn_legacy_client.ovpn");

function findBrowser() {
  const c = [process.env.CHROME_PATH,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium"];
  return c.find((p) => p && existsSync(p));
}

if (typeof WebSocket === "undefined") { console.error("Node >= 22 is required (global WebSocket)."); process.exit(2); }
if (!existsSync(PCAP) || !existsSync(LOG) || !existsSync(OVPN_PCAP) || !existsSync(OVPN_CONF)) { console.error("Missing fixture " + PCAP); process.exit(2); }
const browser = findBrowser();
if (!browser) { console.error("No Chrome/Chromium/Edge found. Set CHROME_PATH."); process.exit(2); }
try { await fetch(BASE + "/api/health"); } catch { console.error(`App not reachable at ${BASE} (start the API and the UI first).`); process.exit(2); }

const profile = mkdtempSync(path.join(tmpdir(), "ipsec-smoke-"));
const asRoot = process.getuid?.() === 0;  // Chrome refuses to start its sandbox as root (containers); a throwaway profile is fine without it
const chrome = spawn(browser, ["--headless=new", "--disable-gpu", ...(asRoot ? ["--no-sandbox"] : []), "--remote-debugging-port=0", "--user-data-dir=" + profile, "--window-size=1366,900", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
let chromeErr = "";
chrome.stderr.on("data", (d) => { chromeErr = (chromeErr + d).slice(-2000); });
const created = [];
let ws, failures = 0;
const problems = [];

async function cleanup() {
  for (const id of created) { try { await fetch(`${BASE}/api/analyses/${id}`, { method: "DELETE", headers: AUTH }); } catch { /* best effort */ } }
  try { ws?.close(); } catch { /* ignore */ }
  chrome.kill();
  await sleep(300);
  try { rmSync(profile, { recursive: true, force: true }); } catch { /* ignore */ }
}

try {
  let port;
  for (let i = 0; i < 240 && !port; i++) {  // 60 s: a cold Chrome start on a busy CI runner can take a while
    try { port = readFileSync(path.join(profile, "DevToolsActivePort"), "utf8").split("\n")[0].trim(); } catch { await sleep(250); }
  }
  if (!port) throw new Error("Chrome did not expose its DevTools port. Chrome said: " + (chromeErr || "(nothing)"));
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
  const api = async (p) => (await fetch(BASE + p, { headers: AUTH })).json();
  const pct = (v) => (v == null ? "n/a" : (v * 100).toFixed(1) + "%");
  const hash = () => run(() => location.hash);
  const clickNav = (label) => run((l) => [...document.querySelectorAll("nav a")].find((a) => a.textContent === l).click(), label);

  await send("Runtime.enable"); await send("Page.enable"); await send("Log.enable"); await send("DOM.enable");

  // ---- 0. sign-in (only when the API is started with API_KEY)
  await nav(BASE + "/");
  if (KEY) {
    check("locked server shows the sign-in form, not the app", await waitFor(() => !!document.querySelector("form.login") && !document.querySelector(".gal-grid")));
    const typeKey = async (text) => { await run(() => { const i = document.getElementById("api-key"); i.focus(); i.select(); }); await send("Input.insertText", { text }); };
    await typeKey("definitely-wrong"); await run(() => document.querySelector("form.login button.primary").click());
    check("wrong key shows an error and stays locked", await waitFor(() => !!document.querySelector("form.login [role=alert]")) && await run(() => !document.querySelector(".gal-grid")));
    await typeKey(KEY); await run(() => document.querySelector("form.login button.primary").click());
    check("correct key unlocks the app", await waitFor(() => !document.querySelector("form.login") && document.querySelectorAll(".gal-card").length > 5));
    check("signed-in session shows Sign out", await run(() => !!document.querySelector("button.linklike")));
    problems.length = 0;  // the browser logs every deliberate 401 (locked state, wrong key); only errors after sign-in count
  }

  // ---- 1. root URL and navigation
  await nav(BASE + "/");
  check("root renders the Analyze page", await waitFor(() => document.querySelector("h1")?.textContent.includes("Automate VPN security assessment")));
  check("root URL is exactly the app URL", (await run(() => location.href)) === BASE + "/", await run(() => location.href));
  await clickNav("Evaluation");
  check("Evaluation page opens", await waitFor(() => document.querySelector("h1")?.textContent === "Evaluation"));
  check("Evaluation URL is clean", (await run(() => location.href)) === BASE + "/#/eval");
  check("active nav link has aria-current=page", (await run(() => document.querySelector("nav a[aria-current=page]")?.textContent)) === "Evaluation");
  await clickNav("Analyze");
  check("Analyze page opens again", await waitFor(() => document.querySelectorAll(".gal-card").length > 5));
  check("Analyze URL is clean", (await run(() => location.href)) === BASE + "/#/");
  check("synthetic scenarios carry the SYNTHETIC (SIMULATED) label", await run(() => [...document.querySelectorAll(".gal-card")].filter((l) => l.querySelector(".prov-synthetic")).every((l) => l.querySelector(".prov-synthetic").textContent.toLowerCase().includes("synthetic (simulated)"))));

  // ---- 1b. sample gallery: cards mirror the API, filters work, phone width does not overflow
  const SAMPLES = await api("/api/samples");
  check("gallery shows one card per bundled capture, in the API's order", JSON.stringify(await run(() => [...document.querySelectorAll(".gal-card h3")].map((h) => h.textContent))) === JSON.stringify(SAMPLES.map((x) => x.title)), `${SAMPLES.length} cards`);
  check("every card shows its computed result (no card left scoring)", await waitFor(() => document.querySelectorAll(".gal-result .spinner").length === 0 && document.querySelectorAll(".gal-score").length === document.querySelectorAll(".gal-card").length));
  const fresh = await api("/api/samples");
  check("card scores and violation counts equal the API preview", JSON.stringify(await run(() => [...document.querySelectorAll(".gal-card")].map((c) => [c.querySelector(".gal-score").textContent, c.querySelector(".gal-result .small").textContent.match(/(no|\d+) violation/)[1]]))) === JSON.stringify(fresh.map((x) => [String(x.preview.top_score), x.preview.violations === 0 ? "no" : String(x.preview.violations)])));
  const weakN = SAMPLES.filter((x) => x.kind === "weak").length;
  await run(() => [...document.querySelectorAll(".gal-filter button")].find((b) => b.textContent === "Weak crypto").click());
  check("the Weak crypto filter keeps only weak-crypto cards", await run((n) => document.querySelectorAll(".gal-card").length === n && !!document.querySelector(".gal-filter button[aria-pressed=true]")?.textContent.includes("Weak"), weakN), `${weakN} cards`);
  await run(() => [...document.querySelectorAll(".gal-filter button")].find((b) => b.textContent === "All").click());
  check("All restores every card", await run((n) => document.querySelectorAll(".gal-card").length === n, SAMPLES.length));
  await send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  await sleep(300);
  check("landing page does not overflow a 390px phone", await run(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth), await run(() => `${document.documentElement.scrollWidth} > ${document.documentElement.clientWidth}`));
  check("gallery buttons are at least 44px tall on a phone", await run(() => [...document.querySelectorAll(".gal-card button")].every((b) => b.getBoundingClientRect().height >= 44)));
  await send("Emulation.clearDeviceMetricsOverride");
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
  check("table keeps all six columns", (await run(() => [...document.querySelectorAll("thead th")].map((t) => t.textContent).join("|"))) === "Risk|Peers|Mode|Negotiated suite|Findings|Anomaly");
  check("results page offers the printable report, PDF, HTML, link, JSON and syslog", JSON.stringify(await run(() => [...document.querySelectorAll(".res-actions > *")].slice(0, 6).map((e) => e.textContent.trim()))) === JSON.stringify(["Open printable report", "Download PDF", "Download HTML", "Copy report link", "JSON", "Syslog / CEF"]));
  check("printable report opens in a new tab", await run(() => { const a = document.querySelector(".res-actions a.primary"); return a.target === "_blank" && a.getAttribute("href").endsWith("/report.html"); }));
  for (const [file, type] of [["report.pdf", "pdf"], ["report.html", "html"], ["export.json", "json"], ["export.syslog", "text"]]) {
    const r = await fetch(`${BASE}/api/analyses/${aid}/${file}`, { headers: AUTH }); await r.arrayBuffer();
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
  await waitFor(() => document.querySelectorAll(".gal-card button").length > 0);
  const before = (await api("/api/analyses")).map((a) => a.id);
  const card0 = await run(() => ({ title: document.querySelector(".gal-card h3").textContent, score: document.querySelector(".gal-score").textContent, tunnels: document.querySelector(".gal-result .small").textContent.split(" ")[0] }));
  await run(() => document.querySelector(".gal-card button").click());
  check("bundled scenario opens the results page", await waitFor(() => /^#\/a\/\d+$/.test(location.hash) && !!document.querySelector(".res-summary"), [], 40000), await hash());
  for (const a of await api("/api/analyses")) if (!before.includes(a.id)) created.push(a.id);
  check("the card's preview matches the analysis it opens", await run((c) => document.querySelector(".hero-score").textContent === c.score && document.querySelector(".kpis li b").textContent === c.tunnels, card0), JSON.stringify(card0));
  check("synthetic scenario results show the compact SYNTHETIC notice with its original wording", await run(() => { const b = document.querySelector(".banner.compact"); return !!b && b.textContent.includes("Simulated capture.") && b.textContent.includes("not a captured real-world incident") && document.querySelector("h1 .badge")?.textContent.toLowerCase().includes("synthetic (simulated)"); }));

  // ---- 4b. strongSwan daemon log: upload through the UI, results come from the log, not from packets
  await nav(BASE + "/#/");
  check("Analyze page has the Live ingest section", await waitFor(() => !!document.querySelector(".az-live") && document.querySelector(".az-live h2")?.textContent === "Live ingest"));
  const docL = await send("DOM.getDocument", { depth: 1 });
  const inputL = await send("DOM.querySelector", { nodeId: docL.result.root.nodeId, selector: ".az-drop input[type=file]" });
  await send("DOM.setFileInputFiles", { nodeId: inputL.result.nodeId, files: [LOG] });
  check("a log file is accepted and the button says so", await waitFor(() => document.querySelector(".az-file")?.textContent === "strongswan_gateway.log" && document.querySelector(".az-go").textContent.startsWith("Analyze log")));
  const beforeL = (await api("/api/analyses")).map((a) => a.id);
  await run(() => document.querySelector(".az-go").click());
  check("log upload opens the results page", await waitFor(() => /^#\/a\/\d+$/.test(location.hash) && !!document.querySelector(".res-summary .hero-score"), [], 40000), await hash());
  for (const a of await api("/api/analyses")) if (!beforeL.includes(a.id)) created.push(a.id);
  const aidL = Number((await hash()).split("/")[2]);
  const TL = await api(`/api/analyses/${aidL}/tunnels`);
  check("log results say they come from a daemon log", await run(() => [...document.querySelectorAll(".banner.compact")].some((b) => b.textContent.includes("Assessed from a daemon log, not from packets"))));
  check("log results list one tunnel per IKE SA, as the API does", await run((n) => document.querySelectorAll("tbody tr.click").length === n, TL.length) && TL.length === 6, `${TL.length} tunnels`);
  check("log risk matches the API", (await run(() => document.querySelector(".hero-score").textContent)) === String(Math.max(...TL.map((t) => t.risk.score))));
  await run(() => document.querySelector("tbody tr.click").click());
  check("a log-derived tunnel opens without a timeline", await waitFor(() => [...document.querySelectorAll("h2")].some((h) => h.textContent.startsWith("Rule-engine findings"))));
  check("its coverage note explains the log source", await run(() => document.body.innerText.includes("Assessed from a daemon log, not from packets")));

  // ---- 4c. OpenVPN capture and OpenVPN config: both upload through the same form and are analysed, not just "seen"
  for (const [file, label, banner, fromConfig] of [[OVPN_PCAP, "ovpn_tls10_legacy.pcap", null, false], [OVPN_CONF, "openvpn_legacy_client.ovpn", "configuration file", true]]) {
    await nav(BASE + "/#/");
    await waitFor(() => !!document.querySelector(".az-drop input[type=file]"));
    const dV = await send("DOM.getDocument", { depth: 1 });
    const iV = await send("DOM.querySelector", { nodeId: dV.result.root.nodeId, selector: ".az-drop input[type=file]" });
    await send("DOM.setFileInputFiles", { nodeId: iV.result.nodeId, files: [file] });
    check(`${label} is accepted`, await waitFor((n) => document.querySelector(".az-file")?.textContent === n, [label]));
    const beforeV = (await api("/api/analyses")).map((a) => a.id);
    await run(() => document.querySelector(".az-go").click());
    check(`${label} opens the results page`, await waitFor(() => /^#\/a\/\d+$/.test(location.hash) && !!document.querySelector(".res-summary .hero-score"), [], 40000), await hash());
    for (const a of await api("/api/analyses")) if (!beforeV.includes(a.id)) created.push(a.id);
    const TV = await api(`/api/analyses/${Number((await hash()).split("/")[2])}/tunnels`);
    check(`${label} yields an analysed VPN tunnel with findings`, TV.length >= 1 && TV[0].protocol !== undefined && TV.some((t) => t.violations.length > 0), `${TV.length} tunnel(s), top ${Math.max(...TV.map((t) => t.risk.score))}`);
    check(`${label} hero score is the highest tunnel risk`, (await run(() => document.querySelector(".hero-score").textContent)) === String(Math.max(...TV.map((t) => t.risk.score))));
    if (banner) check("config results say they come from a file, not traffic", await run((b) => document.body.innerText.toLowerCase().includes(b), banner));
    await run(() => document.querySelector("tbody tr.click").click());
    check(`${label} tunnel opens with rule-engine findings`, await waitFor(() => [...document.querySelectorAll("h2")].some((h) => h.textContent.startsWith("Rule-engine findings"))));
    check(`${label} detail has no IPsec-only cards`, await run(() => ![...document.querySelectorAll("h2")].some((h) => /child sa|esp/i.test(h.textContent))));
    check(`${label} report renders`, (await fetch(`${BASE}/api/analyses/${Number((await hash()).split("/")[2])}/report.html`, { headers: AUTH })).status === 200);
  }

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

  // ---- 6. accounts: sign up, private saved history, persistence across sign-out/in, rename, password change, delete
  const typeInto = async (id, text) => { await run((i) => { const e = document.getElementById(i); e.focus(); e.select(); }, id); await send("Input.insertText", { text }); };
  const submitForm = (label) => run((l) => document.querySelector(`form[aria-label="${l}"] button:not([type=button])`).click(), label);
  const email = `smoke-${Date.now()}@example.com`;
  const pw = "smoke-" + Math.random().toString(36).slice(2) + "-A1";
  await nav(BASE + "/#/account");
  check("Account page offers sign in", await waitFor(() => !!document.querySelector('form[aria-label="Sign in to your account"]')));
  await run(() => [...document.querySelectorAll("form .linklike")].find((b) => b.textContent === "Create an account").click());
  await typeInto("acct-email", email); await typeInto("acct-pw", "short");
  await submitForm("Create account");
  check("a too-short password is rejected with a visible error", await waitFor(() => !!document.querySelector("form [role=alert]")) || await run(() => !document.getElementById("acct-pw").checkValidity()));
  await typeInto("acct-pw", pw); await submitForm("Create account");
  check("registering lands on the (empty) saved history", await waitFor(() => location.hash === "#/history" && document.body.innerText.includes("No saved analyses yet")), await hash());
  check("the top bar shows the signed-in account", await run((e) => document.querySelector(".acct-link")?.textContent === e, email));
  const hadBefore = (await api("/api/analyses")).length;
  await nav(BASE + "/#/");
  await waitFor(() => document.querySelectorAll(".gal-card button").length > 0);
  await run(() => document.querySelector(".gal-card button").click());
  check("analysing while signed in works", await waitFor(() => /^#\/a\/\d+$/.test(location.hash) && !!document.querySelector(".res-summary"), [], 40000), await hash());
  await nav(BASE + "/#/history");
  check("the analysis appears in saved history, marked private", await waitFor(() => document.querySelectorAll("tbody tr").length === 1));
  await run(() => document.querySelector(".name-btn").click());
  await send("Input.insertText", { text: "smoke test run" });
  await run(() => document.querySelector(".name-input").blur());
  check("renaming a saved analysis sticks", await waitFor(() => document.querySelector(".name-btn")?.textContent === "smoke test run"));
  await run(() => [...document.querySelectorAll(".topbar button")].find((b) => b.textContent === "Sign out")?.click());  // API-key mode only
  await run(() => document.querySelector(".acct-link").click());
  await run(() => [...document.querySelectorAll("button")].find((b) => b.textContent === "Sign out").click());
  check("signing out hides the private history", await waitFor(() => document.querySelector(".acct-link")?.textContent === "Sign in"));
  await nav(BASE + "/#/history");
  check("History asks anonymous visitors to sign in", await waitFor(() => document.body.innerText.includes("Sign in to keep your analyses private")));
  await nav(BASE + "/#/account");
  await waitFor(() => !!document.getElementById("acct-email"));
  await typeInto("acct-email", email); await typeInto("acct-pw", "wrong-password-1"); await submitForm("Sign in to your account");
  check("a wrong password shows an error", await waitFor(() => !!document.querySelector("form [role=alert]")));
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes("401")) problems.splice(i, 1);  // the deliberate failed sign-in
  await typeInto("acct-pw", pw); await submitForm("Sign in to your account");
  check("signing back in restores the saved analysis with its name", await waitFor(() => location.hash === "#/history" && document.querySelector(".name-btn")?.textContent === "smoke test run"), await hash());
  await nav(BASE + "/#/account");
  await waitFor(() => !!document.getElementById("pw-del") || [...document.querySelectorAll("button")].some((b) => b.textContent.startsWith("Delete my account")));
  await run(() => [...document.querySelectorAll("button")].find((b) => b.textContent.startsWith("Delete my account")).click());
  await typeInto("pw-del", pw); await submitForm("Delete account");
  check("deleting the account signs out and erases the saved analysis", await waitFor(() => document.querySelector(".acct-link")?.textContent === "Sign in") && (await api("/api/analyses")).length === hadBefore);
  // ---- 7. printable report: renders in the browser, lists every tunnel, hides its toolbar when printing
  await nav(`${BASE}/api/analyses/${aid}/report.html`);
  check("report page renders with its title and one section per tunnel", await waitFor((n) => document.querySelector("h1")?.textContent === "IPsec VPN Security Assessment" && document.querySelectorAll("section.tunnel").length === n, [T.length]));
  check("report summary and remediation match the API", await run((top, n) => Number(document.body.innerText.match(/([\d.]+)\/100/)?.[1]) === top && [...document.querySelectorAll(".fix")].length === n, top, rem.length), `top=${top} rem=${rem.length}`);
  check("report has no external resources and fits the viewport", await run(() => !document.querySelector("link,img,iframe,[src]") && document.documentElement.scrollWidth <= document.documentElement.clientWidth));
  await send("Emulation.setEmulatedMedia", { media: "print" });
  check("toolbar is hidden when printing", await run(() => getComputedStyle(document.querySelector(".toolbar")).display === "none"));
  await send("Emulation.setEmulatedMedia", { media: "" });
  const pdf = await send("Page.printToPDF", { printBackground: true });
  check("browser can print the report to PDF", (pdf.result?.data || "").length > 5000, `${((pdf.result?.data || "").length * 0.75 / 1024).toFixed(0)} KB`);

  check("no console errors or exceptions during the whole run", problems.length === 0, problems.slice(0, 3).join(" || "));
} catch (e) {
  failures++;
  console.log("FAIL test run aborted: " + (e?.stack || e));
  if (problems.length) console.log("browser problems: " + problems.slice(0, 5).join(" || "));
} finally {
  await cleanup();
}
console.log(failures ? `\n${failures} check(s) FAILED` : "\nall checks passed");
process.exit(failures ? 1 : 0);
