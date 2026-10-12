# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

Smart India Hackathon 2026 · PS SIH26160 · working prototype.

Upload a PCAP containing IKEv1/IKEv2 negotiation and ESP/AH traffic. The tool parses the handshakes, rebuilds each tunnel's
Security Association lifecycle, checks it against a YAML policy pack (NIST SP 800-77r1 / RFC 8221 / RFC 8247), scores behavioural
anomalies with an Isolation Forest, combines both into a 0–100 risk score, explains it (SHAP + MITRE ATT&CK), and produces remediation
guidance, an audit PDF, and JSON/syslog(CEF) exports.

```
PCAP → IKE & ESP parsing → SA reconstruction → Rules + AI detection → Risk score & MITRE mapping → Remediation report
```

## Read this first: what is real and what is simulated

| Data | Provenance | Used for |
|---|---|---|
| 12 captures from the **Wireshark test suite** (`data/public/`) — 8 IKEv2 (3DES, AES-CBC/CTR/CCM/GCM), 3 IKEv1 (incl. real XAUTH-PSK aggressive mode), 1 ESP | **real, third-party** | Validating the parser against independent oracles; demo of real findings |
| 309 captures from `backend/synth` (`data/captures/`) | **synthetic** — produced by this project's own byte-level IKE/ESP simulator, with genuine AES/3DES/DES encryption of the encrypted payloads | Training the anomaly baseline, detection metrics, demo capture |
| 23 captures from the **strongSwan Docker lab** (`lab/`, `data/captures/lab/`) | **real traffic** between two strongSwan 5.9.8 daemons (real IKE, real ESP through the kernel). The *weak/downgrade configurations* are deliberate lab scenarios | Real-traffic rule validation, demo |

**Lab notes.** Run with `python lab/generate.py` (needs Docker with virtualization). Findings worth knowing: strongSwan 5.9.8 has no `save-keys`
plugin, so IKEv2 keys are parsed from charon's verbose log (`ike = 4`) into Wireshark-format key files; IKE-SA rekeys are excluded from the scenarios
(they change SPIs/keys mid-capture); strongSwan refuses Aggressive Mode + PSK unless `i_dont_care_about_security_and_use_aggressive_mode_psk = yes`
is set, which the lab does only for that one scenario. Captures are ~20–40 s each with tcpdump on the initiator.

**Behavioural lab scenarios (written, not yet captured).** `behav_slow_relay_450ms`, `behav_slow_relay_700ms`, `behav_lossy_path` (all `tc netem` on the responder's egress) and `behav_half_open_scan` (12 IKE_SA_INIT probes from `lab/scan_probe.py` at a responder with no daemon) are defined in `lab/scenarios.py` and wired into `lab/generate.py`, but no real captures exist yet: they were authored where Docker could not run. Run `python lab/generate.py behav_slow_relay_450ms behav_slow_relay_700ms behav_lossy_path behav_half_open_scan`, then `python -m ipsec_analyzer.evaluation`; the lab section of `docs/EVAL.json` will then say whether the AI layer's behavioural detection holds on real traffic. The scan-probe packet builder is covered by a test (it parses and trips `IKE-HALF-OPEN-FLOOD`); the netem and retransmit-timer settings are untested guesses and may need tuning.

Consequences you should state if asked:
* Every "weak configuration" and "downgrade" tunnel is a **lab or simulated scenario** (labelled *synthetic* or *real · strongSwan lab* in the UI, PDF and exports). None is a real incident.
* Detection metrics below are on simulated data whose labels come from the generator's own configuration, written by the same team as the parser. They show the pipeline is internally consistent and the AI layer behaves sensibly; they are **not field detection rates**.
* The behavioural-anomaly families (slow relay, rekey storm, oversize handshake, scan probes…) were designed by us, so the AI numbers are optimistic.

## Quick start (local, no Docker)

Prerequisites: **Python 3.11** (its `venv` must include pip: if `python -m venv` fails at `ensurepip`, as with some uv-managed builds, use
`uv venv --python 3.11 --seed .venv` instead) and **Node 20+**. Ports **8000** (API) and **5173** (UI) must be free: the Vite dev server proxies `/api` to `localhost:8000`.

```bash
python -m venv .venv            # Python 3.11 recommended (3.14 lacks wheels for some deps)
# constraints.txt pins every package to the exact versions this project was tested with
.venv/Scripts/pip install -r backend/requirements.txt -c backend/constraints.txt   # Linux/macOS: .venv/bin/pip
cd backend
python -m synth.generate --out ../data/captures --benign-per-family 40   # ~1 min, deterministic (seed 2026)
python -m ipsec_analyzer.ml.train                                        # retrain anomaly model (benign train split only)
python -m ipsec_analyzer.evaluation                                      # regenerate docs/EVAL.json
python -m pytest tests -q
uvicorn ipsec_analyzer.api.main:app --port 8000                          # SQLite by default
# second terminal
cd frontend && npm ci && npm run dev                                     # http://localhost:5173
```

`npm ci` may print a harmless warning that esbuild's postinstall script is not pre-approved; the build works regardless.

**UI smoke test.** With the API and the UI running, `cd frontend && npm run e2e` drives a real browser through upload, a bundled scenario, the results page, a tunnel, and the Evaluation page,
checking every figure against the API (needs Node 22+ and Chrome, Chromium or Edge; it deletes the analyses it creates). CI runs it on every push and pull request (`e2e` job); it passes `--no-sandbox` automatically when run as root, e.g. in a container.

**About `docs/EVAL.json`.** Regenerating it rewrites two run-dependent fields, `generated_at` and `throughput` (packets/s varies from run to run), so the file shows as modified even when nothing changed.
The Evaluation page displays both, so they stay in the file. To check that the *metrics* reproduce, compare everything else:

```bash
python - <<'EOF'
import json, subprocess
strip = lambda d: {k: v for k, v in d.items() if k not in ("generated_at", "throughput")}
old = json.loads(subprocess.check_output(["git", "show", "HEAD:docs/EVAL.json"]))
print("metrics identical:", strip(json.load(open("../docs/EVAL.json"))) == strip(old))
EOF
```

Full stack (PostgreSQL + API + nginx UI): `docker compose up --build` → http://localhost:8080. Verified: stack builds, an analysis of a real-lab capture ran through nginx into PostgreSQL, and the PDF/syslog exports download.
The UI container starts only once the API's healthcheck passes, so the page never shows a gateway error while the API boots (first start takes a minute or so). Database credentials default to the demo values and can be overridden with `POSTGRES_USER`, `POSTGRES_PASSWORD` and `POSTGRES_DB` (set them before the first `up`, since an existing `pgdata` volume keeps its original credentials).

Optional: `DATABASE_URL=postgresql+psycopg2://…` to use PostgreSQL, `POLICY_PATH=/path/to/custom.yaml` for a different policy pack.

## How it works

* **Parser** (`backend/ipsec_analyzer/parser/`): Scapy only reads PCAP/PCAPNG frames; link/IP/UDP/ESP/AH decoding (with IPv4 reassembly and NAT-T
  marker handling) and the IKEv1/IKEv2 payload decoders are hand-written from RFC 7296 / RFC 2409. PyShark/TShark are **not** used (TShark
  is not installed here); Scapy's independent ISAKMP dissector is used as a cross-check instead.
* **Decryption (optional)**: IKEv2 encrypts authentication and child SAs. Given a Wireshark-format `ikev2_decryption_table` (keys) the parser opens
  SK/SKF payloads (AES-CBC/CTR/GCM/CCM, 3DES/DES) and reassembles RFC 7383 fragments. **Without keys those facts are reported as "not assessable", never guessed.**
  IKEv1 Quick Mode (ESP transforms, PFS) is likewise encrypted. Given Wireshark's two-column `ikev1_decryption_table` (initiator cookie, expanded phase-1 encryption key) the parser derives the CBC IVs per RFC 2409 Appendix B (DES, 3DES, AES-CBC; MD5/SHA-1/SHA-2 for the IV hash), opens phase-1 and Quick Mode messages, and the child ESP suite and PFS (a KE payload in Quick Mode) become assessable. One key file may hold IKEv1 and IKEv2 rows. A wrong key is reported as a decryption failure, never guessed. Not covered: the analyzer does not derive keys from a PSK itself (you must supply the key), and a key table exported from a real strongSwan/Libreswan lab is untested.
* **SA reconstruction**: one tunnel per initiator SPI; offered vs negotiated suites, auth method, retransmits, cookies, fragments, DPD, rekeys, ESP
  flows (sequence gaps/replays), and earlier failed attempts between the same endpoints (for downgrade detection).
* **Rule engine** (`backend/policy/nist_rfc8221.yaml`): algorithm tiers, thresholds, severities, references, MITRE mapping and remediation are data.
  Edit the YAML — no code change — to change what is flagged. The tiering is this project's reading of the cited documents (document-level
  references only); thresholds marked "site policy" (IKE lifetime, retransmit count, ESP ratios) are not NIST/RFC numbers.
* **Anomaly layer**: six small Isolation Forests (first-message size, message size, handshake timing, reliability, proposal pattern, rekey rate), fitted on
  benign tunnels only, calibrated on **out-of-fold** benign scores; tunnel score = max group score, flagged when above the benign 99th percentile. A single
  forest over all features was tried first and missed single-signal anomalies. Three further **benign-envelope** groups (response time, retransmissions, half-open handshakes) are plain calibrated statistics rather than forests, because a forest cannot rank "far outside the training range" above "just outside it". The PyTorch autoencoder from the brief was **not built**.
* **Explainability**: `shap.TreeExplainer` on the dominant group's fitted forest, computed per request. When a group's benign training data is
  constant (ESP sequencing) the forest has no splits and SHAP is undefined; the UI then says so instead of inventing values. For an envelope group the "why" panel shows each feature's deviation from the benign median in units of the benign median-to-p99 span, and says it is not SHAP.
* **Risk score**: `risk = 100·(1−(1−R)(1−A))`, `R = 1−∏(1−w_severity)`, `A = 0.30 × anomaly score`. Weights live in the policy YAML; the formula is shown on every tunnel.
* **MITRE ATT&CK**: curated in the YAML (T1040, T1557, T1110.002, T1600). T1600 "Weaken Encryption" is the closest analogue for protocol downgrade, not an exact fit.

## Access control and limits

The demo is open by default. For a shared deployment set an access key (no code change):

| Variable | Effect |
|---|---|
| `API_KEY` | Every `/api/*` route except `/api/health` and the login endpoints requires this key. The UI shows a sign-in form; scripts send `X-API-Key: <key>` or `Authorization: Bearer <key>`. |
| `READONLY_API_KEY` | Optional second key that can read results and download reports but cannot upload, analyse samples or delete (HTTP 403). |
| `MAX_UPLOAD_MB` | Capture size cap (default 256). With Docker, nginx allows 270 MB; raise `client_max_body_size` in `frontend/nginx.conf` together with it. |
| `MAX_CONCURRENT_ANALYSES` | Analyses running at once (default 2); the rest stay `queued`. |

Browser sign-in sets an HttpOnly, SameSite=Strict cookie (8 h) holding a digest of role and key, so rotating a key signs everyone out; failed logins are limited to 5 per minute per client. Docker: `API_KEY=… docker compose up --build`. **This is a shared-secret gate, not user accounts or RBAC**: there is no per-user identity or audit trail, keys sit in the environment, and the login throttle is in memory (one process). Serve it over TLS, because the key travels in a header or the login body.

Ingest is bounded by disk and time, not memory: uploads stream to disk in 1 MiB chunks (rejected early on `Content-Length`, key files capped at 1 MB), and the parser keeps running per-flow ESP counters instead of every packet. Measured on this machine: a 244 MB / 2 M-packet ESP capture used a **902 MB → 51 MB** peak RSS and ran in **29.7 s → 11.8 s**, with byte-identical analysis output on 95 test captures. IKE messages are still held in memory, so an IKE-heavy capture costs more per MB than an ESP-heavy one; no capture larger than the 244 MB test file has been tried.

## Current evaluation (`docs/EVAL.json`, regenerated by one command)

**Simulated corpus** — held-out tunnels: 168 (60 benign + 108 weak/downgrade/behavioural). Alert = rules risk in the *medium* band or above, or anomaly score > 0.5.

| Detector | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Rules + AI | 97.3 % | 99.1 % | 0.982 | 5.0 % |
| Rule engine only | 100 % | 77.8 % | 0.875 | 0 % |
| Anomaly model only | 91.9 % | 31.5 % | 0.469 | 5.0 % |
| Rules + AI, **no decryption keys** | 97.0 % | 88.9 % | 0.928 | 5.0 % |

* Rule-level (assessable rules, keys supplied): 288 TP / 0 FP / 0 FN. Near-perfect because it checks deterministic policy against known configurations.
* **Real strongSwan lab traffic (23 tunnels, keys from charon log):** rule-level **41 TP / 0 FP / 0 FN** vs the configs we wrote; detection 10/10 weak/downgrade tunnels found, 0/13 false alarms on benign (precision/recall 1.0). The anomaly model alone flagged 0 of 13 real benign tunnels (no false alarms despite being trained only on simulated traffic) and 0 of 10 weak ones — expected, since they are crypto-weak, not behaviourally odd; the lab has no behavioural-anomaly scenarios, so the AI layer's recall is **untested on real traffic**. 23 tunnels from one lab setup on one host is small.
* Parse accuracy on simulated captures: 100 % for IKE datagram count, ESP packet count, tunnel reconstruction, IKE version, negotiated IKE suite, auth method and child-SA suite (consistency check — same authors wrote encoder and decoder).
* **Parser vs independent oracles on real public captures: 33/33** — decrypted AUTH payload bytes equal Wireshark's expected values for all 8 IKEv2 captures; message/packet counts and IKEv1 transform attributes agree with Scapy's separate ISAKMP dissector. For IKEv1 key-assisted decryption there is no plaintext oracle, so the checks are structural: all 25 encrypted messages in the 3 captures open into valid payload chains, and every decrypted HASH payload is exactly the negotiated hash's digest length (16 B MD5, 32 B SHA-256), which a wrong key or IV would not produce. These are small captures (4–16 packets).
* Real lab traffic also found two of *our* mistakes: strongSwan omits the DH transform in the initial child SA even with PFS configured, so `ESP-NO-PFS` now judges PFS only from observed rekeys (otherwise "PFS not assessable"), and the simulator's model of this was corrected.
* Throughput (single thread, laptop): parse ≈ 23k–110k packets/s (13–60 MB/s) and end-to-end incl. rules, model and SHAP ≈ 18k–80k packets/s across runs — this machine's timings were noisy; re-run before quoting (309 captures, 88k packets, 48 MB).

Behavioural families (all simulator-only, designed by us): oversize handshakes 6/6, slow relay 6/6, retransmit burst 6/6, half-open scan 6/6, rekey storm 5/6, ESP replay 6/6 (rules). Slow relay, retransmit burst and half-open scan were 0/6, 1/6 and 1/6 before the "benign envelope" groups and the `IKE-HALF-OPEN-FLOOD` rule were added. Two things were wrong: an Isolation Forest scores any value beyond the training range the same, so a 600 ms relay looked no worse than a benign 99th-percentile sample; and a scan is many separate half-open handshakes, invisible to per-tunnel features. The fix is deliberately modest and is **not machine learning**: a calibrated benign-baseline envelope (median / 99th percentile in log space, flagged at p99 + 0.5 span) for response time, retransmissions and unanswered handshakes, plus a count of unanswered handshakes per source/target. Response time is now measured from the *last* transmission, so a lost packet and its retransmit timer is not mistaken for a slow peer. The false-positive rate rose from 2 to 3 of 60 benign tunnels (all three are forest groups, after retraining). Treat these numbers as consistency checks on simulated data; the thresholds were chosen on the same simulator, and the strongSwan lab has no behavioural scenarios yet, so none of this is validated on real traffic.

## API

`POST /api/analyses` (multipart `pcap`, optional `keys`) · `POST /api/samples/{name}/analyze` · `GET /api/analyses/{id}` (status + stage) ·
`…/tunnels` · `…/tunnels/{tid}` (SA detail, findings, risk, SHAP) · `…/remediation` · `…/report.pdf` · `…/export.json` · `…/export.syslog` ·
`GET /api/metrics` · `GET /api/policy` · `GET /api/health`. Interactive docs at `/docs`.

## Honest list of corners cut

* Lab traffic is strongSwan-only (no Libreswan), one host, LAN-like latency; no CIC-IDS2018 (not IPsec-labelled, not used); no live NIC capture — the UI's "Replay capture" animates a stored handshake timeline.
* PyShark/TShark not used; autoencoder not built; IKEv1 phase-2 and keyless IKEv2 child SAs not observable without keys (IKEv1 Quick Mode needs a supplied key table; none was produced from the lab yet).
* IKEv2 NAT-T is handled (marker, UDP-encapsulated ESP) but only exercised lightly; IPv6 decoding is minimal; AH is counted, not analysed in depth.
* One capture per analysis, 256 MB default cap (configurable). Optional shared-key auth with a read-only role, but no per-user accounts, audit log or RBAC.
* WireGuard/OpenVPN: roadmap only.
* Risk weights and bands are judgment calls, not calibrated against incident data.
* The UI was exercised in headless Edge against the real API (upload → results → detail → evaluation) with no failed requests; its only automated frontend test is the browser smoke test above (no component or unit tests).
