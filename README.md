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

Consequences you should state if asked:
* Every "weak configuration" and "downgrade" tunnel is a **lab or simulated scenario** (labelled *synthetic* or *real · strongSwan lab* in the UI, PDF and exports). None is a real incident.
* Detection metrics below are on simulated data whose labels come from the generator's own configuration, written by the same team as the parser. They show the pipeline is internally consistent and the AI layer behaves sensibly; they are **not field detection rates**.
* The behavioural-anomaly families (slow relay, rekey storm, oversize handshake, scan probes…) were designed by us, so the AI numbers are optimistic.

## Quick start (local, no Docker)

```bash
python -m venv .venv            # Python 3.11 recommended (3.14 lacks wheels for some deps)
.venv/Scripts/pip install -r backend/requirements.txt      # Linux/macOS: .venv/bin/pip
cd backend
python -m synth.generate --out ../data/captures --benign-per-family 40   # ~1 min, deterministic (seed 2026)
python -m ipsec_analyzer.ml.train                                        # retrain anomaly model (benign train split only)
python -m ipsec_analyzer.evaluation                                      # regenerate docs/EVAL.json
python -m pytest tests -q
uvicorn ipsec_analyzer.api.main:app --port 8000                          # SQLite by default
# second terminal
cd frontend && npm install && npm run dev                                # http://localhost:5173
```

Full stack (PostgreSQL + API + nginx UI): `docker compose up --build` → http://localhost:8080. Verified: stack builds, an analysis of a real-lab capture ran through nginx into PostgreSQL, and the PDF/syslog exports download.

Optional: `DATABASE_URL=postgresql+psycopg2://…` to use PostgreSQL, `POLICY_PATH=/path/to/custom.yaml` for a different policy pack.

## How it works

* **Parser** (`backend/ipsec_analyzer/parser/`): Scapy only reads PCAP/PCAPNG frames; link/IP/UDP/ESP/AH decoding (with IPv4 reassembly and NAT-T
  marker handling) and the IKEv1/IKEv2 payload decoders are hand-written from RFC 7296 / RFC 2409. PyShark/TShark are **not** used (TShark
  is not installed here); Scapy's independent ISAKMP dissector is used as a cross-check instead.
* **Decryption (optional)**: IKEv2 encrypts authentication and child SAs. Given a Wireshark-format `ikev2_decryption_table` (keys) the parser opens
  SK/SKF payloads (AES-CBC/CTR/GCM/CCM, 3DES/DES) and reassembles RFC 7383 fragments. **Without keys those facts are reported as "not assessable", never guessed.**
  IKEv1 Quick Mode (ESP transforms, PFS) is likewise unobservable; IKEv1 key-assisted decryption is not implemented.
* **SA reconstruction**: one tunnel per initiator SPI; offered vs negotiated suites, auth method, retransmits, cookies, fragments, DPD, rekeys, ESP
  flows (sequence gaps/replays), and earlier failed attempts between the same endpoints (for downgrade detection).
* **Rule engine** (`backend/policy/nist_rfc8221.yaml`): algorithm tiers, thresholds, severities, references, MITRE mapping and remediation are data.
  Edit the YAML — no code change — to change what is flagged. The tiering is this project's reading of the cited documents (document-level
  references only); thresholds marked "site policy" (IKE lifetime, retransmit count, ESP ratios) are not NIST/RFC numbers.
* **Anomaly layer**: seven small Isolation Forests (handshake size, timing, reliability, proposal pattern, rekey rate, ESP sequencing), fitted on
  benign tunnels only, calibrated on **out-of-fold** benign scores; tunnel score = max group score, flagged when above the benign 99th percentile. A single
  forest over all features was tried first and missed single-signal anomalies. The PyTorch autoencoder from the brief was **not built**.
* **Explainability**: `shap.TreeExplainer` on the dominant group's fitted forest, computed per request. When a group's benign training data is
  constant (ESP sequencing) the forest has no splits and SHAP is undefined; the UI then says so instead of inventing values.
* **Risk score**: `risk = 100·(1−(1−R)(1−A))`, `R = 1−∏(1−w_severity)`, `A = 0.30 × anomaly score`. Weights live in the policy YAML; the formula is shown on every tunnel.
* **MITRE ATT&CK**: curated in the YAML (T1040, T1557, T1110.002, T1600). T1600 "Weaken Encryption" is the closest analogue for protocol downgrade, not an exact fit.

## Current evaluation (`docs/EVAL.json`, regenerated by one command)

**Simulated corpus** — held-out tunnels: 168 (60 benign + 108 weak/downgrade/behavioural). Alert = rules risk in the *medium* band or above, or anomaly score > 0.5.

| Detector | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|
| Rules + AI | 97.8 % | 84.3 % | 0.905 | 3.3 % |
| Rule engine only | 100 % | 72.2 % | 0.839 | 0 % |
| Anomaly model only | 90.0 % | 16.7 % | 0.281 | 3.3 % |
| Rules + AI, **no decryption keys** | 97.6 % | 74.1 % | 0.842 | 3.3 % |

* Rule-level (assessable rules, keys supplied): 282 TP / 0 FP / 0 FN. Near-perfect because it checks deterministic policy against known configurations.
* **Real strongSwan lab traffic (23 tunnels, keys from charon log):** rule-level **41 TP / 0 FP / 0 FN** vs the configs we wrote; detection 10/10 weak/downgrade tunnels found, 0/13 false alarms on benign (precision/recall 1.0). The anomaly model alone flagged 0 of 13 real benign tunnels (no false alarms despite being trained only on simulated traffic) and 0 of 10 weak ones — expected, since they are crypto-weak, not behaviourally odd; the lab has no behavioural-anomaly scenarios, so the AI layer's recall is **untested on real traffic**. 23 tunnels from one lab setup on one host is small.
* Parse accuracy on simulated captures: 100 % for IKE datagram count, ESP packet count, tunnel reconstruction, IKE version, negotiated IKE suite, auth method and child-SA suite (consistency check — same authors wrote encoder and decoder).
* **Parser vs independent oracles on real public captures: 27/27** — decrypted AUTH payload bytes equal Wireshark's expected values for all 8 IKEv2 captures; message/packet counts and IKEv1 transform attributes agree with Scapy's separate ISAKMP dissector. These are small captures (4–16 packets).
* Real lab traffic also found two of *our* mistakes: strongSwan omits the DH transform in the initial child SA even with PFS configured, so `ESP-NO-PFS` now judges PFS only from observed rekeys (otherwise "PFS not assessable"), and the simulator's model of this was corrected.
* Throughput (single thread, laptop): parse ≈ 23k–110k packets/s (13–60 MB/s) and end-to-end incl. rules, model and SHAP ≈ 18k–80k packets/s across runs — this machine's timings were noisy; re-run before quoting (309 captures, 88k packets, 48 MB).

Where the AI layer is weak (from `docs/EVAL.json`): slow-relay latency 0/6, retransmit burst 1/6, half-open scan probes 1/6 are **missed**. Oversize handshakes (6/6) and rekey storms (5/6) are caught. Isolation Forest struggles with rare discrete values; this is the clearest place an autoencoder or richer features would help. These behavioural families exist only in the simulator.

## API

`POST /api/analyses` (multipart `pcap`, optional `keys`) · `POST /api/samples/{name}/analyze` · `GET /api/analyses/{id}` (status + stage) ·
`…/tunnels` · `…/tunnels/{tid}` (SA detail, findings, risk, SHAP) · `…/remediation` · `…/report.pdf` · `…/export.json` · `…/export.syslog` ·
`GET /api/metrics` · `GET /api/policy` · `GET /api/health`. Interactive docs at `/docs`.

## Honest list of corners cut

* Lab traffic is strongSwan-only (no Libreswan), one host, LAN-like latency; no CIC-IDS2018 (not IPsec-labelled, not used); no live NIC capture — the UI's "Replay capture" animates a stored handshake timeline.
* PyShark/TShark not used; autoencoder not built; IKEv1 phase-2 and keyless IKEv2 child SAs not observable; IKEv1 encrypted-payload decryption not implemented.
* IKEv2 NAT-T is handled (marker, UDP-encapsulated ESP) but only exercised lightly; IPv6 decoding is minimal; AH is counted, not analysed in depth.
* Single-file in-memory analysis with a 64 MB upload cap; streaming/chunked ingest is the documented upgrade path. No authentication/RBAC (single-user demo).
* WireGuard/OpenVPN: roadmap only.
* Risk weights and bands are judgment calls, not calibrated against incident data.
* The UI was exercised in headless Edge against the real API (upload → results → detail → evaluation) with no failed requests; it has no automated frontend tests.
