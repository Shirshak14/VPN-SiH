# Build plan — AI-Powered IPsec VPN Analyzer (SIH26160)

## Environment facts (checked, not assumed)
| Item | State | Consequence |
|---|---|---|
| Python | 3.14 system, 3.11 via uv | Use a 3.11 venv (wheels for scikit-learn/SHAP/PyTorch exist) |
| TShark | not installed | Parser is **pure Scapy + own RFC 7296/2408 payload decoder**; PyShark is an optional cross-check, not a dependency |
| Docker | installed, daemon was stopped | Started Docker Desktop; lab depends on it |
| Network | reachable | Public Wireshark samples can be downloaded |
| Node | present | React (Vite + TypeScript) frontend |

## Data sourcing (ground truth first)
1. **Lab-generated real IKE/ESP (primary):** two strongSwan containers, `tcpdump` on the wire.
   Real protocol traffic, ground truth known because *we* wrote both configs.
   - *benign/compliant:* IKEv2 AES-GCM/AES-CBC + SHA-2 + MODP2048/3072/ECP/Curve25519, PFS on, rekeys, ESP traffic.
   - *weak-config:* IKEv1 aggressive + PSK, 3DES/DES, MD5/SHA1, MODP768/1024, no PFS, short/absurd lifetimes.
   - *downgrade:* initiator offers strong suite → responder rejects (NO_PROPOSAL_CHOSEN) → initiator retries weaker.
   These are **lab-generated attack scenarios, never real-world incidents**; the UI labels them so.
2. **Public Wireshark IPsec samples (secondary, real third-party):** used as parser-accuracy cross-checks
   and as out-of-distribution test data. Provenance recorded in `data/README.md`.
3. **Scapy-synthetic PCAPs (fallback only):** used *only* for unit-test edge cases (fragmentation, malformed
   payloads) that the lab can't cheaply produce. Never counted in headline detection metrics.
4. CIC-IDS2018: not used (huge, not IPsec-labeled). Documented as intentionally skipped.

## Phases
| # | Phase | Output | Done when |
|---|---|---|---|
| 0 | Scaffolding | repo layout, venv, git | `pytest` runs |
| 1 | Lab + captures | `lab/` docker compose, `data/captures/*.pcap` + `manifest.json` (ground-truth labels) | pcaps decode in Wireshark-compatible readers |
| 2 | Parser | `ipsec_analyzer/parser/` IKEv1/v2 + ESP/AH, fragments | parse accuracy vs manifest |
| 3 | SA reconstruction | `sa/` grouping by SPI pair, lifecycle, retransmits, downgrade sequence | tunnels match manifest |
| 4 | Rule engine | `policy/nist_rfc8221.yaml` + `rules/` | every weak scenario flagged, benign clean |
| 5 | Anomaly model | Isolation Forest on handshake/timing features | trained, persisted, evaluated |
| 6 | Risk + XAI + MITRE | 0-100 formula, SHAP TreeExplainer, technique map | explanation from fitted model |
| 7 | API | FastAPI + PostgreSQL (SQLite fallback for tests) | endpoint tests pass |
| 8 | UI | React dashboard, 5 screens | no console errors, all states |
| 9 | Reports | PDF (ReportLab), JSON, syslog CEF | PDF opens, numbers match API |
| 10 | Eval + docs | README metrics, DEMO_SCRIPT.md, docker-compose full stack | metrics regenerate from one command |

## Key design decisions
- **Own IKE decoder over Scapy's PcapReader.** Scapy's ISAKMP layer is inconsistent for IKEv2 transforms/fragments;
  a small explicit decoder is testable byte-for-byte against RFC layouts and needs no TShark.
- **Anomaly model:** Isolation Forest only (skip autoencoder — tightest timeline item, per brief).
  Explainability: SHAP `TreeExplainer` directly on the fitted `IsolationForest` (supported natively).
- **Risk score:** `risk = min(100, Σ severity_weight(rule hits, diminishing) + anomaly_weight × anomaly_score)`;
  formula lives in one documented function and is echoed in the UI.
- **Honesty rules:** every capture carries `provenance: real-lab | real-public | synthetic`; the UI shows it.
