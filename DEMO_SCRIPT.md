# Demo script (2–3 minutes): Capture → Analyze → Score → Remediate

Setup: API on :8000, UI on :5173 (see README). Have `demo_gateway_audit` available (bundled). Say "simulated" out loud when showing it — the UI labels it too.

| Time | Screen | Say / do |
|---|---|---|
| 0:00 | **Analyze** page | "Today auditing IPsec means reading IKE packets one by one in a packet viewer — slow, expert-only, packet-level." Point at the *Before / After* cards. |
| 0:20 | Bundled captures | Click **Analyze** on `demo_gateway_audit` (amber *synthetic (simulated)* badge). "This is a simulated gateway capture with 11 tunnels; real public captures are listed below it." Watch the pipeline highlight each stage. |
| 0:40 | **Results** | "Every tunnel reconstructed and ranked by risk." Point at the provenance banner, KPIs, then the top row (critical). |
| 1:00 | Click top tunnel | Show the **score breakdown** ("R from rules, A from anomaly — inspectable formula"). Show **Security Association**: offered vs negotiated (weak suite chosen when a strong one was offered). |
| 1:20 | Handshake timeline | Click **▶ Replay capture** — the init → auth → DPD sequence, retransmissions flagged. |
| 1:35 | Findings | Open one finding: evidence, NIST/RFC references, **MITRE ATT&CK** chips (T1557, T1600). "Downgrade pattern: strong proposal rejected, retry offered only weak suites." |
| 1:55 | Anomaly model | Show group scores and **SHAP bars** on a behavioural-anomaly tunnel: "explanation computed from the fitted model, not canned." |
| 2:15 | Back to results | Scroll to **Remediation plan**; click **Download PDF report**; mention JSON and syslog/CEF for the SOC. |
| 2:35 | **Real traffic** (optional) | Analyze `weak_des_md5_modp768` (green *real · strongSwan lab*) — real IKE/ESP from two strongSwan daemons, scored critical — or `ikev1-bug-12620.pcapng` (*real · public*): real aggressive-mode PSK flagged with T1110.002. |
| 2:50 | **Evaluation** tab | "Numbers are on held-out simulated data and say so; the real-capture validation is 27/27 against Wireshark and Scapy oracles." Close on the limitations banner. |

If asked about keys: "IKEv2 encrypts auth and child SAs. With keys we see ESP algorithms and PFS; without, the UI says *not assessable* rather than guessing." Try `ikev2-decrypt-aes256cbc.pcapng` for the no-keys message.
