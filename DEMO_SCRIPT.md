# Demo script (about 3½ minutes): Capture → Analyze → Score → Remediate → Prove the fix

Setup: either the hosted demo (README → *Hosted demo*) or API on :8000 and UI on :5173 (see README). Everything below uses bundled
captures, so nothing needs uploading. Say "simulated" out loud when showing `demo_gateway_audit`; the UI labels it too. If the
server has an `API_KEY`, sign in with it first: the read-only key can view results but cannot start an analysis.

**Before you start**, analyze `weak_des_md5_modp768` and `ok_aes256gcm_ecp384` once from the bundled list, so the Compare step at 3:00
is instant.

| Time | Screen | Say / do |
|---|---|---|
| 0:00 | **Analyze** page | "Today auditing IPsec means reading IKE packets one by one in a packet viewer: slow, expert-only, packet-level." |
| 0:15 | Bundled captures | Click **Analyze** on `demo_gateway_audit` (amber *synthetic (simulated)* badge). "A simulated gateway capture with 12 tunnels; real public and real lab captures are listed with it." Watch the pipeline highlight each stage. |
| 0:35 | **Results**: summary and **Overview** | "Every tunnel reconstructed and scored." Point at the **risk strip**: one dot per tunnel across the info → critical zones; hover a critical dot to show its peers and score. Then the **ATT&CK** card: "6 of 12 tunnels expose Network Sniffing and Adversary-in-the-Middle; 2 show Weaken Encryption." |
| 1:00 | Click the top critical dot | Show the **score breakdown** ("R from rules, A from anomaly, inspectable formula"). Show **Security Association**: offered vs negotiated (weak suite chosen when a strong one was offered). |
| 1:20 | Handshake timeline | Click **▶ Replay capture**: the init → auth → DPD sequence, retransmissions flagged. |
| 1:35 | Findings | Open one finding: evidence, NIST/RFC references, **MITRE ATT&CK** chips (T1557, T1600). "Downgrade pattern: strong proposal rejected, retry offered only weak suites." |
| 1:55 | Anomaly model | Back on the results, open a tunnel with the *anomalous* badge; show the group scores and **SHAP bars**: "explanation computed from the fitted model, not canned." (For the benign-envelope groups, such as response time, the panel shows deviation from the benign baseline and says it is not SHAP; `a_slow_relay_00` is the bundled example.) |
| 2:15 | Back to the `demo_gateway_audit` results → **Policy rules checked** | "This is everything we check." The rules that fired in this capture are highlighted with how many tunnels they hit; each row shows its NIST/RFC source, ATT&CK technique and fix. Scroll to the **algorithm tiers** and the **risk formula**: "nothing hidden." |
| 2:40 | Results → **Remediation plan** | Expand one item for the strongSwan config example; click **Download PDF report**; mention JSON and syslog/CEF for the SOC. |
| 3:00 | **Compare** tab | Before = `weak_des_md5_modp768`, After = `ok_aes256gcm_ecp384` (both *real · strongSwan lab*). "The same two lab peers, first with a weak config, then with the suite our remediation recommends: risk falls from 97.3 critical to 0, five critical/high rules fixed, nothing new." |
| 3:20 | **Evaluation** tab | "On 168 held-out simulated tunnels, rules plus AI: 97.3 % precision, 99.1 % recall. On real strongSwan lab traffic, 10 of 10 weak tunnels found with no false alarms. The parser matches Wireshark and Scapy on 33 of 33 checks on real captures." Close on the limitations banner. |

If asked about keys: "IKEv2 and IKEv1 encrypt the later handshake messages. With keys we see ESP algorithms and PFS, for IKEv1 Quick Mode
too; without them the UI says *not assessable* rather than guessing." Try `ikev2-decrypt-aes256cbc.pcapng` for the no-keys message.

If asked about other VPNs: WireGuard and OpenVPN traffic in a capture is reported as *seen, not analysed* (banner on the results page).
