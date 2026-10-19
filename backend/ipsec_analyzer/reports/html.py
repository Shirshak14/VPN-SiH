"""Self-contained, printable HTML report: one file, no scripts, no external resources, so it can be emailed, archived or
printed to PDF from any browser. Every figure is read from the stored analysis; every value is escaped."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape

from typing import Any

from ..scoring import FORMULA
from .pdf import PROV_NOTE
from .summary import attack_rollup, remediation_plan

CSS = """
:root{--ink:#1d2430;--muted:#5b6470;--line:#d9dee5;--bg:#fff;--soft:#f5f7fa;--critical:#b42318;--high:#d9480f;--medium:#b7791f;--low:#2b6cb0;--info:#5b6470}
*{box-sizing:border-box}
body{margin:0;background:var(--soft);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 28px 56px;background:var(--bg)}
h1{font-size:26px;line-height:1.2;margin:0 0 4px}h2{font-size:18px;margin:34px 0 10px;padding-bottom:6px;border-bottom:2px solid var(--ink)}
h3{font-size:15px;margin:22px 0 6px}p{margin:6px 0}code,pre,.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.muted{color:var(--muted)}.small{font-size:12px}
.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin:0 0 18px;padding:10px 14px;background:var(--soft);border:1px solid var(--line);border-radius:8px}
.toolbar button{font:inherit;padding:6px 14px;border-radius:6px;border:1px solid var(--ink);background:var(--ink);color:#fff;cursor:pointer}
.note{padding:10px 14px;border:1px solid var(--medium);border-left-width:4px;background:#fffaf0;border-radius:6px;margin:14px 0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:14px 0}
.kpi{border:1px solid var(--line);border-radius:8px;padding:10px 12px}.kpi b{display:block;font-size:22px;line-height:1.2}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:12.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--soft);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:600;color:#fff;text-transform:uppercase;letter-spacing:.03em}
.critical{background:var(--critical)}.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}
.tunnel{break-before:page}.tunnel:first-of-type{break-before:auto}
.finding{border:1px solid var(--line);border-left:4px solid var(--info);border-radius:6px;padding:8px 12px;margin:10px 0;break-inside:avoid}
.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}
.finding .badge{margin-right:6px}pre{background:var(--soft);padding:8px 10px;border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;margin:6px 0}
ol{margin:4px 0 4px 20px;padding:0}li{margin:2px 0}.fix{break-inside:avoid;margin:10px 0}
footer{margin-top:40px;padding-top:10px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
@media print{body{background:#fff}main{max-width:none;padding:0}.toolbar{display:none}h2{break-after:avoid}a{color:inherit;text-decoration:none}@page{margin:16mm}}
"""


def _e(v: Any) -> str:
    return escape(str(v))


def _badge(level: str) -> str:
    return f'<span class="badge {_e(level)}">{_e(level)}</span>'


def _anchor(tid: str) -> str:
    return "t-" + "".join(c if c.isalnum() else "-" for c in tid)


def _evidence(ev: dict[str, Any]) -> str:
    return "; ".join(f"{k}={v}" for k, v in ev.items() if k != "all_offenders")[:600]


def build_html(analysis: dict[str, Any], tunnels: list[dict[str, Any]]) -> str:
    sm = analysis["summary"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    viol_total = sum(1 for t in tunnels for f in t["findings"] if f["category"] == "violation")
    clean = sum(1 for t in tunnels if not any(f["category"] == "violation" for f in t["findings"]))
    top = max(tunnels, key=lambda t: t["risk"]["score"], default=None)
    plan, attack = remediation_plan(tunnels), attack_rollup(tunnels)
    title = f"IPsec VPN assessment - {analysis['filename']}"
    o: list[str] = [
        f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta name="robots" content="noindex"><title>{_e(title)}</title><style>{CSS}</style></head><body><main>',
        '<div class="toolbar"><span class="small muted">Use Print, then choose "Save as PDF" to keep a copy.</span>'
        '<button type="button" onclick="window.print()">Print / save as PDF</button></div>',
        f'<h1>IPsec VPN Security Assessment</h1><p class="muted">Capture <span class="mono">{_e(analysis["filename"])}</span> · '
        f'policy {_e(sm["policy"])} · report generated {now}</p>',
        f'<div class="note"><b>Data provenance.</b> {_e(PROV_NOTE.get(analysis["provenance"], analysis["provenance"]))}</div>',
        "<h2>Executive summary</h2>",
    ]
    if top is None:
        o.append("<p>No IKE or ESP tunnels were found in this capture.</p>")
    else:
        o.append(f'<p>Highest risk is <b>{top["risk"]["score"]}/100</b> {_badge(top["risk"]["band"])} on '
                 f'<a href="#{_anchor(top["tunnel"]["id"])}" class="mono">{_e(top["tunnel"]["initiator"])} → {_e(top["tunnel"]["responder"])}</a>. '
                 f'{viol_total} policy violation{"" if viol_total == 1 else "s"} across {len(tunnels) - clean} of {len(tunnels)} tunnel{"" if len(tunnels) == 1 else "s"}; '
                 f'{clean} tunnel{"" if clean == 1 else "s"} without violations.</p>')
    anomalous = sum(1 for t in tunnels if (t.get("anomaly") or {}).get("is_anomalous"))
    o.append('<div class="kpis">' + "".join(f'<div class="kpi"><b>{_e(v)}</b><span class="small muted">{_e(k)}</span></div>' for k, v in [
        ("tunnels", len(tunnels)), ("violations", viol_total), ("flagged anomalous", anomalous if sm.get("anomaly_model") else "n/a"),
        ("IKE messages", sm["ike_messages"]), ("ESP packets", sm["esp_packets"]), ("packets", sm["packets"])]) + "</div>")
    o.append(f'<p class="small muted">Decryption keys supplied for {sm["decrypted_tunnels"]} tunnel(s); IKEv2 authentication and child SAs, and IKEv1 Quick Mode, '
             f'are reported as not assessable without them. Analysed in {analysis["seconds"]} s.</p>')
    unanalysed = [v for v in sm.get("other_vpn", []) if not v.get("analysed")]
    if unanalysed:
        o.append('<div class="note"><b>Other VPN traffic seen, no session recognised well enough to assess:</b> ' + _e("; ".join(f'{v["protocol"]} ({v["packets"]} packets)' for v in unanalysed)) + ".</div>")
    if sm.get("source") == "config":
        o.append('<div class="note"><b>Assessed from a configuration file.</b> A configuration shows what an operator asked for, not what two peers negotiated; secrets in the file were removed before analysis.</div>')

    o.append("<h2>Tunnels, highest risk first</h2><table><thead><tr><th>Risk</th><th>Peers</th><th>Mode</th><th>Negotiated suite</th><th>Violations</th></tr></thead><tbody>")
    for t in tunnels:
        tu, n = t["tunnel"], sum(1 for f in t["findings"] if f["category"] == "violation")
        o.append(f'<tr><td><b>{t["risk"]["score"]}</b> {_badge(t["risk"]["band"])}</td>'
                 f'<td class="mono"><a href="#{_anchor(tu["id"])}">{_e(tu["initiator"])} → {_e(tu["responder"])}</a></td>'
                 f'<td>{_e(tu["exchange_mode"])}</td><td class="mono">{_e((tu["chosen"] or {}).get("label", "none negotiated"))}</td><td>{n}</td></tr>')
    o.append("</tbody></table>")

    o.append("<h2>MITRE ATT&amp;CK techniques</h2>")
    if attack:
        o.append("<table><thead><tr><th>Technique</th><th>Tactic</th><th>Tunnels</th><th>Worst severity</th></tr></thead><tbody>")
        o += [f'<tr><td><span class="mono">{_e(a["id"])}</span> {_e(a["name"])}</td><td>{_e(a["tactic"])}</td><td>{a["tunnels"]}/{len(tunnels)}</td><td>{_badge(a["severity"])}</td></tr>' for a in attack]
        o.append("</tbody></table>")
    else:
        o.append('<p class="muted">No rule finding in this capture maps to an ATT&amp;CK technique.</p>')

    o.append(f"<h2>Remediation plan{f' ({len(plan)})' if plan else ''}</h2>")
    if not plan:
        o.append('<p class="muted">No violations to remediate.</p>')
    for i, r in enumerate(plan, 1):
        o.append(f'<div class="fix"><h3>{i}. {_e(r["title"])} {_badge(r["severity"])}</h3>'
                 f'<p class="small muted">Addresses {_e(", ".join(r["rules"]))} on {len(r["tunnels"])} tunnel{"" if len(r["tunnels"]) == 1 else "s"}.</p>'
                 f'<ol>{"".join(f"<li>{_e(s)}</li>" for s in r["steps"])}</ol>' + (f'<pre>{_e(r["example"])}</pre>' if r.get("example") else "") + "</div>")

    o.append("<h2>Findings per tunnel</h2>")
    for t in tunnels:
        tu, risk = t["tunnel"], t["risk"]
        o.append(f'<section class="tunnel" id="{_anchor(tu["id"])}"><h3>{_e(tu["initiator"])} → {_e(tu["responder"])} · risk {risk["score"]} {_badge(risk["band"])}</h3>'
                 f'<p class="small muted mono">{_e(tu["id"])} · {_e(tu["exchange_mode"])} · status {_e(tu["status"])}{" (" + _e(tu["failure"]) + ")" if tu["failure"] else ""}'
                 f' · rules component {risk["rules_component"]}, anomaly component {risk["anomaly_component"]}</p>')
        viol = [f for f in t["findings"] if f["category"] == "violation"]
        cov = [f for f in t["findings"] if f["category"] == "coverage"]
        if not viol:
            o.append("<p>No policy violations detected.</p>")
        for f in viol:
            mitre = ", ".join(f'{m["id"]} {m["name"]}' for m in f["mitre"]) or "none mapped"
            o.append(f'<div class="finding {_e(f["severity"])}"><div>{_badge(f["severity"])}<b>{_e(f["rule_id"])} — {_e(f["title"])}</b></div>'
                     f'<p>{_e(f["description"])}</p><pre>{_e(_evidence(f["evidence"]))}</pre>'
                     f'<p class="small muted">References: {_e(", ".join(f["refs"]))} · MITRE ATT&amp;CK: {_e(mitre)}</p>'
                     f'<p class="small"><b>Fix:</b> {_e(f["remediation"]["title"])}</p></div>')
        an = t.get("anomaly")
        if an:
            ex = an["explanation"]
            o.append(f'<p><b>Behavioural anomaly model.</b> Score {an["score"]} ({"anomalous" if an["is_anomalous"] else "within baseline"}); dominant group {_e(an["dominant_group"])}.</p>')
            if ex.get("top_features"):
                o.append('<ul class="small">' + "".join(
                    f'<li>{_e(f["label"])}: {_e(f["value"])} (benign median {_e(f["baseline_median"])}), SHAP {f["shap"]:+} ({_e(f["direction"])})</li>' for f in ex["top_features"]) + "</ul>")
        if cov:
            o.append('<p class="small muted"><b>Not assessable from this capture:</b> ' + _e("; ".join(f["title"] for f in cov)) + ".</p>")
        o.append("</section>")

    o.append(f'<h2>Method</h2><p class="small">Risk score formula: {_e(FORMULA)} Severity weights and bands come from the policy pack ({_e(sm["policy"])}).</p>'
             f'<footer>Generated by IPsec VPN Analyzer (SIH26160 prototype) on {now}. Capture provenance: {_e(analysis["provenance"])}.</footer></main></body></html>')
    return "".join(o)
