"""SIEM exports: JSON and RFC 5424 syslog carrying CEF payloads (one event per violation finding)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_SEV = {"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
_SYSLOG_SEV = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}


def _cef(s: str, header: bool = False) -> str:
    s = str(s).replace("\\", "\\\\").replace("\n", " ")
    return s.replace("|", "\\|") if header else s.replace("=", "\\=")


def to_syslog(analysis: dict[str, Any], tunnels: list[dict[str, Any]], host: str = "ipsec-analyzer") -> str:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines: list[str] = []
    for t in tunnels:
        tun = t["tunnel"]
        for f in t["findings"]:
            if f["category"] != "violation":
                continue
            mitre = ",".join(m["id"] for m in f["mitre"])
            ext = (f"src={tun['initiator']} dst={tun['responder']} cs1Label=tunnel cs1={_cef(t['tunnel']['id'])} "
                   f"cs2Label=riskScore cs2={t['risk']['score']} cs3Label=mitre cs3={_cef(mitre)} "
                   f"cs4Label=provenance cs4={_cef(analysis['provenance'])} msg={_cef(f['description'][:200])}")
            cef = f"CEF:0|IPsecAnalyzer|VPN Analyzer|1.0|{_cef(f['rule_id'], True)}|{_cef(f['title'], True)}|{_SEV[f['severity']]}|{ext}"
            pri = 8 * 1 + _SYSLOG_SEV[f["severity"]]
            lines.append(f"<{pri}>1 {ts} {host} ipsec-analyzer - {f['rule_id']} - {cef}")
    return "\n".join(lines) + ("\n" if lines else "")


def to_json(analysis: dict[str, Any], tunnels: list[dict[str, Any]]) -> dict[str, Any]:
    return {"analysis": analysis, "tunnels": tunnels}
