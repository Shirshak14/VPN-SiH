"""Runs an analysis and persists it."""
from __future__ import annotations

import os
import traceback
from pathlib import Path
from typing import Any

from ..ml.model import DEFAULT_MODEL, AnomalyModel
from ..pipeline import AnalysisResult, TunnelResult, analyze
from ..rules import RuleEngine
from .db import Analysis, SessionLocal, TunnelRow

_engine: RuleEngine | None = None
_model: AnomalyModel | None = None


def get_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine(os.environ.get("POLICY_PATH") or None)
    return _engine


def get_model() -> AnomalyModel | None:
    """The anomaly model is optional at runtime: if it has not been trained, rules still work."""
    global _model
    if _model is None and Path(DEFAULT_MODEL).exists():
        _model = AnomalyModel.load(DEFAULT_MODEL, get_engine())
    return _model


def tunnel_payload(r: TunnelResult) -> dict[str, Any]:
    return {
        "tunnel": r.tunnel.to_dict(),
        "findings": [f.to_dict() for f in r.findings],
        "risk": r.risk.to_dict(),
        "anomaly": r.anomaly,
    }


def summarize(res: AnalysisResult) -> dict[str, Any]:
    st = res.capture.stats
    bands: dict[str, int] = {}
    for r in res.tunnels:
        bands[r.risk.band] = bands.get(r.risk.band, 0) + 1
    return {
        "packets": st.packets, "ike_messages": st.ike_messages, "ike_malformed": st.ike_malformed,
        "esp_packets": st.esp_packets, "ah_packets": st.ah_packets, "natt_keepalives": st.natt_keepalives,
        "tunnel_count": len(res.tunnels), "bands": bands, "orphan_esp_flows": len(res.reconstruction.orphan_esp),
        "policy": res.policy_name, "anomaly_model": get_model() is not None,
        "decrypted_tunnels": sum(1 for r in res.tunnels if r.tunnel.decrypted),
        "parse_errors": st.errors[:10], "duration_s": round(st.last_ts - st.first_ts, 2),
    }


def run_analysis(analysis_id: int, pcap: Path, keys: Path | None) -> None:
    """Executed in a worker thread. Updates stage/status so the UI can show progress."""
    def stage(name: str) -> None:
        with SessionLocal() as s:
            a = s.get(Analysis, analysis_id)
            a.status, a.stage = "running", name
            s.commit()

    try:
        res = analyze(pcap, keys, get_engine(), get_model(), progress=stage)
        with SessionLocal() as s:
            a = s.get(Analysis, analysis_id)
            a.summary, a.seconds, a.status, a.stage = summarize(res), round(res.seconds, 3), "done", "done"
            for r in res.tunnels:
                s.add(TunnelRow(analysis_id=analysis_id, tunnel_id=r.tunnel.id, risk=r.risk.score, band=r.risk.band,
                                payload=tunnel_payload(r)))
            s.commit()
    except Exception as e:  # surface a readable error in the UI, keep the trace in the server log
        traceback.print_exc()
        with SessionLocal() as s:
            a = s.get(Analysis, analysis_id)
            a.status, a.stage, a.error = "failed", "failed", f"{type(e).__name__}: {e}"[:990]
            s.commit()
