"""End-to-end analysis: PCAP -> parse -> reconstruct -> rules -> (anomaly) -> risk."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .parser import ParsedCapture, parse_pcap
from .parser.decrypt import load_key_table
from .rules import Finding, RuleEngine
from .sa import Reconstruction, Tunnel, reconstruct
from .scoring import RiskScore, score_tunnel


@dataclass
class TunnelResult:
    tunnel: Tunnel
    findings: list[Finding]
    risk: RiskScore
    anomaly: dict[str, Any] | None = None


@dataclass
class AnalysisResult:
    path: str
    tunnels: list[TunnelResult]
    reconstruction: Reconstruction
    capture: ParsedCapture
    policy_name: str
    seconds: float
    key_file: str | None = None
    notes: list[str] = field(default_factory=list)


def analyze(pcap: str | Path, keys: str | Path | None = None, engine: RuleEngine | None = None,
            anomaly_model: Any | None = None, progress: Callable[[str], None] | None = None) -> AnalysisResult:
    t0 = time.perf_counter()
    step = progress or (lambda _s: None)
    step("parsing IKE/ESP")
    engine = engine or RuleEngine()
    key_rows = load_key_table(keys) if keys else None
    cap = parse_pcap(pcap, keys=key_rows)
    step("reconstructing SAs")
    rec = reconstruct(cap)
    step("rules + anomaly model")
    results: list[TunnelResult] = []
    for t in rec.tunnels:
        findings = engine.evaluate(t)
        anomaly = anomaly_model.score(t) if anomaly_model is not None else None
        risk = score_tunnel(findings, anomaly["score"] if anomaly else None, engine.policy)
        results.append(TunnelResult(t, findings, risk, anomaly))
    results.sort(key=lambda r: r.risk.score, reverse=True)
    return AnalysisResult(str(pcap), results, rec, cap, engine.policy.name, time.perf_counter() - t0,
                          str(keys) if keys else None)
