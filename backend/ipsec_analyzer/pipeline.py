"""End-to-end analysis: PCAP -> parse -> reconstruct -> rules -> (anomaly) -> risk."""
from __future__ import annotations

import time
from dataclasses import dataclass
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
    risk: RiskScore | None  # set by score_analyses
    anomaly: dict[str, Any] | None = None


@dataclass
class AnalysisResult:
    tunnels: list[TunnelResult]
    reconstruction: Reconstruction
    capture: ParsedCapture
    policy_name: str
    seconds: float
    log: dict[str, Any] | None = None  # set when the tunnels came from a daemon log instead of a capture


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
    res = AnalysisResult([TunnelResult(t, engine.evaluate(t), None) for t in rec.tunnels], rec, cap, engine.policy.name, 0.0)
    score_analyses([res], anomaly_model, engine)
    res.seconds = time.perf_counter() - t0
    return res


def score_analyses(analyses: list[AnalysisResult], anomaly_model: Any | None, engine: RuleEngine) -> None:
    """Fill in anomaly and risk for every tunnel, then order each analysis by risk.

    All tunnels go to the model in one batch (also across captures): the forests' per-call overhead dwarfs the per-row
    cost, and rows are scored independently, so batching does not change any number.
    """
    results = [r for a in analyses for r in a.tunnels]
    anomalies = anomaly_model.score_many([r.tunnel for r in results]) if anomaly_model is not None else [None] * len(results)
    for r, anomaly in zip(results, anomalies):
        r.anomaly = anomaly
        r.risk = score_tunnel(r.findings, anomaly["score"] if anomaly else None, engine.policy)
    for a in analyses:
        a.tunnels.sort(key=lambda r: r.risk.score, reverse=True)


def analyze_log(log: str | Path, engine: RuleEngine | None = None, progress: Callable[[str], None] | None = None) -> AnalysisResult:
    """Daemon log -> tunnels -> rules -> risk. Same engine and score as a capture; no anomaly model (see ingest/charon.py)."""
    from .ingest.charon import LogError, parse_log
    from .parser.models import CaptureStats, ParsedCapture
    from .rules.engine import Finding
    from .sa import Reconstruction

    t0 = time.perf_counter()
    step = progress or (lambda _s: None)
    step("parsing IKE/ESP")
    engine = engine or RuleEngine()
    parsed = parse_log(Path(log))
    if parsed.lines_matched == 0:
        raise LogError("no strongSwan charon log lines found (expected lines like '12[IKE] ...')")
    step("reconstructing SAs")
    stats = CaptureStats(packets=parsed.lines_matched, first_ts=parsed.first_ts, last_ts=parsed.last_ts)
    cap = ParsedCapture(path=str(log), ike=[], esp_flows=[], stats=stats)
    rec = Reconstruction(parsed.tunnels, [], stats)
    step("rules + anomaly model")
    results = []
    for t in parsed.tunnels:
        findings = engine.evaluate(t)
        findings.append(Finding(
            "COV-LOG-SOURCE", "Assessed from a daemon log, not from packets", "info", "coverage", t.id,
            "Only what the daemon logged is assessed: negotiated algorithms, authentication, lifetimes, rekeys, retransmits. "
            "Message sizes, handshake timing, ESP sequencing and handshake floods are not visible in a log, so the "
            "behavioural anomaly model is not applied and those rules cannot fire.", {"reason": "log-derived"}))
        results.append(TunnelResult(t, findings, None))
    res = AnalysisResult(results, rec, cap, engine.policy.name, 0.0, parsed.info())
    score_analyses([res], None, engine)
    res.seconds = time.perf_counter() - t0
    return res
