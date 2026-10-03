"""FastAPI application.  Run:  uvicorn ipsec_analyzer.api.main:app --port 8000"""
from __future__ import annotations

import json
import shutil
import threading
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..reports.export import to_json, to_syslog
from ..reports.pdf import build_pdf
from ..rules.policy import SEV_ORDER
from . import service
from .db import DATA_DIR, Analysis, SessionLocal, TunnelRow, init_db

MAX_UPLOAD = 64 * 1024 * 1024
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
CAPTURES = DATA_DIR / "captures"
PUBLIC = DATA_DIR / "public"

app = FastAPI(title="IPsec VPN Analyzer", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def _startup() -> None:
    init_db()
    service.get_engine()  # fail fast on a malformed policy pack
    threading.Thread(target=service.warm_up, name="warm-up", daemon=True).start()  # first analysis then runs warm


def db() -> Session:
    with SessionLocal() as s:
        yield s


def _analysis_dict(a: Analysis) -> dict[str, Any]:
    return {"id": a.id, "filename": a.filename, "provenance": a.provenance, "status": a.status, "stage": a.stage,
            "error": a.error, "created_at": a.created_at.isoformat(), "seconds": a.seconds, "summary": a.summary,
            "has_keys": bool(a.has_keys)}


def _get(s: Session, aid: int) -> Analysis:
    a = s.get(Analysis, aid)
    if a is None:
        raise HTTPException(404, "analysis not found")
    return a


def _tunnels(s: Session, aid: int) -> list[dict[str, Any]]:
    rows = s.scalars(select(TunnelRow).where(TunnelRow.analysis_id == aid).order_by(TunnelRow.risk.desc())).all()
    return [r.payload for r in rows]


def _done(s: Session, aid: int) -> Analysis:
    a = _get(s, aid)
    if a.status != "done":
        raise HTTPException(409, f"analysis is {a.status}")
    return a


# ------------------------------------------------------------------ meta
@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "policy": service.get_engine().policy.name, "anomaly_model": service.get_model() is not None}


@app.get("/api/metrics")
def metrics() -> dict[str, Any]:
    p = DATA_DIR.parent / "docs" / "EVAL.json"
    if not p.exists():
        raise HTTPException(404, "no evaluation yet: run `python -m ipsec_analyzer.evaluation`")
    return json.loads(p.read_text())


def _samples() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    mp = CAPTURES / "manifest.json"
    if mp.exists():
        man = json.loads(mp.read_text())
        picks = ["demo_gateway_audit"] + [f"{f}_00" for f in ("w_v1_aggr_psk", "d_retry_after_reject", "b_modern", "a_slow_relay")]
        for n in picks:
            if n in man and (CAPTURES / man[n]["file"]).exists():
                m = man[n]
                out[n] = {"name": n, "provenance": "synthetic", "pcap": CAPTURES / m["file"],
                          "keys": CAPTURES / m["keys"] if m.get("keys") else None,
                          "description": "Simulated multi-tunnel gateway capture (11 tunnels: compliant, weak, downgrade, anomalous)"
                          if n == "demo_gateway_audit" else f"Simulated single-tunnel scenario: {m['family']}"}
    lm = CAPTURES / "lab" / "manifest.json"
    if lm.exists():
        lab = json.loads(lm.read_text())
        for n in ("ok_aes256gcm_ecp384", "weak_des_md5_modp768", "downgrade_retry_after_reject", "weak_ikev1_aggressive_psk"):
            if n in lab and (CAPTURES / "lab" / lab[n]["file"]).exists():
                m = lab[n]
                out[n] = {"name": n, "provenance": "real-lab", "pcap": CAPTURES / "lab" / m["file"],
                          "keys": CAPTURES / "lab" / m["keys"] if m.get("keys") else None,
                          "description": f"Real strongSwan 5.9.8 traffic from the Docker lab. Scenario: {m['description']}"}
    pm = PUBLIC / "manifest.json"
    if pm.exists():
        man = json.loads(pm.read_text())
        for f in list(man["ikev1"]) + ["ikev2-decrypt-aes256gcm16.pcap", "ikev2-decrypt-3des-sha1_160.pcap"]:
            if (PUBLIC / f).exists():
                v2 = f.startswith("ikev2")
                out[f] = {"name": f, "provenance": "real-public", "pcap": PUBLIC / f,
                          "keys": PUBLIC / man["keys"] if v2 else None,
                          "description": "Real Wireshark public sample capture" + (" (decryption keys from Wireshark test suite)" if v2 else "")}
    return out


@app.get("/api/samples")
def samples() -> list[dict[str, Any]]:
    return [{k: v for k, v in s.items() if k not in ("pcap", "keys")} | {"has_keys": s["keys"] is not None}
            for s in _samples().values()]


@app.get("/api/policy")
def policy() -> dict[str, Any]:
    p = service.get_engine().policy
    return {"name": p.name, "thresholds": p.thresholds, "tiers": p.raw["tiers"], "severity_weight": p.raw["severity_weight"],
            "risk": p.raw["risk"], "rules": [{k: r.get(k) for k in ("id", "title", "severity", "severity_by_tier", "refs", "mitre")}
                                            for r in p.rules]}


# ------------------------------------------------------------------ analyses
@app.post("/api/analyses", status_code=202)
async def create_analysis(bg: BackgroundTasks, pcap: UploadFile = File(...), keys: UploadFile | None = File(None),
                          s: Session = Depends(db)) -> dict[str, Any]:
    head = await pcap.read(4)
    if head not in PCAP_MAGICS:
        raise HTTPException(400, "not a PCAP/PCAPNG file (bad magic bytes)")
    a = Analysis(filename=(pcap.filename or "upload.pcap")[:255], provenance="user-upload", has_keys=int(keys is not None))
    s.add(a)
    s.commit()
    d = DATA_DIR / "uploads" / str(a.id)
    d.mkdir(parents=True, exist_ok=True)
    size = len(head)
    with open(d / "capture.pcap", "wb") as f:
        f.write(head)
        while chunk := await pcap.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD:
                shutil.rmtree(d, ignore_errors=True)
                s.delete(a)
                s.commit()
                raise HTTPException(413, f"capture exceeds {MAX_UPLOAD // 2**20} MB demo limit (streaming ingest is roadmap)")
            f.write(chunk)
    kp = None
    if keys is not None:
        kp = d / "keys.txt"
        kp.write_bytes(await keys.read())
    bg.add_task(service.run_analysis, a.id, d / "capture.pcap", kp)
    return _analysis_dict(a)


@app.post("/api/samples/{name}/analyze", status_code=202)
def analyze_sample(name: str, bg: BackgroundTasks, s: Session = Depends(db)) -> dict[str, Any]:
    smp = _samples().get(name)
    if smp is None:
        raise HTTPException(404, "unknown sample")
    a = Analysis(filename=name, provenance=smp["provenance"], has_keys=int(smp["keys"] is not None))
    s.add(a)
    s.commit()
    bg.add_task(service.run_analysis, a.id, smp["pcap"], smp["keys"])
    return _analysis_dict(a)


@app.get("/api/analyses")
def list_analyses(s: Session = Depends(db)) -> list[dict[str, Any]]:
    return [_analysis_dict(a) for a in s.scalars(select(Analysis).order_by(Analysis.id.desc()).limit(50))]


@app.get("/api/analyses/{aid}")
def get_analysis(aid: int, s: Session = Depends(db)) -> dict[str, Any]:
    return _analysis_dict(_get(s, aid))


@app.delete("/api/analyses/{aid}", status_code=204)
def delete_analysis(aid: int, s: Session = Depends(db)) -> Response:
    s.delete(_get(s, aid))
    s.commit()
    shutil.rmtree(DATA_DIR / "uploads" / str(aid), ignore_errors=True)
    return Response(status_code=204)


@app.get("/api/analyses/{aid}/tunnels")
def list_tunnels(aid: int, s: Session = Depends(db)) -> list[dict[str, Any]]:
    _done(s, aid)
    out = []
    for p in _tunnels(s, aid):
        t = p["tunnel"]
        out.append({"id": t["id"], "initiator": t["initiator"], "responder": t["responder"], "ike_version": t["ike_version"],
                    "exchange_mode": t["exchange_mode"], "status": t["status"], "chosen": t["chosen"], "decrypted": t["decrypted"],
                    "risk": p["risk"], "anomaly_score": (p["anomaly"] or {}).get("score"),
                    "violations": [{"rule_id": f["rule_id"], "severity": f["severity"]} for f in p["findings"] if f["category"] == "violation"]})
    return out


@app.get("/api/analyses/{aid}/tunnels/{tid}")
def get_tunnel(aid: int, tid: str, s: Session = Depends(db)) -> dict[str, Any]:
    _done(s, aid)
    row = s.scalars(select(TunnelRow).where(TunnelRow.analysis_id == aid, TunnelRow.tunnel_id == tid)).first()
    if row is None:
        raise HTTPException(404, "tunnel not found")
    return row.payload


@app.get("/api/analyses/{aid}/remediation")
def remediation(aid: int, s: Session = Depends(db)) -> list[dict[str, Any]]:
    """Consolidated remediation plan: each remediation once, with the rules/tunnels that need it."""
    _done(s, aid)
    plan: dict[str, dict[str, Any]] = {}
    for p in _tunnels(s, aid):
        for f in p["findings"]:
            if f["category"] != "violation":
                continue
            r = plan.setdefault(f["remediation"]["id"], {**f["remediation"], "rules": set(), "tunnels": set(), "severity": f["severity"]})
            r["rules"].add(f["rule_id"])
            r["tunnels"].add(p["tunnel"]["id"])
            if SEV_ORDER[f["severity"]] < SEV_ORDER[r["severity"]]:
                r["severity"] = f["severity"]
    return sorted(({**v, "rules": sorted(v["rules"]), "tunnels": sorted(v["tunnels"])} for v in plan.values()),
                  key=lambda v: SEV_ORDER[v["severity"]])


@app.get("/api/analyses/{aid}/report.pdf")
def report_pdf(aid: int, s: Session = Depends(db)) -> Response:
    a = _done(s, aid)
    pdf = build_pdf(_analysis_dict(a), _tunnels(s, aid))
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="ipsec-report-{aid}.pdf"'})


@app.get("/api/analyses/{aid}/export.json")
def export_json(aid: int, s: Session = Depends(db)) -> Response:
    a = _done(s, aid)
    return Response(json.dumps(to_json(_analysis_dict(a), _tunnels(s, aid)), indent=1), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="ipsec-analysis-{aid}.json"'})


@app.get("/api/analyses/{aid}/export.syslog")
def export_syslog(aid: int, s: Session = Depends(db)) -> Response:
    a = _done(s, aid)
    return Response(to_syslog(_analysis_dict(a), _tunnels(s, aid)), media_type="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="ipsec-analysis-{aid}.syslog"'})
