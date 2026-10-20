"""FastAPI application.  Run:  uvicorn ipsec_analyzer.api.main:app --port 8000"""
from __future__ import annotations

import json
import os
import shutil
import threading
from typing import Any

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..reports.export import to_json, to_syslog
from ..reports.html import build_html
from ..reports.pdf import build_pdf
from ..reports.summary import remediation_plan
from ..scoring import FORMULA
from ..ingest.charon import looks_like_charon
from . import accounts, auth, gallery, live, service
from .compare import compare
from .db import DATA_DIR, Analysis, TunnelRow, User, init_db

# Uploads stream to disk in 1 MiB chunks and the parser keeps only per-flow ESP counters, so the cap is a disk/time
# limit rather than a memory one (measured: a 244 MB / 2 M-packet capture peaks at ~51 MB RSS). Override with MAX_UPLOAD_MB.
MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD_MB", "256")) * 1024 * 1024
MAX_KEYS_UPLOAD = 1024 * 1024  # a key table is a few KB; anything bigger is not one
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
CAPTURES = DATA_DIR / "captures"
PUBLIC = DATA_DIR / "public"
LOGS = DATA_DIR / "logs"
LOG_SAMPLES = {
    "strongswan_gateway.log": "Hand-written strongSwan gateway log (syslog format): six IKE SAs - compliant, weak suite chosen, downgrade retry, IKEv1 aggressive PSK, auth failure",
    "strongswan_initiator_filelog.log": "Hand-written strongSwan initiator log (filelog format): handshake retransmits, then a compliant tunnel",
}

app = FastAPI(title="IPsec VPN Analyzer", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
auth.install(app)  # no-op until API_KEY is set
app.include_router(accounts.router)


def _warm() -> None:
    service.warm_up()
    gallery.warm_previews(_samples(), service.get_engine(), service.get_model())  # headline numbers for the gallery cards


@app.on_event("startup")
def _startup() -> None:
    init_db()
    service.get_engine()  # fail fast on a malformed policy pack
    threading.Thread(target=_warm, name="warm-up", daemon=True).start()  # first analysis then runs warm
    live.start(MAX_UPLOAD)  # watched folder / syslog listener, only if WATCH_DIR / SYSLOG_LISTEN are set


@app.on_event("shutdown")
def _shutdown() -> None:
    live.stop()


db = accounts.get_session  # one session per request, shared with the current_user dependency


def _analysis_dict(a: Analysis) -> dict[str, Any]:
    return {"id": a.id, "filename": a.filename, "provenance": a.provenance, "status": a.status, "stage": a.stage,
            "error": a.error, "created_at": a.created_at.isoformat(), "seconds": a.seconds, "summary": a.summary,
            "has_keys": bool(a.has_keys), "label": a.label, "private": a.owner_id is not None}


def _get(s: Session, aid: int, user: User | None) -> Analysis:
    """Anonymous analyses are the shared demo space; an owned one is invisible (404, not 403) to everybody else."""
    a = s.get(Analysis, aid)
    if a is None or (a.owner_id is not None and (user is None or a.owner_id != user.id)):
        raise HTTPException(404, "analysis not found")
    return a


def _tunnels(s: Session, aid: int) -> list[dict[str, Any]]:
    rows = s.scalars(select(TunnelRow).where(TunnelRow.analysis_id == aid).order_by(TunnelRow.risk.desc())).all()
    return [r.payload for r in rows]


def _done(s: Session, aid: int, user: User | None) -> Analysis:
    a = _get(s, aid, user)
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
    for lf, desc in LOG_SAMPLES.items():
        if (LOGS / lf).exists():
            out[lf] = {"name": lf, "provenance": "sample-log", "input": "log", "pcap": LOGS / lf, "keys": None, "description": desc}
    pm = PUBLIC / "manifest.json"
    if pm.exists():
        man = json.loads(pm.read_text())
        for f in list(man["ikev1"]) + ["ikev2-decrypt-aes256gcm16.pcap", "ikev2-decrypt-3des-sha1_160.pcap"]:
            if (PUBLIC / f).exists():
                key_file = man["keys"] if f.startswith("ikev2") else man.get("keys_ikev1") if f in man["ikev1"] else None
                out[f] = {"name": f, "provenance": "real-public", "pcap": PUBLIC / f,
                          "keys": PUBLIC / key_file if key_file else None,
                          "description": "Real Wireshark public sample capture" + (" (decryption keys from Wireshark test suite)" if key_file else "")}
    return out


@app.get("/api/samples")
def samples() -> list[dict[str, Any]]:
    """Gallery entries, curated order first. `preview` is null until the background warm-up has analysed that capture."""
    rows = [{k: v for k, v in s.items() if k not in ("pcap", "keys")} | {"has_keys": s["keys"] is not None, "input": s.get("input", "pcap")}
            | gallery.describe(s["name"], s["description"], s["provenance"]) for s in _samples().values()]
    return sorted(rows, key=lambda r: r["order"])


@app.get("/api/policy")
def policy() -> dict[str, Any]:
    p = service.get_engine().policy
    cat, rems = p.raw["mitre_catalog"], p.raw["remediations"]
    return {"name": p.name, "thresholds": p.thresholds, "tiers": p.raw["tiers"], "severity_weight": p.raw["severity_weight"],
            "risk": p.raw["risk"], "formula": FORMULA,
            "rules": [{k: r.get(k) for k in ("id", "title", "severity", "severity_by_tier", "refs", "mitre", "description")}
                      | {"mitre_detail": [{"id": m, **cat[m]} for m in r.get("mitre", [])],
                         "remediation": {"id": r["remediation"], "title": rems[r["remediation"]]["title"]}}
                      for r in p.rules]}


# ------------------------------------------------------------------ analyses
@app.post("/api/analyses", status_code=202)
async def create_analysis(request: Request, bg: BackgroundTasks, pcap: UploadFile = File(...), keys: UploadFile | None = File(None),
                          s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> dict[str, Any]:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_UPLOAD + MAX_KEYS_UPLOAD + 65536:  # refuse before reading the body
        raise HTTPException(413, f"request exceeds the {MAX_UPLOAD // 2**20} MB upload limit (set MAX_UPLOAD_MB to change it)")
    head = await pcap.read(4)
    if head not in PCAP_MAGICS:
        raise HTTPException(400, "not a PCAP/PCAPNG file (bad magic bytes)")
    a = Analysis(filename=(pcap.filename or "upload.pcap")[:255], provenance="user-upload", has_keys=int(keys is not None),
                 owner_id=user.id if user else None)
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
                raise HTTPException(413, f"capture exceeds the {MAX_UPLOAD // 2**20} MB upload limit (set MAX_UPLOAD_MB to change it)")
            f.write(chunk)
    kp = None
    if keys is not None:
        kp = d / "keys.txt"
        blob = await keys.read(MAX_KEYS_UPLOAD + 1)
        if len(blob) > MAX_KEYS_UPLOAD:
            shutil.rmtree(d, ignore_errors=True)
            s.delete(a)
            s.commit()
            raise HTTPException(413, "key file larger than 1 MB; expected a Wireshark decryption table")
        kp.write_bytes(blob)
    bg.add_task(service.run_analysis, a.id, d / "capture.pcap", kp)
    return _analysis_dict(a)


@app.post("/api/logs", status_code=202)
async def create_log_analysis(request: Request, bg: BackgroundTasks, log: UploadFile = File(...), s: Session = Depends(db),
                              user: User | None = Depends(accounts.current_user)) -> dict[str, Any]:
    """Analyse a strongSwan daemon log (plain file, syslog or journald text) instead of a packet capture."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_UPLOAD + 65536:
        raise HTTPException(413, f"request exceeds the {MAX_UPLOAD // 2**20} MB upload limit (set MAX_UPLOAD_MB to change it)")
    head = await log.read(65536)
    if not looks_like_charon(head):
        raise HTTPException(400, "no strongSwan charon log lines found (expected lines like '12[IKE] ...'); only strongSwan logs are read")
    a = Analysis(filename=(log.filename or "charon.log")[:255], provenance="user-upload", has_keys=0, owner_id=user.id if user else None)
    s.add(a)
    s.commit()
    d = DATA_DIR / "uploads" / str(a.id)
    d.mkdir(parents=True, exist_ok=True)
    size = len(head)
    with open(d / "charon.log", "wb") as f:
        f.write(head)
        while chunk := await log.read(1 << 20):
            size += len(chunk)
            if size > MAX_UPLOAD:
                shutil.rmtree(d, ignore_errors=True)
                s.delete(a)
                s.commit()
                raise HTTPException(413, f"log exceeds the {MAX_UPLOAD // 2**20} MB upload limit (set MAX_UPLOAD_MB to change it)")
            f.write(chunk)
    bg.add_task(service.run_analysis, a.id, d / "charon.log", None, "log")
    return _analysis_dict(a)


@app.get("/api/ingest/status")
def ingest_status() -> dict[str, Any]:
    """What the watched folder and the syslog listener are doing (both are off unless configured by environment)."""
    return live.status()


@app.post("/api/samples/{name}/analyze", status_code=202)
def analyze_sample(name: str, bg: BackgroundTasks, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> dict[str, Any]:
    smp = _samples().get(name)
    if smp is None:
        raise HTTPException(404, "unknown sample")
    a = Analysis(filename=name, provenance=smp["provenance"], has_keys=int(smp["keys"] is not None), owner_id=user.id if user else None)
    s.add(a)
    s.commit()
    bg.add_task(service.run_analysis, a.id, smp["pcap"], smp["keys"], smp.get("input", "pcap"))
    return _analysis_dict(a)


@app.get("/api/analyses")
def list_analyses(s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> list[dict[str, Any]]:
    """Signed in: your saved analyses. Anonymous: the shared demo space."""
    where = Analysis.owner_id == user.id if user else Analysis.owner_id.is_(None)
    return [_analysis_dict(a) for a in s.scalars(select(Analysis).where(where).order_by(Analysis.id.desc()).limit(200 if user else 50))]


@app.get("/api/analyses/{aid}")
def get_analysis(aid: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> dict[str, Any]:
    return _analysis_dict(_get(s, aid, user))


@app.patch("/api/analyses/{aid}")
async def rename_analysis(aid: int, request: Request, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> dict[str, Any]:
    """Give a saved analysis your own name (e.g. "gateway-2 after the IKE hardening"). Owners only."""
    a = _get(s, aid, user)
    if a.owner_id is None:
        raise HTTPException(403, "sign in to save and name analyses")
    body = await request.json()
    label = str(body.get("label", "")).strip()[:120] if isinstance(body, dict) else ""
    a.label = label or None
    s.commit()
    return _analysis_dict(a)


@app.delete("/api/analyses/{aid}", status_code=204)
def delete_analysis(aid: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> Response:
    s.delete(_get(s, aid, user))
    s.commit()
    shutil.rmtree(DATA_DIR / "uploads" / str(aid), ignore_errors=True)
    return Response(status_code=204)


@app.get("/api/analyses/{aid}/tunnels")
def list_tunnels(aid: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> list[dict[str, Any]]:
    _done(s, aid, user)
    out = []
    for p in _tunnels(s, aid):
        t = p["tunnel"]
        out.append({"id": t["id"], "initiator": t["initiator"], "responder": t["responder"], "ike_version": t["ike_version"],
                    "exchange_mode": t["exchange_mode"], "status": t["status"], "chosen": t["chosen"], "decrypted": t["decrypted"],
                    "risk": p["risk"], "anomaly_score": (p["anomaly"] or {}).get("score"),
                    "violations": [{"rule_id": f["rule_id"], "severity": f["severity"], "mitre": [m["id"] for m in f["mitre"]]}
                                   for f in p["findings"] if f["category"] == "violation"],
                    "mitre": list({m["id"]: m for f in p["findings"] if f["category"] == "violation" for m in f["mitre"]}.values())})
    return out


@app.get("/api/analyses/{aid}/tunnels/{tid}")
def get_tunnel(aid: int, tid: str, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> dict[str, Any]:
    _done(s, aid, user)
    row = s.scalars(select(TunnelRow).where(TunnelRow.analysis_id == aid, TunnelRow.tunnel_id == tid)).first()
    if row is None:
        raise HTTPException(404, "tunnel not found")
    return row.payload


@app.get("/api/analyses/{aid}/remediation")
def remediation(aid: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> list[dict[str, Any]]:
    """Consolidated remediation plan: each remediation once, with the rules/tunnels that need it."""
    _done(s, aid, user)
    return remediation_plan(_tunnels(s, aid))


@app.get("/api/analyses/{aid}/report.pdf")
def report_pdf(aid: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> Response:
    a = _done(s, aid, user)
    pdf = build_pdf(_analysis_dict(a), _tunnels(s, aid))
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="ipsec-report-{aid}.pdf"'})


@app.get("/api/analyses/{aid}/report.html")
def report_html(aid: int, download: bool = False, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> Response:
    """Self-contained printable report. Opens in the browser by default; ?download=1 saves it as a file to share."""
    a = _done(s, aid, user)
    headers = {"Content-Disposition": f'attachment; filename="ipsec-report-{aid}.html"'} if download else {}
    headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'"
    return Response(build_html(_analysis_dict(a), _tunnels(s, aid)), media_type="text/html; charset=utf-8", headers=headers)


@app.get("/api/analyses/{aid}/export.json")
def export_json(aid: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> Response:
    a = _done(s, aid, user)
    return Response(json.dumps(to_json(_analysis_dict(a), _tunnels(s, aid)), indent=1), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="ipsec-analysis-{aid}.json"'})


@app.get("/api/analyses/{aid}/export.syslog")
def export_syslog(aid: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> Response:
    a = _done(s, aid, user)
    return Response(to_syslog(_analysis_dict(a), _tunnels(s, aid)), media_type="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="ipsec-analysis-{aid}.syslog"'})


@app.get("/api/compare")
def compare_analyses(before: int, after: int, s: Session = Depends(db), user: User | None = Depends(accounts.current_user)) -> dict[str, Any]:
    """Before/after diff of two finished analyses: risk change, rules fixed/new/remaining, tunnels matched by peer pair."""
    if before == after:
        raise HTTPException(400, "pick two different analyses")
    a, b = _done(s, before, user), _done(s, after, user)
    return {"before_analysis": _analysis_dict(a), "after_analysis": _analysis_dict(b), **compare(_tunnels(s, before), _tunnels(s, after))}


# Single-container deployments (root Dockerfile, render.yaml) serve the built UI from this process too. Mounted last so
# every /api route above takes precedence; the UI uses hash routing, so index.html is the only page it needs.
if os.environ.get("UI_DIR"):
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=os.environ["UI_DIR"], html=True), name="ui")
