"""High-risk alerts: email and/or signed webhook when a signed-in user's analysis finishes with a risky tunnel.

Each user chooses a risk threshold and channels (default threshold 33 = the policy's "high" band). Delivery runs in the
analysis worker thread after the results are saved and can never fail an analysis; every attempt is logged (`alert_events`)
so the user can see what was sent or why it was not.

- Email: SMTP from the environment (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_SECURITY`
  = starttls | ssl | none). Without `SMTP_HOST` the email channel is reported as unavailable in the UI.
- Webhook: JSON POST (`text`/`content` fields make it work as-is with Slack/Teams/Discord incoming webhooks) signed with a
  per-user secret: `X-Signature: sha256=<hex hmac of the raw body>`. Redirects are not followed, the target must be http(s),
  and its host must resolve only to public addresses (the connection is pinned to the checked address, so DNS cannot
  switch it afterwards) unless `ALERTS_ALLOW_PRIVATE=1` (lab/intranet receivers and tests).
- A webhook URL may embed a token, so the API only ever returns it masked.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import secrets
import smtplib
import socket
import ssl
import traceback
from email.message import EmailMessage
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import accounts
from . import db as dbm

router = APIRouter()
TIMEOUT_S = 8
DEFAULT_MIN_RISK = 33.0
MAX_BODY_FINDINGS = 5


# ------------------------------------------------------------------ transport safety
def _allow_private() -> bool:
    return os.environ.get("ALERTS_ALLOW_PRIVATE", "0").lower() in ("1", "true", "yes")


def _public(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_webhook_url(url: str) -> tuple[str, str, int, str, str]:
    """Returns (scheme, host, port, path, pinned_ip) or raises ValueError with a user-readable reason."""
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("webhook URL must start with http:// or https://")
    if u.username or u.password:
        raise ValueError("put credentials in the URL path or a header-less token, not user:password@")
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError(f"cannot resolve {u.hostname}") from None
    addrs = [ipaddress.ip_address(i[4][0]) for i in infos]
    if not _allow_private() and not all(_public(a) for a in addrs):
        raise ValueError("webhook host resolves to a private or internal address (blocked; set ALERTS_ALLOW_PRIVATE=1 to allow)")
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return u.scheme, u.hostname, port, path, str(addrs[0])


class _Pinned(http.client.HTTPConnection):
    """Connects to an address we already vetted instead of resolving the name again."""

    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedTLS(_Pinned):
    def connect(self) -> None:
        super().connect()
        self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)


def mask_url(url: str | None) -> str | None:
    if not url:
        return None
    u = urlsplit(url)
    return f"{u.scheme}://{u.netloc}/…" if (u.path.strip("/") or u.query) else f"{u.scheme}://{u.netloc}"


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def send_webhook(url: str, secret: str, payload: dict[str, Any]) -> str:
    scheme, host, port, path, ip = validate_webhook_url(url)
    body = json.dumps(payload, separators=(",", ":")).encode()
    conn = (_PinnedTLS if scheme == "https" else _Pinned)(host, port, ip, TIMEOUT_S)
    try:
        conn.request("POST", path, body, {"Content-Type": "application/json", "User-Agent": "ipsec-analyzer-alerts/1",
                                          "X-Signature": sign(secret, body), "Host": host if port in (80, 443) else f"{host}:{port}"})
        r = conn.getresponse()
        r.read(2048)
        if not 200 <= r.status < 300:
            raise RuntimeError(f"receiver answered HTTP {r.status}")
        return f"HTTP {r.status}"
    finally:
        conn.close()


def smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST"))


def send_email(to: str, subject: str, text: str) -> str:
    host = os.environ["SMTP_HOST"]
    sec = os.environ.get("SMTP_SECURITY", "starttls").lower()
    port = int(os.environ.get("SMTP_PORT", "465" if sec == "ssl" else "587" if sec == "starttls" else "25"))
    msg = EmailMessage()
    msg["From"] = os.environ.get("SMTP_FROM") or os.environ.get("SMTP_USER") or "ipsec-analyzer@localhost"
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text)
    ctx = ssl.create_default_context()
    smtp = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT_S, context=ctx) if sec == "ssl" else smtplib.SMTP(host, port, timeout=TIMEOUT_S)
    with smtp:
        if sec == "starttls":
            smtp.starttls(context=ctx)
        if os.environ.get("SMTP_USER"):
            smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
        smtp.send_message(msg)
    return f"accepted by {host}"


# ------------------------------------------------------------------ message content
def _level(score: float) -> str:
    return "critical" if score >= 55 else "high" if score >= 33 else "medium"


def build_alert(analysis: dict[str, Any], risky: list[dict[str, Any]], min_risk: float, test: bool = False) -> dict[str, Any]:
    base = (os.environ.get("PUBLIC_URL") or "").rstrip("/")
    top = risky[0]["risk"]["score"] if risky else 0
    tunnels = []
    for p in risky[:10]:
        viol = [f for f in p["findings"] if f["category"] == "violation"]
        tunnels.append({"id": p["tunnel"]["id"], "initiator": p["tunnel"]["initiator"], "responder": p["tunnel"]["responder"],
                        "risk": p["risk"]["score"], "band": p["risk"]["band"],
                        "findings": [{"rule_id": f["rule_id"], "severity": f["severity"], "title": f["title"]} for f in viol[:MAX_BODY_FINDINGS]]})
    name = analysis.get("label") or analysis["filename"]
    head = f"{len(risky)} tunnel{'s' if len(risky) != 1 else ''} at risk {min_risk:g}+ in \"{name}\" (highest {top:g}, {_level(top)})"
    lines = [("[TEST] " if test else "") + head]
    for t in tunnels:
        lines.append(f"- {t['initiator']} -> {t['responder']}: risk {t['risk']:g} ({t['band']}); "
                     + (", ".join(f"{f['rule_id']} ({f['severity']})" for f in t["findings"]) or "behavioural anomaly"))
    link = f"{base}/#/a/{analysis['id']}" if base and analysis.get("id") else None
    if link:
        lines.append(link)
    text = "\n".join(lines)
    return {"event": "ipsec_analyzer.high_risk_tunnel" if not test else "ipsec_analyzer.test", "test": test,
            "analysis": {"id": analysis.get("id"), "name": name, "provenance": analysis.get("provenance"), "url": link},
            "threshold": min_risk, "highest_risk": top, "tunnel_count": len(risky), "tunnels": tunnels,
            "text": text, "content": text}


def sample_alert(min_risk: float) -> dict[str, Any]:
    fake = [{"tunnel": {"id": "example", "initiator": "198.51.100.10", "responder": "203.0.113.5"}, "risk": {"score": 72.0, "band": "critical"},
             "findings": [{"category": "violation", "rule_id": "EXAMPLE-WEAK-DH", "severity": "high", "title": "Example finding (this is only a test)"}]}]
    return build_alert({"id": None, "filename": "test-alert", "provenance": "synthetic", "label": None}, fake, min_risk, test=True)


# ------------------------------------------------------------------ delivery
def _log(s: Session, uid: int, aid: int | None, channel: str, ok: bool, detail: str, n: int, top: float | None) -> dict[str, Any]:
    ev = dbm.AlertEvent(user_id=uid, analysis_id=aid, channel=channel, status="sent" if ok else "failed", detail=detail[:500], tunnels=n, top_risk=top)
    s.add(ev)
    s.commit()
    return _event(ev)


def _deliver(s: Session, cfg: dbm.AlertSettings, payload: dict[str, Any], aid: int | None) -> list[dict[str, Any]]:
    out = []
    n, top = payload["tunnel_count"], payload["highest_risk"]
    if cfg.email_enabled and cfg.email_to:
        try:
            if not smtp_configured():
                raise RuntimeError("this server has no SMTP configured (SMTP_HOST)")
            subject = f"{'[TEST] ' if payload['test'] else ''}IPsec analyzer: {n} high-risk tunnel{'s' if n != 1 else ''} (highest {top:g})"
            out.append(_log(s, cfg.user_id, aid, "email", True, send_email(cfg.email_to, subject, payload["text"]), n, top))
        except Exception as e:  # noqa: BLE001 - a broken channel is a log line, never an exception to the caller
            out.append(_log(s, cfg.user_id, aid, "email", False, f"{type(e).__name__}: {e}", n, top))
    if cfg.webhook_enabled and cfg.webhook_url:
        try:
            out.append(_log(s, cfg.user_id, aid, "webhook", True, send_webhook(cfg.webhook_url, cfg.webhook_secret, payload), n, top))
        except Exception as e:  # noqa: BLE001
            out.append(_log(s, cfg.user_id, aid, "webhook", False, f"{type(e).__name__}: {e}", n, top))
    return out


def notify_if_risky(analysis_id: int) -> None:
    """Called by the analysis worker once results are stored. Silent no-op for anonymous analyses or users without alerts."""
    try:
        with dbm.SessionLocal() as s:
            a = s.get(dbm.Analysis, analysis_id)
            if a is None or a.owner_id is None or a.status != "done":
                return
            cfg = s.get(dbm.AlertSettings, a.owner_id)
            if cfg is None or not cfg.enabled:
                return
            rows = s.scalars(select(dbm.TunnelRow).where(dbm.TunnelRow.analysis_id == analysis_id, dbm.TunnelRow.risk >= cfg.min_risk)
                             .order_by(dbm.TunnelRow.risk.desc())).all()
            if not rows:
                return
            info = {"id": a.id, "filename": a.filename, "provenance": a.provenance, "label": a.label}
            _deliver(s, cfg, build_alert(info, [r.payload for r in rows], cfg.min_risk), a.id)
    except Exception:  # noqa: BLE001
        traceback.print_exc()


# ------------------------------------------------------------------ API
def _event(e: dbm.AlertEvent) -> dict[str, Any]:
    return {"id": e.id, "analysis_id": e.analysis_id, "channel": e.channel, "status": e.status, "detail": e.detail, "tunnels": e.tunnels,
            "top_risk": e.top_risk, "test": e.analysis_id is None, "created_at": e.created_at.isoformat()}


def _view(cfg: dbm.AlertSettings | None, user: dbm.User) -> dict[str, Any]:
    cfg = cfg or dbm.AlertSettings(user_id=user.id, enabled=False, min_risk=DEFAULT_MIN_RISK, email_enabled=False, webhook_enabled=False, webhook_secret="")
    return {"enabled": cfg.enabled, "min_risk": cfg.min_risk, "email_enabled": cfg.email_enabled, "email_to": cfg.email_to or user.email,
            "webhook_enabled": cfg.webhook_enabled, "webhook_url": mask_url(cfg.webhook_url), "webhook_secret": cfg.webhook_secret or None,
            "smtp_available": smtp_configured(), "allow_private": _allow_private()}


@router.get("/api/alerts")
def get_settings(user: dbm.User = Depends(accounts.require_user), s: Session = Depends(accounts.get_session)) -> dict[str, Any]:
    return {"settings": _view(s.get(dbm.AlertSettings, user.id), user),
            "events": [_event(e) for e in s.scalars(select(dbm.AlertEvent).where(dbm.AlertEvent.user_id == user.id)
                                                     .order_by(dbm.AlertEvent.id.desc()).limit(30))]}


@router.put("/api/alerts")
async def put_settings(request: Request, user: dbm.User = Depends(accounts.require_user), s: Session = Depends(accounts.get_session)) -> dict[str, Any]:
    """Partial update. `webhook_url`: a string sets it, "" clears it, absent keeps it. `rotate_secret: true` issues a new signing secret."""
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "expected a JSON object")
    cfg = s.get(dbm.AlertSettings, user.id)
    if cfg is None:
        cfg = dbm.AlertSettings(user_id=user.id, enabled=False, min_risk=DEFAULT_MIN_RISK, email_enabled=False, webhook_enabled=False,
                                webhook_secret=secrets.token_hex(24))
        s.add(cfg)
    if "min_risk" in body:
        try:
            mr = float(body["min_risk"])
        except (TypeError, ValueError):
            raise HTTPException(422, "min_risk must be a number 1-100") from None
        if not 1 <= mr <= 100:
            raise HTTPException(422, "min_risk must be between 1 and 100")
        cfg.min_risk = mr
    for k in ("enabled", "email_enabled", "webhook_enabled"):
        if k in body:
            if not isinstance(body[k], bool):
                raise HTTPException(422, f"{k} must be true or false")
            setattr(cfg, k, body[k])
    if "email_to" in body:
        to = str(body["email_to"] or "").strip().lower()
        if to and not accounts._EMAIL.match(to):
            raise HTTPException(422, "enter a valid email address")
        cfg.email_to = to or None
    if "webhook_url" in body:
        url = str(body["webhook_url"] or "").strip()
        if url:
            if len(url) > 1000:
                raise HTTPException(422, "webhook URL is too long")
            try:
                validate_webhook_url(url)
            except ValueError as e:
                raise HTTPException(422, str(e)) from None
        cfg.webhook_url = url or None
    if body.get("rotate_secret") is True:
        cfg.webhook_secret = secrets.token_hex(24)
    if cfg.webhook_enabled and not cfg.webhook_url:
        raise HTTPException(422, "add a webhook URL before turning the webhook on")
    if cfg.email_enabled and not (cfg.email_to or user.email):
        raise HTTPException(422, "add an email address before turning email on")
    if cfg.email_enabled and not cfg.email_to:
        cfg.email_to = user.email
    s.commit()
    return _view(cfg, user)


@router.post("/api/alerts/test")
def send_test(user: dbm.User = Depends(accounts.require_user), s: Session = Depends(accounts.get_session)) -> dict[str, Any]:
    """Sends a clearly labelled test message through the enabled channels and reports each result."""
    cfg = s.get(dbm.AlertSettings, user.id)
    if cfg is None or not (cfg.email_enabled or cfg.webhook_enabled):
        raise HTTPException(409, "turn on email or a webhook first")
    return {"results": _deliver(s, cfg, sample_alert(cfg.min_risk), None)}
