"""Alerts: webhook (real local receiver, signature checked), email (real in-process SMTP server), thresholds, SSRF guard, privacy."""
import hashlib
import hmac
import importlib
import json
import secrets
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "data/captures/synthetic/demo_gateway_audit.pcap"
pytestmark = pytest.mark.skipif(not DEMO.exists(), reason="bundled demo capture missing")
PW = secrets.token_urlsafe(14)


class Receiver:
    """Local HTTP endpoint that records every POST; `status` controls the answer."""

    def __init__(self):
        self.got: list[tuple[dict, bytes]] = []
        self.status = 200
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("content-length", 0))
                outer.got.append((dict(self.headers), self.rfile.read(n)))
                self.send_response(outer.status)
                self.end_headers()

            def log_message(self, *a):
                pass
        self.srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_port}/hook/abc123"

    def close(self):
        self.srv.shutdown()


class FakeSMTP:
    """Minimal SMTP server (no auth/TLS) that keeps the messages it accepts."""

    def __init__(self):
        self.messages: list[str] = []
        outer = self

        class H(socketserver.StreamRequestHandler):
            def handle(self):
                w = lambda t: self.wfile.write((t + "\r\n").encode())  # noqa: E731
                w("220 fake ESMTP")
                data = False
                buf: list[str] = []
                while line := self.rfile.readline():
                    t = line.decode().rstrip("\r\n")
                    if data:
                        if t == ".":
                            outer.messages.append("\n".join(buf))
                            data, buf = False, []
                            w("250 queued")
                        else:
                            buf.append(t)
                    elif t.upper().startswith("EHLO") or t.upper().startswith("HELO"):
                        w("250 fake")
                    elif t.upper() == "DATA":
                        data = True
                        w("354 go")
                    elif t.upper() == "QUIT":
                        w("221 bye")
                        return
                    else:
                        w("250 ok")
        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    rcv, smtp = Receiver(), FakeSMTP()
    clients = []

    def make(**extra):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
        monkeypatch.setenv("ALERTS_ALLOW_PRIVATE", "1")
        monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SMTP_PORT", str(smtp.port))
        monkeypatch.setenv("SMTP_SECURITY", "none")
        monkeypatch.setenv("SMTP_FROM", "alerts@example.test")
        monkeypatch.setenv("PUBLIC_URL", "https://analyzer.example.test")
        for k in ("API_KEY", "READONLY_API_KEY", "ALLOW_REGISTRATION"):
            monkeypatch.delenv(k, raising=False)
        for k, v in extra.items():
            monkeypatch.setenv(k, v) if v is not None else monkeypatch.delenv(k, raising=False)
        from ipsec_analyzer.api import accounts, db, main
        importlib.reload(db)
        importlib.reload(main)
        accounts.login_throttle.reset()
        accounts.register_throttle.reset()

        def client(email="a@example.com"):
            c = TestClient(main.app)
            c.__enter__()
            clients.append(c)
            c.post("/api/account/register", json={"email": email, "password": PW})
            return c
        return client

    yield make, rcv, smtp
    for c in clients:
        c.__exit__(None, None, None)
    rcv.close()
    smtp.close()


def _analyze(c, label=None):
    r = c.post("/api/analyses", files={"pcap": ("demo.pcap", DEMO.read_bytes()), "keys": ("k.txt", DEMO.with_suffix(".keys").read_bytes())})
    aid = r.json()["id"]
    for _ in range(120):
        a = c.get(f"/api/analyses/{aid}").json()
        if a["status"] == "done":
            return a
        assert a["status"] != "failed", a
        time.sleep(0.25)
    raise AssertionError("timeout")


def _events(c, n=1, wait=10):
    for _ in range(int(wait * 4)):
        ev = c.get("/api/alerts").json()["events"]
        if len(ev) >= n:
            return ev
        time.sleep(0.25)
    return c.get("/api/alerts").json()["events"]


def test_settings_default_off_and_require_login(env):
    make, *_ = env
    client = make()
    c = client()
    s = c.get("/api/alerts").json()["settings"]
    assert s["enabled"] is False and s["min_risk"] == 33 and s["email_to"] == "a@example.com" and s["webhook_url"] is None and s["smtp_available"]
    anon = TestClient(__import__("ipsec_analyzer.api.main", fromlist=["app"]).app)
    assert anon.get("/api/alerts").status_code == 401
    assert anon.post("/api/alerts/test").status_code == 401


def test_settings_validation(env):
    make, rcv, _ = env
    c = make()()
    assert c.put("/api/alerts", json={"min_risk": 0}).status_code == 422
    assert c.put("/api/alerts", json={"min_risk": "high"}).status_code == 422
    assert c.put("/api/alerts", json={"enabled": "yes"}).status_code == 422
    assert c.put("/api/alerts", json={"email_to": "nope"}).status_code == 422
    assert c.put("/api/alerts", json={"webhook_url": "ftp://x/y"}).status_code == 422
    assert c.put("/api/alerts", json={"webhook_enabled": True}).status_code == 422  # no URL yet
    assert c.post("/api/alerts/test").status_code == 409  # nothing switched on
    r = c.put("/api/alerts", json={"webhook_url": rcv.url, "webhook_enabled": True, "min_risk": 40.5})
    assert r.status_code == 200 and r.json()["min_risk"] == 40.5


def test_webhook_url_is_never_returned_in_full_and_secret_rotates(env):
    make, rcv, _ = env
    c = make()()
    s = c.put("/api/alerts", json={"webhook_url": rcv.url}).json()
    assert "abc123" not in json.dumps(s) and s["webhook_url"].endswith("/…")
    old = s["webhook_secret"]
    assert len(old) == 48
    assert c.put("/api/alerts", json={"rotate_secret": True}).json()["webhook_secret"] != old
    assert c.put("/api/alerts", json={"webhook_url": ""}).json()["webhook_url"] is None


def test_high_risk_analysis_sends_signed_webhook_and_email(env):
    make, rcv, smtp = env
    c = make()()
    s = c.put("/api/alerts", json={"enabled": True, "webhook_enabled": True, "webhook_url": rcv.url, "email_enabled": True}).json()
    _analyze(c)
    ev = _events(c, 2)
    assert {e["channel"] for e in ev} == {"email", "webhook"} and all(e["status"] == "sent" for e in ev), ev
    headers, body = rcv.got[0]
    assert headers["X-Signature"] == "sha256=" + hmac.new(s["webhook_secret"].encode(), body, hashlib.sha256).hexdigest()
    p = json.loads(body)
    assert p["event"] == "ipsec_analyzer.high_risk_tunnel" and p["test"] is False and p["tunnel_count"] >= 1
    assert p["highest_risk"] >= 33 and all(t["risk"] >= 33 for t in p["tunnels"]) and p["tunnels"][0]["findings"]
    assert p["analysis"]["url"].startswith("https://analyzer.example.test/#/a/") and p["text"] == p["content"]
    assert smtp.messages and "high-risk" in smtp.messages[0] and "To: a@example.com" in smtp.messages[0]


def test_threshold_above_every_tunnel_sends_nothing(env):
    make, rcv, smtp = env
    c = make()()
    c.put("/api/alerts", json={"enabled": True, "webhook_enabled": True, "webhook_url": rcv.url, "min_risk": 100})
    _analyze(c)
    time.sleep(1)
    assert rcv.got == [] and c.get("/api/alerts").json()["events"] == []


def test_master_switch_off_and_anonymous_analyses_never_alert(env):
    make, rcv, _ = env
    client = make()
    c = client()
    c.put("/api/alerts", json={"webhook_enabled": True, "webhook_url": rcv.url, "enabled": False})
    _analyze(c)
    anon = TestClient(__import__("ipsec_analyzer.api.main", fromlist=["app"]).app)
    anon.post("/api/analyses", files={"pcap": ("d.pcap", DEMO.read_bytes())})
    time.sleep(3)
    assert rcv.got == []


def test_alerts_go_only_to_the_analysis_owner(env):
    make, rcv, _ = env
    client = make()
    alice, bob = client("alice@example.com"), client("bob@example.com")
    alice.put("/api/alerts", json={"enabled": True, "webhook_enabled": True, "webhook_url": rcv.url})
    _analyze(bob)  # bob's analysis must not trigger alice's webhook
    time.sleep(2)
    assert rcv.got == [] and alice.get("/api/alerts").json()["events"] == [] and bob.get("/api/alerts").json()["events"] == []


def test_failing_receiver_is_logged_and_does_not_break_the_analysis(env):
    make, rcv, _ = env
    rcv.status = 500
    c = make()()
    c.put("/api/alerts", json={"enabled": True, "webhook_enabled": True, "webhook_url": rcv.url})
    a = _analyze(c)
    assert a["status"] == "done"
    ev = _events(c)
    assert ev[0]["status"] == "failed" and "HTTP 500" in ev[0]["detail"]


def test_test_button_sends_labelled_message_through_enabled_channels(env):
    make, rcv, smtp = env
    c = make()()
    c.put("/api/alerts", json={"webhook_enabled": True, "webhook_url": rcv.url, "email_enabled": True, "email_to": "ops@example.com"})
    res = c.post("/api/alerts/test").json()["results"]
    assert sorted(r["channel"] for r in res) == ["email", "webhook"] and all(r["status"] == "sent" and r["test"] for r in res)
    assert json.loads(rcv.got[0][1])["test"] is True
    assert "[TEST]" in smtp.messages[0] and "To: ops@example.com" in smtp.messages[0]


def test_email_without_smtp_is_reported_not_raised(env):
    make, *_ = env
    c = make(SMTP_HOST=None)()
    assert c.get("/api/alerts").json()["settings"]["smtp_available"] is False
    c.put("/api/alerts", json={"email_enabled": True})
    r = c.post("/api/alerts/test").json()["results"][0]
    assert r["status"] == "failed" and "SMTP" in r["detail"]


def test_private_webhook_targets_are_blocked_by_default(env):
    make, rcv, _ = env
    c = make(ALERTS_ALLOW_PRIVATE="0")()
    for url in (rcv.url, "http://169.254.169.254/latest/meta-data", "http://localhost:8080/x", "http://[::1]/x", "http://10.0.0.5/x"):
        r = c.put("/api/alerts", json={"webhook_url": url})
        assert r.status_code == 422 and "private" in r.json()["detail"], url
    assert c.put("/api/alerts", json={"webhook_url": "http://user:pw@example.com/x"}).status_code == 422


def test_pinned_connection_rejects_a_host_that_turns_private_after_saving(env, monkeypatch):
    make, rcv, _ = env
    c = make()()
    c.put("/api/alerts", json={"webhook_url": rcv.url, "webhook_enabled": True})  # allowed while ALERTS_ALLOW_PRIVATE=1
    monkeypatch.setenv("ALERTS_ALLOW_PRIVATE", "0")  # re-checked at send time, not only at save time
    r = c.post("/api/alerts/test").json()["results"][0]
    assert r["status"] == "failed" and "private" in r["detail"] and rcv.got == []


def test_account_deletion_removes_alert_data(env):
    make, rcv, _ = env
    c = make()()
    c.put("/api/alerts", json={"webhook_url": rcv.url, "webhook_enabled": True})
    c.post("/api/alerts/test")
    assert c.request("DELETE", "/api/account", json={"password": PW}).status_code == 204
    import sqlite3
    from ipsec_analyzer.api import db
    con = sqlite3.connect(str(db.engine.url.database))
    assert con.execute("select count(*) from alert_settings").fetchone()[0] == 0 and con.execute("select count(*) from alert_events").fetchone()[0] == 0
