"""Optional API-key auth (two roles, cookie login) and upload limits. Uses the bundled demo capture; SQLite, no mocks."""
import importlib
import os
import secrets
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "data/captures/synthetic/demo_gateway_audit.pcap"
pytestmark = pytest.mark.skipif(not DEMO.exists(), reason="bundled demo capture missing")

# Keys are generated per run so no credential-looking literal sits in the repo (secret scanners flag those).
KEY = secrets.token_urlsafe(16)
RO_KEY = secrets.token_urlsafe(16)


@pytest.fixture()
def make_client(tmp_path, monkeypatch):
    clients = []

    def make(**env):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
        for k in ("API_KEY", "READONLY_API_KEY", "MAX_UPLOAD_MB"):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from ipsec_analyzer.api import auth, db, main
        importlib.reload(db)
        importlib.reload(main)
        auth.throttle.reset()
        c = TestClient(main.app)
        c.__enter__()
        clients.append(c)
        return c

    yield make
    for c in clients:
        c.__exit__(None, None, None)


def test_open_by_default(make_client):
    c = make_client()
    assert c.get("/api/analyses").status_code == 200
    assert c.get("/api/auth").json() == {"required": False, "authenticated": True, "role": "admin"}


def test_key_required_when_configured_but_health_stays_open(make_client):
    c = make_client(API_KEY=KEY)
    assert c.get("/api/health").status_code == 200  # docker healthcheck must keep working
    assert c.get("/api/analyses").status_code == 401
    assert c.get("/api/analyses", headers={"X-API-Key": "not-" + KEY}).status_code == 401
    assert c.get("/api/analyses", headers={"X-API-Key": KEY}).status_code == 200
    assert c.get("/api/analyses", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200
    assert c.get("/api/auth").json() == {"required": True, "authenticated": False, "role": None}


def test_cookie_login_unlocks_downloads_and_logout_locks_again(make_client):
    c = make_client(API_KEY=KEY)
    r = c.post("/api/login", json={"key": KEY})
    assert r.status_code == 200 and r.json()["role"] == "admin"
    assert "httponly" in r.headers["set-cookie"].lower() and "samesite=strict" in r.headers["set-cookie"].lower()
    assert c.get("/api/analyses").status_code == 200  # cookie jar carries the session
    assert c.get("/api/auth").json()["authenticated"] is True
    c.post("/api/logout")
    assert c.get("/api/analyses").status_code == 401


def test_readonly_key_reads_but_cannot_upload_or_delete(make_client):
    c = make_client(API_KEY=KEY, READONLY_API_KEY=RO_KEY)
    ro = {"X-API-Key": RO_KEY}
    assert c.get("/api/analyses", headers=ro).status_code == 200
    r = c.post("/api/samples/demo_gateway_audit/analyze", headers=ro)
    assert r.status_code == 403 and "read-only" in r.json()["detail"]
    assert c.delete("/api/analyses/1", headers=ro).status_code == 403
    assert c.delete("/api/analyses/1", headers={"X-API-Key": KEY}).status_code == 404  # allowed, just not found


def test_repeated_bad_logins_are_throttled(make_client):
    c = make_client(API_KEY=KEY)
    codes = [c.post("/api/login", json={"key": f"bad{i}"}).status_code for i in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    assert c.post("/api/login", json={"key": KEY}).status_code == 429  # even the right key waits out the window


def test_upload_over_the_configured_limit_is_rejected_and_cleaned_up(make_client, tmp_path):
    c = make_client(MAX_UPLOAD_MB="1")
    big = DEMO.read_bytes()[:4] + b"\x00" * (2 * 1024 * 1024)
    r = c.post("/api/analyses", files={"pcap": ("big.pcap", big)})
    assert r.status_code == 413 and "MAX_UPLOAD_MB" in r.json()["detail"]
    assert c.get("/api/analyses").json() == []
    assert not any((tmp_path / "uploads").glob("*")) if (tmp_path / "uploads").exists() else True


def test_oversized_key_file_is_rejected(make_client):
    c = make_client()
    r = c.post("/api/analyses", files={"pcap": ("d.pcap", DEMO.read_bytes()), "keys": ("k.txt", b"a" * (1024 * 1024 + 10))})
    assert r.status_code == 413 and "key file" in r.json()["detail"]
    assert c.get("/api/analyses").json() == []
