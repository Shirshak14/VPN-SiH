"""User accounts and saved analyses: auth, ownership isolation, persistence across sessions. Real app, SQLite, no mocks."""
import importlib
import secrets
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
DEMO = ROOT / "data/captures/synthetic/demo_gateway_audit.pcap"
pytestmark = pytest.mark.skipif(not DEMO.exists(), reason="bundled demo capture missing")

# Generated per run: no credential-looking literals in the repo.
PW = secrets.token_urlsafe(14)
PW2 = secrets.token_urlsafe(14)


@pytest.fixture()
def make_app(tmp_path, monkeypatch):
    made = []

    def make(**env):
        monkeypatch.setenv("DATA_DIR", str(tmp_path))
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
        for k in ("API_KEY", "READONLY_API_KEY", "ALLOW_REGISTRATION"):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from ipsec_analyzer.api import accounts, auth, db, main
        importlib.reload(db)
        importlib.reload(main)
        auth.throttle.reset()
        accounts.login_throttle.reset()
        accounts.register_throttle.reset()

        def client():
            c = TestClient(main.app)
            c.__enter__()
            made.append(c)
            return c
        return client

    yield make
    for c in made:
        c.__exit__(None, None, None)


def _register(c, email="a@example.com", pw=PW):
    return c.post("/api/account/register", json={"email": email, "password": pw})


def _analyze(c):
    r = c.post("/api/analyses", files={"pcap": ("demo.pcap", DEMO.read_bytes()), "keys": ("k.txt", DEMO.with_suffix(".keys").read_bytes())})
    assert r.status_code == 202
    aid = r.json()["id"]
    for _ in range(120):
        a = c.get(f"/api/analyses/{aid}").json()
        if a["status"] in ("done", "failed"):
            assert a["status"] == "done", a
            return a
        time.sleep(0.25)
    raise AssertionError("timeout")


def test_register_login_logout_roundtrip(make_app):
    c = make_app()()
    assert c.get("/api/account").json() == {"registration_open": True, "user": None}
    r = _register(c, "  Alice@Example.COM ")
    assert r.status_code == 201 and r.json()["user"]["email"] == "alice@example.com"
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert c.get("/api/account").json()["user"]["email"] == "alice@example.com"
    c.post("/api/account/logout")
    assert c.get("/api/account").json()["user"] is None
    assert c.post("/api/account/login", json={"email": "alice@example.com", "password": PW}).status_code == 200
    assert c.get("/api/account").json()["user"] is not None


def test_validation_and_duplicates(make_app):
    c = make_app()()
    assert _register(c, "not-an-email").status_code == 422
    assert _register(c, pw="short").status_code == 422
    assert _register(c, pw="x" * 300).status_code == 422
    assert _register(c).status_code == 201
    assert _register(c, "A@example.com").status_code == 409  # case-insensitive
    from ipsec_analyzer.api import accounts
    accounts.register_throttle.reset()
    assert c.post("/api/account/register", content=b"[]", headers={"content-type": "application/json"}).status_code == 400


def test_password_is_hashed_and_session_token_is_not_stored(make_app, tmp_path):
    c = make_app()()
    r = _register(c)
    token = c.cookies.get("ipsec_user")
    import sqlite3
    con = sqlite3.connect(tmp_path / "t.db")
    (h,) = con.execute("select password_hash from users").fetchone()
    stored = [t for (t,) in con.execute("select token_hash from user_sessions")]
    assert h.startswith("scrypt$") and PW not in h
    assert stored and token not in stored and r.status_code == 201


def test_wrong_password_unknown_user_and_throttle(make_app):
    c = make_app()()
    _register(c)
    c.post("/api/account/logout")
    bad = c.post("/api/account/login", json={"email": "a@example.com", "password": "nope-nope-nope"})
    unk = c.post("/api/account/login", json={"email": "ghost@example.com", "password": "nope-nope-nope"})
    assert bad.status_code == unk.status_code == 401 and bad.json() == unk.json()  # no account enumeration
    for _ in range(4):
        c.post("/api/account/login", json={"email": "a@example.com", "password": "nope-nope-nope"})
    assert c.post("/api/account/login", json={"email": "a@example.com", "password": PW}).status_code == 429


def test_registration_can_be_closed(make_app):
    c = make_app(ALLOW_REGISTRATION="0")()
    assert c.get("/api/account").json()["registration_open"] is False
    assert _register(c).status_code == 403


def test_analyses_are_private_to_their_owner_and_anonymous_stays_open(make_app):
    client = make_app()
    anon, alice, bob = client(), client(), client()
    _register(alice, "alice@example.com")
    _register(bob, "bob@example.com")
    mine = _analyze(alice)
    assert mine["private"] is True and mine["provenance"] == "user-upload"
    shared = _analyze(anon)
    assert shared["private"] is False

    assert [a["id"] for a in alice.get("/api/analyses").json()] == [mine["id"]]
    assert [a["id"] for a in anon.get("/api/analyses").json()] == [shared["id"]]
    assert bob.get("/api/analyses").json() == []
    for who in (anon, bob):  # every per-analysis route hides it with a 404
        for path in ("", "/tunnels", "/remediation", "/report.pdf", "/export.json", "/export.syslog"):
            assert who.get(f"/api/analyses/{mine['id']}{path}").status_code == 404, path
        assert who.delete(f"/api/analyses/{mine['id']}").status_code == 404
        assert who.patch(f"/api/analyses/{mine['id']}", json={"label": "x"}).status_code == 404
        assert who.get(f"/api/compare?before={mine['id']}&after={shared['id']}").status_code == 404
    assert alice.get(f"/api/analyses/{mine['id']}/tunnels").status_code == 200
    assert alice.get(f"/api/compare?before={mine['id']}&after={shared['id']}").status_code == 200  # owner may compare with demo data


def test_history_persists_across_sessions_and_can_be_named(make_app):
    client = make_app()
    c = client()
    _register(c)
    a = _analyze(c)
    r = c.patch(f"/api/analyses/{a['id']}", json={"label": "  gateway before hardening  "})
    assert r.json()["label"] == "gateway before hardening"
    c.post("/api/account/logout")
    assert c.get("/api/analyses").json() != [a]  # signed out: demo space only
    other = client()  # a brand-new browser
    assert other.post("/api/account/login", json={"email": "a@example.com", "password": PW}).status_code == 200
    got = other.get("/api/analyses").json()
    assert [x["id"] for x in got] == [a["id"]] and got[0]["label"] == "gateway before hardening"
    assert other.patch(f"/api/analyses/{a['id']}", json={"label": ""}).json()["label"] is None


def test_anonymous_cannot_name_demo_analyses(make_app):
    c = make_app()()
    a = _analyze(c)
    assert c.patch(f"/api/analyses/{a['id']}", json={"label": "x"}).status_code == 403


def test_change_password_signs_out_other_browsers(make_app):
    client = make_app()
    one, two = client(), client()
    _register(one)
    two.post("/api/account/login", json={"email": "a@example.com", "password": PW})
    assert one.post("/api/account/password", json={"current": "wrong-wrong-1", "new": PW2}).status_code == 403
    assert one.post("/api/account/password", json={"current": PW, "new": "short"}).status_code == 422
    assert one.post("/api/account/password", json={"current": PW, "new": PW2}).status_code == 200
    assert one.get("/api/account").json()["user"] is not None
    assert two.get("/api/account").json()["user"] is None
    one.post("/api/account/logout")
    assert one.post("/api/account/login", json={"email": "a@example.com", "password": PW}).status_code == 401
    assert one.post("/api/account/login", json={"email": "a@example.com", "password": PW2}).status_code == 200


def test_delete_account_erases_everything(make_app, tmp_path):
    client = make_app()
    c, anon = client(), client()
    _register(c)
    a = _analyze(c)
    assert c.request("DELETE", "/api/account", json={"password": "wrong-wrong-1"}).status_code == 403
    assert c.request("DELETE", "/api/account", json={"password": PW}).status_code == 204
    assert c.get("/api/account").json()["user"] is None
    assert anon.get(f"/api/analyses/{a['id']}").status_code == 404
    assert c.post("/api/account/login", json={"email": "a@example.com", "password": PW}).status_code == 401


def test_old_database_without_owner_columns_is_migrated(tmp_path, monkeypatch):
    import sqlite3
    con = sqlite3.connect(tmp_path / "t.db")
    con.execute("create table analyses (id integer primary key, filename varchar(255), provenance varchar(64), status varchar(16),"
                " stage varchar(64), error varchar(1000), created_at datetime, seconds float, summary json, has_keys integer)")
    con.execute("insert into analyses (id, filename, provenance, status, stage, created_at) values (1, 'old.pcap', 'user-upload', 'done', 'done', '2026-01-01')")
    con.commit()
    con.close()
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    from ipsec_analyzer.api import db
    importlib.reload(db)
    db.init_db()
    with db.SessionLocal() as s:
        a = s.get(db.Analysis, 1)
        assert a.filename == "old.pcap" and a.owner_id is None and a.label is None


def test_api_key_gate_still_applies_and_readonly_key_can_sign_in(make_app):
    ro = secrets.token_urlsafe(12)
    admin = secrets.token_urlsafe(12)
    c = make_app(API_KEY=admin, READONLY_API_KEY=ro)()
    assert c.get("/api/account").status_code == 401
    assert _register(c).status_code == 401
    assert c.post("/api/account/register", json={"email": "a@example.com", "password": PW}, headers={"X-API-Key": admin}).status_code == 201
    c.post("/api/account/logout", headers={"X-API-Key": admin})
    assert c.post("/api/account/login", json={"email": "a@example.com", "password": PW}, headers={"X-API-Key": ro}).status_code == 200
