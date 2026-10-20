"""User accounts: registration, login and the per-user ownership of saved analyses.

Optional and additive. Anonymous use keeps working exactly as before (analyses with no owner are the shared demo
space); a signed-in user's analyses are private to them and persist between sessions. This sits behind the optional
API-key gate in `auth.py`, which is unchanged: when `API_KEY` is set a client needs the key *and* may then sign in.

Security notes
- Passwords are hashed with scrypt (stdlib, per-password random salt, constant-time compare). Nothing reversible is stored.
- The session cookie is a random 256-bit token; only its SHA-256 is stored, so a database leak cannot be replayed.
  HttpOnly, SameSite=Strict, Secure behind HTTPS, 14-day lifetime. Changing the password signs out every other browser.
- Failed logins are throttled per client address and per account; unknown accounts cost the same time as wrong passwords.
- `ALLOW_REGISTRATION=0` closes sign-up for deployments where an admin creates users out of band.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import db as dbm
from .auth import _Throttle

USER_COOKIE = "ipsec_user"
SESSION_DAYS = 14
MIN_PASSWORD = 10
MAX_PASSWORD = 256  # bounds the scrypt work an attacker can request
_SCRYPT = (2**14, 8, 1)
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,189}\.[^@\s]{2,}$")

router = APIRouter()
login_throttle = _Throttle()
register_throttle = _Throttle()


def get_session() -> Session:
    with dbm.SessionLocal() as s:
        yield s


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    n, r, p = _SCRYPT
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt${}${}${}${}${}".format(n, r, p, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, dk = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return secrets.compare_digest(got, base64.b64decode(dk))
    except Exception:  # noqa: BLE001 - a malformed hash is simply a failed login
        return False


_DUMMY = hash_password(secrets.token_urlsafe(16))  # spent on unknown emails so they take as long as wrong passwords


def _check_password_rules(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise HTTPException(422, f"password must be at least {MIN_PASSWORD} characters")
    if len(password) > MAX_PASSWORD:
        raise HTTPException(422, f"password must be at most {MAX_PASSWORD} characters")


# ------------------------------------------------------------------ sessions
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)  # SQLite returns naive datetimes


def _start_session(s: Session, user: dbm.User, request: Request, response: Response) -> None:
    s.execute(delete(dbm.UserSession).where(dbm.UserSession.expires_at < _now()))  # housekeeping
    token = secrets.token_urlsafe(32)
    s.add(dbm.UserSession(token_hash=_token_hash(token), user_id=user.id, expires_at=_now() + timedelta(days=SESSION_DAYS)))
    s.commit()
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(USER_COOKIE, token, max_age=SESSION_DAYS * 86400, httponly=True, samesite="strict", secure=secure, path="/")


def current_user(request: Request, s: Session = Depends(get_session)) -> dbm.User | None:
    token = request.cookies.get(USER_COOKIE)
    if not token:
        return None
    row = s.get(dbm.UserSession, _token_hash(token))
    if row is None or _aware(row.expires_at) < _now():
        return None
    return s.get(dbm.User, row.user_id)


def _public(u: dbm.User) -> dict[str, Any]:
    return {"id": u.id, "email": u.email, "created_at": u.created_at.isoformat()}


def _client(request: Request) -> str:
    return request.client.host if request.client else "?"


def _registration_open() -> bool:
    return os.environ.get("ALLOW_REGISTRATION", "1").lower() not in ("0", "false", "no")


async def _json(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        raise HTTPException(400, "expected a JSON body") from None
    if not isinstance(body, dict):
        raise HTTPException(400, "expected a JSON object")
    return body


# ------------------------------------------------------------------ routes
@router.get("/api/account")
def whoami(user: dbm.User | None = Depends(current_user)) -> dict[str, Any]:
    return {"registration_open": _registration_open(), "user": _public(user) if user else None}


@router.post("/api/account/register", status_code=201)
async def register(request: Request, response: Response, s: Session = Depends(get_session)) -> Any:
    if not _registration_open():
        raise HTTPException(403, "registration is closed on this server")
    who = _client(request)
    if register_throttle.blocked(who):
        return JSONResponse({"detail": "too many sign-up attempts; wait a minute"}, status_code=429)
    register_throttle.fail(who)  # every attempt counts, successful or not
    body = await _json(request)
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not _EMAIL.match(email):
        raise HTTPException(422, "enter a valid email address")
    _check_password_rules(password)
    if s.scalars(select(dbm.User).where(dbm.User.email == email)).first():
        raise HTTPException(409, "an account with this email already exists")
    user = dbm.User(email=email, password_hash=hash_password(password))
    s.add(user)
    s.commit()
    _start_session(s, user, request, response)
    return {"user": _public(user)}


@router.post("/api/account/login")
async def login(request: Request, response: Response, s: Session = Depends(get_session)) -> Any:
    who = _client(request)
    body = await _json(request)
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))[:MAX_PASSWORD]
    if login_throttle.blocked(who) or login_throttle.blocked("e:" + email):
        return JSONResponse({"detail": "too many failed attempts; wait a minute"}, status_code=429)
    user = s.scalars(select(dbm.User).where(dbm.User.email == email)).first()
    ok = verify_password(password, user.password_hash if user else _DUMMY)
    if not (user and ok):
        login_throttle.fail(who)
        login_throttle.fail("e:" + email)
        return JSONResponse({"detail": "wrong email or password"}, status_code=401)
    _start_session(s, user, request, response)
    return {"user": _public(user)}


@router.post("/api/account/logout")
def logout(request: Request, response: Response, s: Session = Depends(get_session)) -> dict[str, bool]:
    token = request.cookies.get(USER_COOKIE)
    if token:
        s.execute(delete(dbm.UserSession).where(dbm.UserSession.token_hash == _token_hash(token)))
        s.commit()
    response.delete_cookie(USER_COOKIE, path="/")
    return {"ok": True}


def require_user(user: dbm.User | None = Depends(current_user)) -> dbm.User:
    if user is None:
        raise HTTPException(401, "sign in to do this")
    return user


@router.post("/api/account/password")
async def change_password(request: Request, user: dbm.User = Depends(require_user), s: Session = Depends(get_session)) -> dict[str, bool]:
    body = await _json(request)
    if login_throttle.blocked("u:%d" % user.id):
        raise HTTPException(429, "too many failed attempts; wait a minute")
    if not verify_password(str(body.get("current", ""))[:MAX_PASSWORD], user.password_hash):
        login_throttle.fail("u:%d" % user.id)
        raise HTTPException(403, "current password is wrong")
    new = str(body.get("new", ""))
    _check_password_rules(new)
    user.password_hash = hash_password(new)
    keep = _token_hash(request.cookies.get(USER_COOKIE, ""))
    s.execute(delete(dbm.UserSession).where(dbm.UserSession.user_id == user.id, dbm.UserSession.token_hash != keep))  # sign out elsewhere
    s.commit()
    return {"ok": True}


@router.delete("/api/account", status_code=204)
async def delete_account(request: Request, response: Response, user: dbm.User = Depends(require_user), s: Session = Depends(get_session)) -> Response:
    """Erases the account, its sessions and every analysis it owns (including uploaded captures on disk)."""
    import shutil
    body = await _json(request)
    if not verify_password(str(body.get("password", ""))[:MAX_PASSWORD], user.password_hash):
        raise HTTPException(403, "password is wrong")
    for a in s.scalars(select(dbm.Analysis).where(dbm.Analysis.owner_id == user.id)).all():
        shutil.rmtree(dbm.DATA_DIR / "uploads" / str(a.id), ignore_errors=True)
        s.delete(a)
    for model in (dbm.UserSession, dbm.AlertEvent, dbm.AlertSettings):  # SQLite does not enforce ON DELETE CASCADE
        s.execute(delete(model).where(model.user_id == user.id))
    s.delete(user)
    s.commit()
    out = Response(status_code=204)
    out.delete_cookie(USER_COOKIE, path="/")
    return out
