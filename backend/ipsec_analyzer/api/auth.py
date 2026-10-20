"""Optional shared-key authentication with two roles.

Off by default (the demo stays open). Set `API_KEY` to require a key on every `/api/*` route except the health
check and the login endpoints; set `READONLY_API_KEY` as well to hand out a second key that can read but not
upload or delete. A client authenticates with an `X-API-Key` / `Authorization: Bearer` header (scripts) or by
POSTing the key to `/api/login`, which sets an HttpOnly, SameSite=Strict cookie (the browser UI, whose download
links cannot carry headers). The cookie holds a SHA-256 digest of role and key, so rotating a key signs everyone
out; nothing is stored server-side.

This is a shared-secret gate for a single-team deployment, not user accounts: there is no per-user identity,
audit trail or key hashing at rest (keys live in the environment). Put TLS in front of it.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import JSONResponse

COOKIE = "ipsec_session"
COOKIE_MAX_AGE = 8 * 3600
OPEN_PATHS = {"/api/health", "/api/login", "/api/logout", "/api/auth"}
READONLY_OK = {"/api/account/login", "/api/account/logout"}  # a read-only key may still sign in to its own account
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_MAX_FAILURES, _WINDOW_S = 5, 60.0

router = APIRouter()


def _keys() -> dict[str, str]:
    """role -> key, read per request so the environment can change in tests."""
    out = {}
    if os.environ.get("API_KEY"):
        out["admin"] = os.environ["API_KEY"]
    if os.environ.get("READONLY_API_KEY"):
        out["readonly"] = os.environ["READONLY_API_KEY"]
    return out


def _digest(role: str, key: str) -> str:
    return hashlib.sha256(f"{role}:{key}".encode()).hexdigest()


def _role_for_key(presented: str) -> str | None:
    found = None
    for role, key in _keys().items():  # compare against every key so timing does not reveal which one matched
        if secrets.compare_digest(presented.encode(), key.encode()):
            found = role
    return found


def _role_for_cookie(value: str) -> str | None:
    found = None
    for role, key in _keys().items():
        if secrets.compare_digest(value.encode(), _digest(role, key).encode()):
            found = role
    return found


def role_of(request: Request) -> str | None:
    h = request.headers
    presented = h.get("x-api-key") or (h.get("authorization", "")[7:] if h.get("authorization", "").lower().startswith("bearer ") else "")
    if presented and (role := _role_for_key(presented)):
        return role
    cookie = request.cookies.get(COOKIE)
    return _role_for_cookie(cookie) if cookie else None


class _Throttle:
    """Per-client limit on failed logins (in memory; one process)."""

    def __init__(self) -> None:
        self._fails: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, who: str) -> bool:
        now = time.monotonic()
        with self._lock:
            recent = [t for t in self._fails.get(who, []) if now - t < _WINDOW_S]
            self._fails[who] = recent
            return len(recent) >= _MAX_FAILURES

    def fail(self, who: str) -> None:
        with self._lock:
            self._fails.setdefault(who, []).append(time.monotonic())

    def reset(self) -> None:
        with self._lock:
            self._fails.clear()


throttle = _Throttle()


def install(app: FastAPI) -> None:
    app.include_router(router)

    @app.middleware("http")
    async def gate(request: Request, call_next):  # noqa: ANN001
        path = request.url.path
        if not _keys() or not path.startswith("/api/") or path in OPEN_PATHS or request.method == "OPTIONS":
            return await call_next(request)
        role = role_of(request)
        if role is None:
            return JSONResponse({"detail": "authentication required"}, status_code=401)
        if role == "readonly" and request.method not in _SAFE_METHODS and path not in READONLY_OK:
            return JSONResponse({"detail": "this key is read-only"}, status_code=403)
        return await call_next(request)


@router.get("/api/auth")
def auth_status(request: Request) -> dict[str, object]:
    required = bool(_keys())
    role = role_of(request) if required else "admin"
    return {"required": required, "authenticated": role is not None, "role": role}


@router.post("/api/login")
async def login(request: Request, response: Response) -> dict[str, object]:
    who = request.client.host if request.client else "?"
    if not _keys():
        return {"required": False, "role": "admin"}
    if throttle.blocked(who):
        return JSONResponse({"detail": "too many failed attempts; wait a minute"}, status_code=429)  # type: ignore[return-value]
    try:
        presented = str((await request.json()).get("key", ""))
    except Exception:  # noqa: BLE001 - malformed body is just a failed login
        presented = ""
    role = _role_for_key(presented) if presented else None
    if role is None:
        throttle.fail(who)
        return JSONResponse({"detail": "invalid key"}, status_code=401)  # type: ignore[return-value]
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(COOKIE, _digest(role, _keys()[role]), max_age=COOKIE_MAX_AGE, httponly=True, samesite="strict", secure=secure, path="/")
    return {"required": True, "role": role}


@router.post("/api/logout")
def logout(response: Response) -> dict[str, bool]:
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}
