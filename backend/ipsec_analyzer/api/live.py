"""Wires the watched folder and the syslog listener (ingest/) to the database and the analysis service."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from ..ingest.syslog_udp import SyslogListener
from ..ingest.watch import Settings, Watcher
from . import service
from .db import DATA_DIR, Analysis, SessionLocal

watcher: Watcher | None = None
listener: SyslogListener | None = None


def _ingest(path: Path, keys: Path | None, kind: str, existing: int | None, rel: str, provenance: str) -> tuple[int, str | None]:
    with SessionLocal() as s:
        a = s.get(Analysis, existing) if existing else None
        if a is None:
            a = Analysis(filename=rel, provenance=provenance, has_keys=int(keys is not None))
            s.add(a)
        else:
            a.status, a.stage, a.error, a.has_keys = "queued", "queued", None, int(keys is not None)
        s.commit()
        aid = a.id
    service.run_analysis(aid, path, keys, kind)  # synchronous: this is the watcher's own thread
    with SessionLocal() as s:
        a = s.get(Analysis, aid)
        if a is None or a.status != "done":
            return aid, (a.error if a else None) or "analysis failed"
        return aid, None


def _exists(aid: int) -> bool:
    with SessionLocal() as s:
        return s.get(Analysis, aid) is not None


def _prune(ids: list[int]) -> list[int]:
    removed = []
    with SessionLocal() as s:
        for i in ids:
            if (a := s.get(Analysis, i)) is not None:
                s.delete(a)
                removed.append(i)
        s.commit()
    for i in removed:
        shutil.rmtree(DATA_DIR / "uploads" / str(i), ignore_errors=True)
    return removed


def start(max_upload: int) -> None:
    """Start whatever the environment asks for (WATCH_DIR, SYSLOG_LISTEN); both are off by default."""
    global watcher, listener
    settings = Settings.from_env(max_upload)
    roots: list[tuple[Path, str]] = []
    if settings.watch_dir:
        roots.append((settings.watch_dir, "watch-folder"))
    listener = SyslogListener.from_env(DATA_DIR / "ingest" / "syslog")
    if listener:
        listener.start()
        roots.append((listener.out_dir, "live-syslog"))
    if roots:
        watcher = Watcher(roots, DATA_DIR / "ingest" / "state.json", _ingest, _exists, _prune, settings)
        watcher.start()


def stop() -> None:
    global watcher, listener
    if watcher:
        watcher.stop()
    if listener:
        listener.stop()
    watcher = listener = None


def status() -> dict[str, Any]:
    return {"watch": watcher.status() if watcher else {"enabled": False},
            "syslog": listener.status() if listener else {"enabled": False}}
