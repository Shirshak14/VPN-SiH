"""Watched-folder ingestion: drop a capture or a daemon log into a directory and it is analysed without an upload.

    WATCH_DIR=/var/captures          directory to watch (searched to depth 3); unset = off
    WATCH_INTERVAL_S=5               seconds between scans
    WATCH_STABLE_S=5                 a file must be unchanged (size and mtime) for this long before it is read
    WATCH_KEEP=100                   keep at most this many watched analyses (oldest are removed)
    WATCH_LIVE_MAX_WAIT_S=30         a known log that keeps changing is still re-read at least this often

One analysis per file path, always the latest content of that file:
  * a new file becomes a new analysis;
  * a file that changed after it was analysed (a log that keeps growing, a capture that was overwritten) is analysed
    again and the same analysis is updated in place, so rotating logs do not pile up analyses;
  * an analysis the user deleted is not recreated until the file changes again;
  * `x.pcap` uses a sibling `x.keys` as its decryption table when one exists (the convention used in data/captures).

This is polling on purpose: it works on every platform and on network mounts, where inotify does not. A scan only reads
a file once it has settled, which keeps a half-written `tcpdump -w` file out of the parser; combine it with
`tcpdump -G 60 -w cap-%FT%T.pcap` (rotated captures) for near-live capture without a long-lived socket. It does not sniff
interfaces, and it does not tail a file the instant a line is appended: latency is the scan interval plus the settle time.
"""
from __future__ import annotations

import json
import os
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .charon import looks_like_charon

CAPTURE_EXT = {".pcap", ".pcapng", ".cap"}
LOG_EXT = {".log", ".syslog", ".txt"}
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
_SKIP_SUFFIX = (".part", ".tmp", ".swp", ".crdownload", "~")
_MAX_DEPTH = 3
_MAX_FILES = 2000
_MAX_ERRORS = 20


@dataclass
class Settings:
    watch_dir: Path | None
    interval_s: float
    stable_s: float
    keep: int
    max_bytes: int
    live_max_wait_s: float = 30.0

    @classmethod
    def from_env(cls, max_bytes: int) -> "Settings":
        d = os.environ.get("WATCH_DIR")
        return cls(Path(d) if d else None, float(os.environ.get("WATCH_INTERVAL_S", "5")), float(os.environ.get("WATCH_STABLE_S", "5")),
                   int(os.environ.get("WATCH_KEEP", "100")), max_bytes,
                   float(os.environ.get("WATCH_LIVE_MAX_WAIT_S", "30")))


@dataclass
class _Seen:
    sig: tuple
    since: float  # monotonic time at which this signature was first observed
    streak: float  # when the current run of consecutive scans that each saw a change began
    confirmed: bool = False  # the same signature was seen on a later scan too


@dataclass
class Watcher:
    """Directory poller. `ingest(path, keys, kind, existing_id, filename, provenance)` creates or refreshes an analysis
    and returns (its id, error message or None) (it is injected so this module has no web or database dependency and can be tested alone)."""
    roots: list[tuple[Path, str]]  # (directory, provenance label)
    state_path: Path
    ingest: Callable[..., tuple[int, str | None]]
    exists: Callable[[int], bool]
    prune: Callable[[int], list[int]]
    settings: Settings
    state: dict[str, dict[str, Any]] = field(default_factory=dict)
    last_scan: float = 0.0
    errors: list[dict[str, Any]] = field(default_factory=list)
    _seen: dict[str, _Seen] = field(default_factory=dict)
    _last_proc: dict[str, float] = field(default_factory=dict)
    _now: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    def __post_init__(self) -> None:
        try:
            self.state = json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            self.state = {}

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="watch-folder", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.scan_once()
            except Exception:  # noqa: BLE001 - the watcher must outlive any single bad file
                traceback.print_exc()
            self._stop.wait(self.settings.interval_s)

    # ------------------------------------------------------------------ scanning
    def _candidates(self) -> list[tuple[Path, Path, str]]:
        out: list[tuple[Path, Path, str]] = []
        for root, prov in self.roots:
            if not root.is_dir():
                continue
            base = len(root.resolve().parts)
            for dirpath, dirnames, filenames in os.walk(root):
                depth = len(Path(dirpath).resolve().parts) - base
                dirnames[:] = [d for d in dirnames if not d.startswith(".")] if depth < _MAX_DEPTH else []
                for fn in filenames:
                    p = Path(dirpath) / fn
                    if fn.startswith(".") or fn.endswith(_SKIP_SUFFIX) or p.is_symlink():
                        continue
                    if p.suffix.lower() in CAPTURE_EXT | LOG_EXT:
                        out.append((p, root, prov))
                    if len(out) >= _MAX_FILES:
                        return out
        return out

    def scan_once(self, now: float | None = None) -> int:
        """One pass. Returns how many files were (re)analysed. `now` (monotonic seconds) is injectable for tests."""
        now = time.monotonic() if now is None else now
        self._now = now
        done = 0
        with self._lock:
            live = set()
            for path, root, prov in self._candidates():
                key = str(path)
                live.add(key)
                try:
                    st = path.stat()
                except OSError:
                    continue
                keys = path.with_suffix(".keys") if path.suffix.lower() in CAPTURE_EXT else None
                kst = keys.stat() if keys and keys.is_file() else None
                sig = (st.st_size, st.st_mtime_ns, kst.st_size if kst else 0, kst.st_mtime_ns if kst else 0)
                seen, rec = self._seen.get(key), self.state.get(key)
                if seen is None or seen.sig != sig:
                    streak = seen.streak if seen is not None and not seen.confirmed else now
                    self._seen[key] = _Seen(sig, now, streak)  # new or still changing: start (or restart) the settle clock
                    # A log that never goes quiet (a busy gateway) would never settle, so an already-known log that has
                    # changed on every scan for `live_max_wait_s` is read anyway; a capture is never read while growing.
                    live_log = rec is not None and path.suffix.lower() in LOG_EXT
                    if not (live_log and now - max(streak, self._last_proc.get(key, streak)) >= self.settings.live_max_wait_s):
                        continue
                else:
                    seen.confirmed = True
                    if now - seen.since < self.settings.stable_s:
                        continue
                if rec and rec.get("sig") == list(sig):
                    continue
                if self._process(path, root, prov, sig, kst is not None and keys, rec):
                    done += 1
            for gone in set(self._seen) - live:
                self._seen.pop(gone, None)
            self.last_scan = time.time()
            if done:
                self._prune()
            self._save()
        return done

    def _process(self, path: Path, root: Path, prov: str, sig: tuple, keys: Path | None | bool, rec: dict | None) -> bool:
        key = str(path)
        kind = "pcap" if path.suffix.lower() in CAPTURE_EXT else "log"
        rel = str(path.relative_to(root))[:255]
        try:
            if sig[0] > self.settings.max_bytes:
                raise ValueError(f"larger than the {self.settings.max_bytes // 2**20} MB limit")
            with open(path, "rb") as f:
                head = f.read(65536)
            if kind == "pcap" and head[:4] not in PCAP_MAGICS:
                raise ValueError("not a PCAP/PCAPNG file (bad magic bytes)")
            if kind == "log" and not looks_like_charon(head):
                raise ValueError("no strongSwan charon log lines found")
            existing = rec.get("analysis_id") if rec else None
            if existing is not None and not self.exists(existing):
                existing = None
            aid, err = self.ingest(path, keys if keys else None, kind, existing, rel, prov)
            self.state[key] = {"sig": list(sig), "analysis_id": aid, "kind": kind, "at": time.time(), "error": err}
            self._last_proc[key] = self._now
            if err:
                self.errors = ([{"path": rel, "error": err, "at": time.time()}] + self.errors)[:_MAX_ERRORS]
            return err is None
        except Exception as e:  # noqa: BLE001 - recorded, not retried until the file changes
            msg = f"{type(e).__name__}: {e}"[:300]
            self.state[key] = {"sig": list(sig), "analysis_id": rec.get("analysis_id") if rec else None, "kind": kind, "at": time.time(), "error": msg}
            self.errors = ([{"path": rel, "error": msg, "at": time.time()}] + self.errors)[:_MAX_ERRORS]
            return False

    def _prune(self) -> None:
        """Keep the newest `keep` watched analyses; forget state for the ones removed."""
        ids = sorted((r["analysis_id"], k) for k, r in self.state.items() if r.get("analysis_id") is not None)
        extra = len(ids) - self.settings.keep
        if extra > 0:
            removed = set(self.prune([i for i, _ in ids[:extra]]))
            for i, k in ids[:extra]:
                if i in removed:
                    self.state[k]["analysis_id"] = None

    def _save(self) -> None:
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state))
            tmp.replace(self.state_path)
        except OSError:
            traceback.print_exc()

    # ------------------------------------------------------------------ status
    def status(self) -> dict[str, Any]:
        with self._lock:
            files = [{"path": k, "analysis_id": r.get("analysis_id"), "kind": r.get("kind"), "at": r.get("at"), "error": r.get("error")}
                     for k, r in sorted(self.state.items(), key=lambda kv: -(kv[1].get("at") or 0))[:50]]
            return {"enabled": True, "dirs": [str(r) for r, _ in self.roots], "interval_s": self.settings.interval_s,
                    "stable_s": self.settings.stable_s, "keep": self.settings.keep, "last_scan": self.last_scan or None,
                    "files": files, "errors": list(self.errors)}
