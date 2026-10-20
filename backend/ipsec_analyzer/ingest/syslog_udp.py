"""UDP syslog listener: point a gateway's rsyslog at this server and its strongSwan log is analysed as it arrives.

    SYSLOG_LISTEN=0.0.0.0:5514       host:port to bind (UDP); unset = off. Ports below 1024 need privileges.
    SYSLOG_ALLOW=198.51.100.0/24,... optional source allow-list (comma-separated IPs/CIDRs); empty = accept any source
    SYSLOG_MAX_MB=8                  per-source file size cap; at the cap the oldest half is dropped

Each source IP gets its own file `<DATA_DIR>/ingest/syslog/<ip>.log` (so two gateways never mix), which the watched-folder
machinery analyses as a growing log: one analysis per source, updated in place. rsyslog example for the sender:

    if $programname startswith 'charon' then @198.51.100.9:5514       # '@' = UDP, '@@' = TCP (not supported here)

Only lines that look like charon output (`12[IKE] ...`) are stored; everything else is counted and dropped. Each line is
stored with the *receive* time in front of it (the sender's own clock and year are not trusted), RFC 3164 `<PRI>` is
stripped, and a datagram is capped at 8 KiB.

Limits: UDP syslog is unauthenticated and unencrypted and can be spoofed or lost under load, so treat what arrives as
evidence of what the gateway said, not as an audit-grade record; restrict the port at the network level and use
`SYSLOG_ALLOW`. TCP/TLS syslog is not implemented. Rotation drops the oldest half of a file, which can cut the early lines
of a long-lived SA (its negotiated proposals) out of view; the tunnel is then assessed only on what remains.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .charon import LINE

_PRI = re.compile(rb"^<\d{1,3}>(?:\d )?")
_MAX_DATAGRAM = 8192
_MAX_SOURCES = 64


@dataclass
class _Source:
    lines: int = 0
    bytes: int = 0
    last: float = 0.0


@dataclass
class SyslogListener:
    host: str
    port: int
    out_dir: Path
    allow: list[ipaddress._BaseNetwork] = field(default_factory=list)
    max_bytes: int = 8 * 1024 * 1024
    sources: dict[str, _Source] = field(default_factory=dict)
    ignored: int = 0  # datagrams that were not charon lines or came from a disallowed/excess source
    _sock: socket.socket | None = None
    _thread: threading.Thread | None = None
    _stop: threading.Event = field(default_factory=threading.Event)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def from_env(cls, out_dir: Path) -> "SyslogListener | None":
        spec = os.environ.get("SYSLOG_LISTEN", "").strip()
        if not spec:
            return None
        host, _, port = spec.rpartition(":")
        allow = [ipaddress.ip_network(x.strip(), strict=False) for x in os.environ.get("SYSLOG_ALLOW", "").split(",") if x.strip()]
        return cls(host or "0.0.0.0", int(port), out_dir, allow, int(float(os.environ.get("SYSLOG_MAX_MB", "8")) * 1024 * 1024))

    def start(self) -> int:
        """Bind and serve in a daemon thread. Returns the bound port (useful when port 0 was asked for)."""
        self.out_dir.mkdir(parents=True, exist_ok=True)
        fam = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self._sock = socket.socket(fam, socket.SOCK_DGRAM)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name="syslog-udp", daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, (src, *_rest) = self._sock.recvfrom(_MAX_DATAGRAM + 1)  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.handle(data[:_MAX_DATAGRAM], src)
            except Exception:  # noqa: BLE001 - one bad datagram must not stop the listener
                traceback.print_exc()

    def _allowed(self, src: str) -> bool:
        if not self.allow:
            return True
        try:
            ip = ipaddress.ip_address(src)
        except ValueError:
            return False
        return any(ip in n for n in self.allow)

    def handle(self, data: bytes, src: str) -> bool:
        """Store one datagram if it is a charon line from an allowed source. Returns whether it was stored."""
        text = _PRI.sub(b"", data.strip(), count=1).decode("utf-8", errors="replace")
        text = text.replace("\r", "").split("\n", 1)[0]
        with self._lock:
            if not self._allowed(src) or not LINE.search(text) or (src not in self.sources and len(self.sources) >= _MAX_SOURCES):
                self.ignored += 1
                return False
            safe = re.sub(r"[^0-9A-Za-z.]+", "_", src)  # IPv6 colons etc.; never a path component from the network
            self.out_dir.mkdir(parents=True, exist_ok=True)
            path = self.out_dir / f"{safe}.log"
            stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00"
            line = f"{stamp} {text}\n"
            if path.exists() and path.stat().st_size + len(line) > self.max_bytes:
                self._rotate(path)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
            s = self.sources.setdefault(src, _Source())
            s.lines, s.bytes, s.last = s.lines + 1, s.bytes + len(line), time.time()
            return True

    @staticmethod
    def _rotate(path: Path) -> None:
        raw = path.read_bytes()
        keep = raw[len(raw) // 2:]
        nl = keep.find(b"\n")
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(keep[nl + 1:] if nl >= 0 else b"")
        tmp.replace(path)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"enabled": True, "listen": f"{self.host}:{self.port}", "allow": [str(n) for n in self.allow], "ignored": self.ignored,
                    "sources": [{"source": k, "lines": v.lines, "bytes": v.bytes, "last_seen": v.last} for k, v in sorted(self.sources.items())]}
