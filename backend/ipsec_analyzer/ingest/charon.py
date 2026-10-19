"""strongSwan `charon` log -> reconstructed tunnels (the same `Tunnel` objects the packet pipeline produces).

A gateway's own log is the one place where an IKEv2 tunnel's negotiated suites are visible without decryption keys:
the daemon logs every proposal it received and the one it selected, for the IKE SA and for each child SA. This parser
reads those lines (plain `filelog`, syslog, or journald text) and builds one `Tunnel` per IKE SA, so the existing rule
engine, risk score, reports and UI work unchanged.

What it reads (strongSwan 5.x message formats; verbose lines need `cfg = 2` and `ike = 2` or higher):

    12[IKE] <net-net|1> initiating IKE_SA net-net[1] to 192.0.2.2          role + peer
    13[IKE] 192.0.2.1 is initiating an IKE_SA                              role + peer (responder side)
    12[CFG] <1> received proposals: IKE:AES_CBC_256/..., IKE:3DES_CBC/...  what the peer offered
    12[CFG] <1> configured proposals: IKE:...                              what we offered (initiator)
    12[CFG] <1> selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
    12[CFG] <1> selected proposal: ESP:AES_GCM_16_256/MODP_3072/NO_EXT_SEQ
    12[IKE] <net-net|1> IKE_SA net-net[1] established between L[id]...R[id]
    12[IKE] <net-net|1> CHILD_SA net-net{1} established with SPIs c1_i c2_o and TS ... === ...
    plus retransmits, NO_PROPOSAL_CHOSEN / AUTHENTICATION_FAILED, lifetimes, rekeys and authentication method.

Limits, stated plainly: the format was implemented from strongSwan's documented/known message layout and tested on
hand-written fixtures modelled on it; it has not been run against logs from a live daemon in this repository's
sandbox (use `python -m ipsec_analyzer.ingest.charon <file>` on a real log to check). A log shows what the daemon
decided, not what was on the wire, so wire-level facts (message sizes, handshake timing, ESP sequence numbers,
unanswered-handshake floods) are not observable and those rules/anomaly scoring do not apply. Only strongSwan is read;
Libreswan/other daemons are not. Timestamps without a year or zone are read as UTC in the current year.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..sa.models import AttemptSummary, ChildSa, Suite, Tunnel

LINE = re.compile(r"(?P<thread>\d{1,3})\[(?P<grp>[A-Z]{3})\]\s(?P<msg>.*)$")
TAG = re.compile(r"^<(?:(?P<name>[^|<>]*)\|)?(?P<uid>\d+)>\s*")
_SYSLOG_TS = re.compile(r"^(?:<\d+>\d?\s*)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)")
_ISO_TS = re.compile(r"^(?P<d>\d{4}-\d\d-\d\d)[T ](?P<t>\d\d:\d\d:\d\d)(?P<frac>\.\d+)?(?P<tz>Z|[+-]\d\d:?\d\d)?")
_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
_PRIOR_WINDOW_S = 300.0
_MAX_LINES = 5_000_000  # a log this long is not a log we can sensibly hold; stop rather than run out of memory


class LogError(ValueError):
    """The input is not a strongSwan log we can read."""


@dataclass
class _Sa:
    key: tuple[int, int]  # (daemon start counter, unique id)
    first_ts: float = 0.0
    last_ts: float = 0.0
    role: str | None = None  # initiator | responder
    mode: str | None = None  # IKEv2 | Main Mode | Aggressive Mode
    version: int | None = None
    local: str | None = None
    remote: str | None = None
    established: bool = False
    failure: str | None = None
    offered_received: list[Suite] = field(default_factory=list)
    offered_configured: list[Suite] = field(default_factory=list)
    chosen: Suite | None = None
    lifetime: int | None = None
    pending_esp: list[Suite] = field(default_factory=list)
    children: list[ChildSa] = field(default_factory=list)
    auth: str | None = None
    retransmits: int = 0
    streak: int = 0
    ike_rekeys: int = 0
    child_rekeys: int = 0
    dpd: int = 0
    lines: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class ParsedLog:
    tunnels: list[Tunnel]
    lines_total: int
    lines_matched: int
    first_ts: float
    last_ts: float
    daemon_starts: int
    skipped_sas: int = 0  # SAs that never reached a proposal or an outcome (nothing to assess)

    def info(self) -> dict:
        return {"lines": self.lines_total, "charon_lines": self.lines_matched, "first_ts": self.first_ts, "last_ts": self.last_ts,
                "daemon_starts": self.daemon_starts, "ike_sas": len(self.tunnels), "skipped_sas": self.skipped_sas}


# ----------------------------------------------------------------------------- algorithm names
_GROUP_FIX = {"ECP_192_BP": "ECP_192", "ECP_224_BP": "BRAINPOOL_P224", "ECP_256_BP": "BRAINPOOL_P256",
              "ECP_384_BP": "BRAINPOOL_P384", "ECP_512_BP": "BRAINPOOL_P512", "CURVE_25519": "CURVE_25519",
              "CURVE_448": "CURVE_448"}
_ENCR_FIX = {"3DES_CBC": "3DES", "DES_CBC": "DES", "BLOWFISH_CBC": "BLOWFISH", "CAST_CBC": "CAST", "IDEA_CBC": "IDEA",
             "RC5_CBC": "RC5"}
_AEAD = re.compile(r"^(AES_(?:GCM|CCM)_(?:8|12|16)|CAMELLIA_CCM_(?:8|12|16))(?:_(\d{3}))?$")
_BITS = re.compile(r"^(.+?)_(\d{2,3})$")
_DH = re.compile(r"^(MODP_\d+(?:_\d+)?|ECP_\d+(?:_BP)?|CURVE_\d+|NTRU_\w+|ML_KEM_\d+|KYBER_\w+)$")


def parse_suite(text: str) -> Suite:
    """'AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048' -> Suite (names as the policy pack spells them)."""
    s = Suite()
    for tok in (t.strip() for t in text.split("/") if t.strip()):
        if tok.startswith("PRF_"):
            s.prf = tok[4:]
        elif tok in ("NO_EXT_SEQ", "EXT_SEQ"):
            s.esn = tok
        elif _DH.match(tok):
            s.dh = _GROUP_FIX.get(tok, tok)
        elif tok.startswith(("HMAC_", "AES_XCBC", "AES_CMAC", "AES_128_GMAC", "AES_192_GMAC", "AES_256_GMAC")):
            s.integ = tok
        elif tok == "NULL":
            s.encr = "NULL"
        else:
            m = _AEAD.match(tok)
            if m:
                s.encr, s.encr_bits = m.group(1), int(m.group(2)) if m.group(2) else None
                continue
            if tok in _ENCR_FIX:
                s.encr = _ENCR_FIX[tok]
                continue
            m = _BITS.match(tok)
            if m and m.group(1) in ("AES_CBC", "AES_CTR", "CAMELLIA_CBC", "CAMELLIA_CTR", "CHACHA20_POLY1305", "BLOWFISH_CBC", "CAST_CBC", "RC5_CBC"):
                name = m.group(1)
                s.encr, s.encr_bits = _ENCR_FIX.get(name, name), int(m.group(2))
            else:
                s.encr = _ENCR_FIX.get(tok, tok)
    return s


def _suites(text: str, proto: str) -> list[Suite]:
    out = []
    for part in re.split(r",\s*(?=(?:IKE|ESP|AH):)", text.strip()):
        head, _, body = part.partition(":")
        if head.strip() == proto and body:
            out.append(parse_suite(body))
    return out


# ----------------------------------------------------------------------------- timestamps
def _ts(line: str, year: int) -> float | None:
    m = _ISO_TS.match(line)
    if m:
        tz = m.group("tz")
        tzs = "+00:00" if not tz or tz == "Z" else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
        try:
            return datetime.fromisoformat(f"{m['d']}T{m['t']}{m['frac'] or ''}{tzs}").timestamp()
        except ValueError:
            return None
    m = _SYSLOG_TS.match(line)
    if m and m["mon"] in _MONTHS:
        try:
            return datetime(year, _MONTHS[m["mon"]], int(m["day"]), *map(int, m["time"].split(":")), tzinfo=timezone.utc).timestamp()
        except ValueError:
            return None
    return None


# ----------------------------------------------------------------------------- parser
_IP = r"(?P<ip>[0-9a-fA-F:.]+)"
RE_INITIATING = re.compile(r"initiating (?:(?P<mode>Main Mode|Aggressive Mode) )?IKE_SA \S+\[\d+\] to " + _IP)
RE_IS_INITIATING = re.compile(r"^" + _IP + r" is initiating (?:a|an) (?:(?P<mode>Main Mode|Aggressive Mode) )?IKE_SA")
RE_MODE = re.compile(r"(?:generating|parsed) (?P<ex>IKE_SA_INIT|IKE_AUTH|ID_PROT|AGGRESSIVE|QUICK_MODE) (?:request|response)")
RE_ESTABLISHED = re.compile(r"IKE_SA \S+\[\d+\] established between (?P<l>[^\[\s]+)(?:\[[^\]]*\])?\.\.\.(?P<r>[^\[\s]+)")
RE_CHILD = re.compile(r"CHILD_SA \S+\{\d+\} established with SPIs (?P<i>[0-9a-fA-F]+)_i (?P<o>[0-9a-fA-F]+)_o")
RE_RETX = re.compile(r"retransmit (?P<n>\d+) of request with message ID")
RE_AUTH = re.compile(r"authentication of '[^']*'(?: \(myself\))? with (?P<how>.+?)(?: successful| failed|$)")
RE_NOTIFY_ERR = re.compile(r"received (?P<n>[A-Z_]+) notify error")
RE_LIFETIME = re.compile(r"maximum IKE_SA lifetime (?P<s>\d+)s")
UNIQUE_ID = re.compile(r"IKE_SA \S+\[(?P<uid>\d+)\]")
RE_PKT = re.compile(r"(?P<dir>received|sending) packet: from (?P<a>[0-9a-fA-F:.]+)\[\d+\] to (?P<b>[0-9a-fA-F:.]+)\[\d+\]")
RE_START = re.compile(r"Starting IKE charon daemon")


def _auth_name(how: str) -> str:
    h = how.lower()
    if "pre-shared" in h or "psk" in h:
        return "PSK"
    if "eap" in h:
        return "EAP"
    if "rsa" in h or "ecdsa" in h or "signature" in h or "dsa" in h:
        return "Digital signature"
    return how.strip()[:40]


def parse_log(text: str | bytes | Path, *, year: int | None = None) -> ParsedLog:
    if isinstance(text, Path):
        text = text.read_bytes()
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    year = year or datetime.now(timezone.utc).year
    sas: dict[tuple[int, int], _Sa] = {}
    thread_uid: dict[str, tuple[int, int]] = {}
    epoch, total, matched, first_ts, last_ts, last_known = 0, 0, 0, 0.0, 0.0, 0.0
    pending: dict[str, list[tuple[float, str]]] = {}

    for raw in text.splitlines():
        total += 1
        if total > _MAX_LINES:
            break
        m = LINE.search(raw)
        if not m:
            continue
        matched += 1
        ts = _ts(raw, year)
        if ts is None:
            ts = last_known
        else:
            last_known = ts
        first_ts = first_ts or ts
        last_ts = max(last_ts, ts)
        thread, msg = m["thread"], m["msg"]
        if RE_START.search(msg):
            epoch += 1
            thread_uid.clear()
            continue
        tag = TAG.match(msg)
        starts = RE_IS_INITIATING.search(msg) if not tag else None
        if starts:  # a responder's "<ip> is initiating an IKE_SA" precedes the unique id and opens a new SA on this thread
            thread_uid.pop(thread, None)
            pending.setdefault(thread, []).append((ts, msg))
            continue
        if tag:
            key = (epoch, int(tag["uid"]))
            msg = msg[tag.end():]
        elif (um := UNIQUE_ID.search(msg)):
            key = (epoch, int(um["uid"]))
        else:
            key = thread_uid.get(thread)
        if key is None:  # lines logged before the SA has an id (packet in, parsed message): replay them once it has
            buf = pending.setdefault(thread, [])
            if len(buf) < 50:
                buf.append((ts, msg))
            continue
        thread_uid[thread] = key
        sa = sas.get(key)
        if sa is None:
            sa = sas[key] = _Sa(key)
            for pts, pmsg in pending.pop(thread, []):
                _apply(sa, pmsg, pts)
                sa.first_ts = sa.first_ts or pts
        sa.lines += 1
        sa.first_ts = sa.first_ts or ts
        sa.last_ts = ts
        _apply(sa, msg, ts)

    return _finish(sas, total, matched, first_ts, last_ts, epoch)


def _apply(sa: _Sa, msg: str, ts: float) -> None:
    if (m := RE_INITIATING.search(msg)):
        sa.role, sa.remote = "initiator", m["ip"]
        if m["mode"]:
            sa.mode, sa.version = m["mode"], 1
    elif (m := RE_IS_INITIATING.search(msg)):
        sa.role, sa.remote = "responder", m["ip"]
        if m["mode"]:
            sa.mode, sa.version = m["mode"], 1
    if (m := RE_PKT.search(msg)):  # received: from remote to local; sending: from local to remote
        recv = m["dir"] == "received"
        sa.local = sa.local or (m["b"] if recv else m["a"])
        sa.remote = sa.remote or (m["a"] if recv else m["b"])
    if (m := RE_MODE.search(msg)):
        ex = m["ex"]
        if ex in ("IKE_SA_INIT", "IKE_AUTH"):
            sa.mode, sa.version = "IKEv2", 2
        elif ex == "ID_PROT" and sa.mode is None:
            sa.mode, sa.version = "Main Mode", 1
        elif ex == "AGGRESSIVE":
            sa.mode, sa.version = "Aggressive Mode", 1
    if msg.startswith("received proposals:"):
        sa.offered_received += _suites(msg.split(":", 1)[1], "IKE")
    elif msg.startswith("configured proposals:"):
        sa.offered_configured += _suites(msg.split(":", 1)[1], "IKE")
    elif msg.startswith("selected proposal:"):
        body = msg.split(":", 1)[1].strip()
        head = body.split(":", 1)[0]
        if head == "IKE" and sa.chosen is None:
            sa.chosen = parse_suite(body.split(":", 1)[1])
        elif head == "ESP":
            sa.pending_esp.append(parse_suite(body.split(":", 1)[1]))
    elif (m := RE_LIFETIME.search(msg)):
        sa.lifetime = int(m["s"])
    elif (m := RE_ESTABLISHED.search(msg)):
        sa.established, sa.local, sa.remote = True, m["l"], m["r"]
    elif (m := RE_CHILD.search(msg)):
        suite = sa.pending_esp.pop(0) if sa.pending_esp else Suite()
        if not suite.encr and not suite.integ:
            sa.notes.append("child SA proposal was not logged (needs cfg = 2); its algorithms were not assessed")
        first = not sa.children
        v1 = sa.version == 1
        sa.children.append(ChildSa(
            protocol="ESP", via="Quick Mode" if v1 else ("IKE_AUTH" if first else "CREATE_CHILD_SA"), ts=ts, suite=suite,
            spi_initiator=(m["i"] if sa.role == "initiator" else m["o"]).lower(),
            spi_responder=(m["o"] if sa.role == "initiator" else m["i"]).lower(),
            pfs=bool(suite.dh), dh_offered=bool(suite.dh), rekey=not first))
        if not first:
            sa.child_rekeys += 1
    elif (m := RE_RETX.search(msg)):
        sa.retransmits += 1
        sa.streak = max(sa.streak, int(m["n"]))
    elif (m := RE_AUTH.search(msg)):
        sa.auth = sa.auth or _auth_name(m["how"])
    elif (m := RE_NOTIFY_ERR.search(msg)):
        sa.failure = sa.failure or m["n"]
    elif "giving up after" in msg and "retransmit" in msg:
        sa.failure = sa.failure or "NO_RESPONSE"
    elif "received proposals inacceptable" in msg or "no acceptable proposal found" in msg or "no proposal found" in msg:
        sa.failure = sa.failure or "NO_PROPOSAL_CHOSEN"
    elif "tried" in msg and "shared key" in msg and "MAC mismatched" in msg:
        sa.failure = sa.failure or "AUTHENTICATION_FAILED"
    elif re.search(r"authentication of '[^']*' with .* failed", msg):
        sa.failure = sa.failure or "AUTHENTICATION_FAILED"
    elif "rekeying IKE_SA" in msg or "IKE_SA rekeyed" in msg:
        sa.ike_rekeys += 1 if "IKE_SA rekeyed" in msg else 0
    elif "DPD" in msg and "sending" in msg:
        sa.dpd += 1


def _finish(sas: dict, total: int, matched: int, first_ts: float, last_ts: float, epochs: int) -> ParsedLog:
    tunnels: list[Tunnel] = []
    skipped = 0
    for sa in sorted(sas.values(), key=lambda s: (s.first_ts, s.key)):
        outcome = sa.established or sa.failure
        if not (sa.chosen or sa.offered_received or sa.offered_configured or outcome):
            skipped += 1
            continue
        local, remote = sa.local or "?", sa.remote or "?"
        init, resp = (local, remote) if sa.role != "responder" else (remote, local)
        offered = sa.offered_configured if sa.role == "initiator" and sa.offered_configured else (sa.offered_received or sa.offered_configured)
        version = sa.version or (2 if sa.mode == "IKEv2" else 2)
        mode = sa.mode or "IKEv2"
        chosen = sa.chosen
        if chosen and version == 1 and sa.lifetime:
            chosen.lifetime_s = sa.lifetime
        status = "established" if sa.established else ("failed" if sa.failure else "incomplete")
        t = Tunnel(
            id=f"log-{sa.key[0]}-{sa.key[1]}", ike_version=version, exchange_mode=mode, initiator=init, responder=resp,
            ispi="", rspi="", natt=False, first_ts=sa.first_ts, last_ts=sa.last_ts, status=status, failure=sa.failure,
            offered=offered, chosen=chosen, auth_method=sa.auth, auth_observable=sa.auth is not None,
            child_sas=sa.children, child_observable=True, ike_rekeys=sa.ike_rekeys, child_rekeys=sa.child_rekeys,
            retransmits=sa.retransmits, max_retransmit_streak=sa.streak, dpd_messages=sa.dpd, msg_count=sa.lines,
            handshake_duration_s=max(0.0, sa.last_ts - sa.first_ts), decrypted=True,
            notes=["Derived from a strongSwan daemon log, not from packets."] + sa.notes)
        tunnels.append(t)
    _link_prior_attempts(tunnels)
    tunnels.sort(key=lambda t: (t.first_ts, t.id))
    return ParsedLog(tunnels, total, matched, first_ts, last_ts, epochs, skipped)


def _link_prior_attempts(tunnels: list[Tunnel]) -> None:
    """Earlier failed attempts between the same two endpoints (what the downgrade rule reads)."""
    for i, t in enumerate(tunnels):
        for prev in tunnels[:i]:
            same = {prev.initiator, prev.responder} == {t.initiator, t.responder}
            if same and prev.status == "failed" and 0 <= t.first_ts - prev.last_ts <= _PRIOR_WINDOW_S:
                t.prior_attempts.append(AttemptSummary(prev.id, prev.first_ts, prev.status, prev.failure, prev.offered, prev.chosen))


def looks_like_charon(head: bytes) -> bool:
    """Cheap upload check: does the first chunk contain at least one charon-style line?"""
    return any(LINE.search(line) for line in head.decode("utf-8", errors="replace").splitlines())


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python -m ipsec_analyzer.ingest.charon <charon.log>")
        return 2
    res = parse_log(Path(argv[0]))
    print(f"{res.lines_matched}/{res.lines_total} charon lines, {len(res.tunnels)} IKE SA(s), {res.skipped_sas} skipped")
    for t in res.tunnels:
        print(f"  {t.id}: IKEv{t.ike_version} {t.exchange_mode} {t.initiator} -> {t.responder} {t.status}"
              f"{' (' + t.failure + ')' if t.failure else ''} ike={t.chosen.label() if t.chosen else '-'} "
              f"children={[c.suite.label() for c in t.child_sas]}")
    return 0 if res.tunnels else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
