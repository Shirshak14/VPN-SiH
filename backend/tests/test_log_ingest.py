"""strongSwan log ingestion, the watched folder and the UDP syslog listener (fixtures are hand-written; see ingest/charon.py)."""
import importlib
import json
import os
import shutil
import socket
import time
from pathlib import Path

import pytest

from ipsec_analyzer.ingest.charon import looks_like_charon, parse_log, parse_suite
from ipsec_analyzer.ingest.syslog_udp import SyslogListener
from ipsec_analyzer.ingest.watch import Settings, Watcher
from ipsec_analyzer.pipeline import analyze_log
from ipsec_analyzer.rules import RuleEngine

LOGS = Path(__file__).resolve().parents[2] / "data" / "logs"
GATEWAY, INITIATOR = LOGS / "strongswan_gateway.log", LOGS / "strongswan_initiator_filelog.log"


def _by_peer(res, ip):
    return [t for t in res.tunnels if ip in (t.initiator, t.responder)]


# ------------------------------------------------------------------ parsing
def test_parse_suite_names_match_the_policy_spelling():
    s = parse_suite("AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048")
    assert (s.encr, s.encr_bits, s.integ, s.prf, s.dh) == ("AES_CBC", 256, "HMAC_SHA2_256_128", "HMAC_SHA2_256", "MODP_2048")
    g = parse_suite("AES_GCM_16_256/NO_EXT_SEQ")
    assert (g.encr, g.encr_bits, g.integ, g.esn) == ("AES_GCM_16", 256, None, "NO_EXT_SEQ")
    assert parse_suite("3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024").encr == "3DES"
    assert parse_suite("CHACHA20_POLY1305_256/PRF_HMAC_SHA2_256/CURVE_25519").encr == "CHACHA20_POLY1305"
    assert parse_suite("AES_CBC_128/ECP_256_BP").dh == "BRAINPOOL_P256"


def test_gateway_log_yields_one_tunnel_per_ike_sa_with_roles_and_suites():
    p = parse_log(GATEWAY, year=2026)
    assert (p.lines_total, p.lines_matched, len(p.tunnels), p.skipped_sas) == (76, 76, 6, 0)
    ok = _by_peer(p, "203.0.113.10")[0]
    assert (ok.initiator, ok.responder, ok.ike_version, ok.status, ok.auth_method) == ("203.0.113.10", "198.51.100.1", 2, "established", "PSK")
    assert ok.chosen.label() == "AES_GCM_16-256/HMAC_SHA2_384/ECP_384"
    assert [c.via for c in ok.child_sas] == ["IKE_AUTH", "CREATE_CHILD_SA"] and [c.pfs for c in ok.child_sas] == [False, True]
    assert len(ok.offered) == 2 and ok.child_rekeys == 1
    agg = _by_peer(p, "192.0.2.99")[0]
    assert (agg.ike_version, agg.exchange_mode, agg.chosen.lifetime_s) == (1, "Aggressive Mode", 172800)
    assert [c.via for c in agg.child_sas] == ["Quick Mode"]


def test_failures_and_downgrade_retry_are_linked():
    p = parse_log(GATEWAY, year=2026)
    failed, retry = _by_peer(p, "192.0.2.77")
    assert (failed.status, failed.failure, retry.status) == ("failed", "NO_PROPOSAL_CHOSEN", "established")
    assert [a.failure for a in retry.prior_attempts] == ["NO_PROPOSAL_CHOSEN"]
    bad_auth = _by_peer(p, "203.0.113.55")[0]
    assert (bad_auth.status, bad_auth.failure) == ("failed", "AUTHENTICATION_FAILED")


def test_initiator_filelog_counts_retransmits_and_reads_untagged_timestamps():
    p = parse_log(INITIATOR, year=2026)
    (t,) = p.tunnels
    assert (t.initiator, t.responder, t.retransmits, t.max_retransmit_streak, t.auth_method) == ("192.0.2.10", "198.51.100.1", 3, 3, "Digital signature")
    assert 25 < t.last_ts - t.first_ts < 35  # 09:00:05 -> 09:00:36 in the file


def test_iso_timestamps_and_daemon_restart_do_not_merge_sas():
    log = (
        "2026-10-19T09:00:00+00:00 00[DMN] Starting IKE charon daemon (strongSwan 5.9.8)\n"
        "2026-10-19T09:00:01+00:00 05[CFG] <1> selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048\n"
        "2026-10-19T09:00:02+00:00 05[IKE] <a|1> IKE_SA a[1] established between 10.0.0.1[x]...10.0.0.2[y]\n"
        "2026-10-19T09:10:00+00:00 00[DMN] Starting IKE charon daemon (strongSwan 5.9.8)\n"
        "2026-10-19T09:10:01+00:00 05[CFG] <1> selected proposal: IKE:3DES_CBC/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_1024\n"
        "2026-10-19T09:10:02+00:00 05[IKE] <a|1> IKE_SA a[1] established between 10.0.0.1[x]...10.0.0.2[y]\n")
    p = parse_log(log)
    assert [t.chosen.encr for t in p.tunnels] == ["AES_CBC", "3DES"] and p.daemon_starts == 2
    assert p.tunnels[1].first_ts - p.tunnels[0].first_ts == 600


def test_garbage_and_truncated_input_never_crash():
    assert parse_log("").tunnels == [] and parse_log("hello\nworld\n").lines_matched == 0
    cut = GATEWAY.read_text()[:1234]
    parse_log(cut)  # a log cut mid-line still parses what is there
    parse_log("\x00\xff" * 500 + "12[IKE] <9> IKE_SA x[9] established between ...")
    assert looks_like_charon(b"Oct 19 09:00:00 gw1 charon: 07[IKE] hello") and not looks_like_charon(b"just some text\n")


# ------------------------------------------------------------------ rules on log-derived tunnels
def test_rules_fire_from_a_log_exactly_as_they_do_from_a_capture():
    res = analyze_log(GATEWAY, RuleEngine())
    viol = {t.tunnel.id: {f.rule_id for f in t.findings if f.category == "violation"} for t in res.tunnels}
    by = {i: v for i, v in viol.items()}
    ok = next(t for t in res.tunnels if t.tunnel.initiator == "203.0.113.10")
    assert by[ok.tunnel.id] == set() and ok.risk.score == 0
    weak = next(t for t in res.tunnels if t.tunnel.initiator == "203.0.113.20")
    assert {"IKE-ENC-WEAK", "IKE-DH-WEAK", "SA-DOWNGRADE", "ESP-ENC-WEAK", "ESP-NO-PFS"} <= by[weak.tunnel.id]
    ev = next(f for f in weak.findings if f.rule_id == "SA-DOWNGRADE").evidence
    assert "offered_compliant_suite" in ev
    retry = next(t for t in res.tunnels if t.tunnel.responder == "198.51.100.1" and t.tunnel.initiator == "192.0.2.77" and t.tunnel.status == "established")
    assert "prior_attempt" in next(f for f in retry.findings if f.rule_id == "SA-DOWNGRADE").evidence
    aggr = next(t for t in res.tunnels if t.tunnel.initiator == "192.0.2.99")
    assert {"IKE-AGGR-PSK", "IKE-V1-LEGACY", "IKE-LIFETIME-LONG"} <= by[aggr.tunnel.id]
    assert all(t.anomaly is None for t in res.tunnels)
    assert all(any(f.rule_id == "COV-LOG-SOURCE" for f in t.findings) for t in res.tunnels)
    assert res.tunnels == sorted(res.tunnels, key=lambda t: -t.risk.score)


def test_a_log_without_charon_lines_is_rejected(tmp_path):
    p = tmp_path / "x.log"
    p.write_text("nothing to see\n" * 10)
    with pytest.raises(ValueError):
        analyze_log(p, RuleEngine())


@pytest.mark.skipif(not list((LOGS.parent / "captures" / "lab").glob("*.charon.log")), reason="no real lab logs saved (python lab/generate.py)")
def test_real_lab_logs_agree_with_the_lab_manifest():
    man = json.loads((LOGS.parent / "captures" / "lab" / "manifest.json").read_text())
    for f in (LOGS.parent / "captures" / "lab").glob("*.charon.log"):
        res = analyze_log(f, RuleEngine())
        assert res.tunnels, f.name
        assert man[f.name.removesuffix(".charon.log")]


# ------------------------------------------------------------------ watched folder
class _Fake:
    def __init__(self):
        self.calls, self.alive, self.next = [], set(), 1

    def ingest(self, path, keys, kind, existing, rel, prov):
        self.calls.append((rel, kind, existing, prov, keys.name if keys else None))
        aid = existing or self.next
        self.next += existing is None
        self.alive.add(aid)
        return aid, None

    def prune(self, ids):
        self.alive -= set(ids)
        return ids


def _watcher(tmp_path, **kw):
    f = _Fake()
    s = Settings(tmp_path / "w", 1, 5, kw.get("keep", 100), 10 * 2**20, 30)
    (tmp_path / "w").mkdir(exist_ok=True)
    return f, Watcher([(tmp_path / "w", "watch-folder")], tmp_path / "state.json", f.ingest, lambda i: i in f.alive, f.prune, s)


def test_watcher_waits_for_a_file_to_settle_then_analyses_it_once(tmp_path):
    f, w = _watcher(tmp_path)
    log = tmp_path / "w" / "gw.log"
    log.write_text(GATEWAY.read_text())
    assert w.scan_once(now=0) == 0 and w.scan_once(now=3) == 0  # seen, not yet settled
    assert w.scan_once(now=6) == 1 and w.scan_once(now=60) == 0
    assert f.calls == [("gw.log", "log", None, "watch-folder", None)]


def test_a_changed_file_updates_its_analysis_in_place(tmp_path):
    f, w = _watcher(tmp_path)
    log = tmp_path / "w" / "gw.log"
    log.write_text(GATEWAY.read_text())
    w.scan_once(now=0)
    w.scan_once(now=6)
    log.write_text(GATEWAY.read_text() + INITIATOR.read_text())
    w.scan_once(now=10)
    assert w.scan_once(now=16) == 1
    assert [c[2] for c in f.calls] == [None, 1] and f.next == 2  # second run refreshed analysis 1


def test_busy_log_is_refreshed_without_ever_going_quiet(tmp_path):
    f, w = _watcher(tmp_path)
    log = tmp_path / "w" / "gw.log"
    log.write_text(GATEWAY.read_text())
    w.scan_once(now=0)
    w.scan_once(now=6)
    for i, now in enumerate((8, 16, 24, 32, 40)):  # grows every scan, so it never settles
        log.write_text(log.read_text() + INITIATOR.read_text())
        w.scan_once(now=now)
    assert len(f.calls) >= 2 and all(c[2] == 1 for c in f.calls[1:])


def test_deleted_analysis_is_not_recreated_until_the_file_changes(tmp_path):
    f, w = _watcher(tmp_path)
    log = tmp_path / "w" / "gw.log"
    log.write_text(GATEWAY.read_text())
    w.scan_once(now=0)
    w.scan_once(now=6)
    f.alive.clear()  # the user deleted it
    assert w.scan_once(now=100) == 0
    log.write_text(GATEWAY.read_text() + "\n")
    w.scan_once(now=101)
    assert w.scan_once(now=110) == 1 and f.calls[-1][2] is None


def test_unreadable_files_are_reported_once_and_not_retried(tmp_path):
    f, w = _watcher(tmp_path)
    (tmp_path / "w" / "bad.pcap").write_bytes(b"not a capture")
    (tmp_path / "w" / "notes.txt").write_text("hello")
    (tmp_path / "w" / ".hidden.log").write_text(GATEWAY.read_text())
    (tmp_path / "w" / "half.log.part").write_text(GATEWAY.read_text())
    w.scan_once(now=0)
    assert w.scan_once(now=6) == 0 and w.scan_once(now=60) == 0
    assert f.calls == [] and {e["path"] for e in w.errors} == {"bad.pcap", "notes.txt"}
    assert all(r["error"] for r in w.state.values())


def test_sibling_keys_file_is_passed_with_a_capture_and_state_survives_restart(tmp_path):
    f, w = _watcher(tmp_path)
    cap = Path(__file__).resolve().parents[2] / "data/captures/synthetic/demo_gateway_audit"
    if not cap.with_suffix(".pcap").exists():
        pytest.skip("run `python -m synth.generate` first")
    (tmp_path / "w" / "a.pcap").write_bytes(cap.with_suffix(".pcap").read_bytes())
    (tmp_path / "w" / "a.keys").write_bytes(cap.with_suffix(".keys").read_bytes())
    w.scan_once(now=0)
    assert w.scan_once(now=6) == 1 and f.calls[0][4] == "a.keys"
    f2, w2 = _watcher(tmp_path)
    f2.alive.add(1)
    w2.scan_once(now=0)
    assert w2.scan_once(now=6) == 0  # same signature as recorded: nothing to redo after a restart


def test_oldest_analyses_are_pruned(tmp_path):
    f, w = _watcher(tmp_path, keep=2)
    for n in range(4):
        (tmp_path / "w" / f"g{n}.log").write_text(GATEWAY.read_text())
    w.scan_once(now=0)
    w.scan_once(now=6)
    assert f.alive == {3, 4}


# ------------------------------------------------------------------ syslog over UDP (real sockets on localhost)
def _send(port, *lines):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for ln in lines:
        s.sendto(ln.encode(), ("127.0.0.1", port))
    s.close()


def test_syslog_listener_stores_only_charon_lines_per_source(tmp_path):
    lst = SyslogListener("127.0.0.1", 0, tmp_path / "sl")
    port = lst.start()
    try:
        _send(port, "<30>Oct 19 09:00:10 gw1 charon-systemd[812]: 07[IKE] <1> IKE_SA a[1] established between 10.0.0.1[x]...10.0.0.2[y]",
              "<30>Oct 19 09:00:11 gw1 sshd[1]: Accepted password for root", "<30>Oct 19 09:00:12 gw1 charon: 07[CFG] <1> selected proposal: IKE:AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048")
        for _ in range(50):
            if lst.status()["sources"] and lst.status()["sources"][0]["lines"] == 2 and lst.ignored == 1:
                break
            time.sleep(0.05)
        st = lst.status()
        assert st["ignored"] == 1 and st["sources"][0]["source"] == "127.0.0.1" and st["sources"][0]["lines"] == 2
        text = (tmp_path / "sl" / "127.0.0.1.log").read_text()
        assert text.count("\n") == 2 and "<30>" not in text and "sshd" not in text and text.startswith("20")
        p = parse_log(text)  # what the listener wrote is what the parser reads, receive-time stamped
        assert len(p.tunnels) == 1 and p.tunnels[0].chosen.encr == "AES_CBC"
    finally:
        lst.stop()


def test_syslog_allow_list_rotation_and_source_cap(tmp_path):
    lst = SyslogListener("127.0.0.1", 0, tmp_path / "sl", allow=[__import__("ipaddress").ip_network("10.9.0.0/16")], max_bytes=2000)
    line = "07[IKE] <1> IKE_SA a[1] established between 10.0.0.1[x]...10.0.0.2[y]"
    assert not lst.handle(line.encode(), "127.0.0.1") and lst.ignored == 1
    for _ in range(100):
        assert lst.handle(line.encode(), "10.9.1.1")
    p = tmp_path / "sl" / "10.9.1.1.log"
    assert 0 < p.stat().st_size <= 2000 and p.read_text().endswith("\n") and all(x.startswith("20") for x in p.read_text().splitlines())
    open_ = SyslogListener("127.0.0.1", 0, tmp_path / "sl2")
    for n in range(80):
        open_.handle(line.encode(), f"10.1.{n // 250}.{n % 250}")
    assert len(open_.sources) == 64  # excess sources are dropped, not allowed to fill the disk
    v6 = SyslogListener("127.0.0.1", 0, tmp_path / "sl3")
    v6.handle(line.encode(), "fe80::1%eth0")
    assert [x.name for x in (tmp_path / "sl3").iterdir()] == ["fe80_1_eth0.log"]


# ------------------------------------------------------------------ through the API
@pytest.fixture()
def live_client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    monkeypatch.setenv("WATCH_DIR", str(tmp_path / "watch"))
    monkeypatch.setenv("WATCH_INTERVAL_S", "0.2")
    monkeypatch.setenv("WATCH_STABLE_S", "0.4")
    monkeypatch.setenv("SYSLOG_LISTEN", "127.0.0.1:0")
    (tmp_path / "watch").mkdir()
    shutil.copytree(LOGS, tmp_path / "data" / "logs")
    from fastapi.testclient import TestClient
    from ipsec_analyzer.api import db, live, main, service
    for m in (db, service, live, main):
        importlib.reload(m)
    with TestClient(main.app) as c:
        yield c, tmp_path, live


def _wait_done(c, aid, secs=20):
    for _ in range(int(secs / 0.2)):
        a = c.get(f"/api/analyses/{aid}").json()
        if a["status"] in ("done", "failed"):
            return a
        time.sleep(0.2)
    raise AssertionError("timeout")


def test_log_upload_endpoint_and_reports(live_client):
    c, _tmp, _live = live_client
    assert c.post("/api/logs", files={"log": ("x.log", b"nothing here\n")}).status_code == 400
    r = c.post("/api/logs", files={"log": ("gw.log", GATEWAY.read_bytes())})
    assert r.status_code == 202
    a = _wait_done(c, r.json()["id"])
    assert a["status"] == "done" and a["summary"]["source"] == "log" and a["summary"]["tunnel_count"] == 6 and a["summary"]["log"]["ike_sas"] == 6
    ts = c.get(f"/api/analyses/{a['id']}/tunnels").json()
    assert ts[0]["risk"]["score"] >= 90 and any(t["violations"] == [] for t in ts)
    detail = c.get(f"/api/analyses/{a['id']}/tunnels/{ts[0]['id']}").json()
    assert detail["tunnel"]["timeline"] == [] and detail["anomaly"] is None
    assert c.get(f"/api/analyses/{a['id']}/report.pdf").content.startswith(b"%PDF")
    assert "CEF:0" in c.get(f"/api/analyses/{a['id']}/export.syslog").text
    assert c.get(f"/api/analyses/{a['id']}/remediation").json()


def test_bundled_log_samples_are_listed_and_analysable(live_client):
    c, _t, _l = live_client
    names = {s["name"]: s for s in c.get("/api/samples").json()}
    assert names["strongswan_gateway.log"]["kind"] == "log" and names["strongswan_gateway.log"]["provenance"] == "sample-log"
    r = c.post("/api/samples/strongswan_initiator_filelog.log/analyze")
    assert _wait_done(c, r.json()["id"])["summary"]["tunnel_count"] == 1


def test_watch_folder_and_syslog_end_to_end(live_client):
    c, tmp, live = live_client
    (tmp / "watch" / "gw.log").write_text(GATEWAY.read_text())
    deadline = time.time() + 20
    rows = []
    while time.time() < deadline and not rows:
        time.sleep(0.3)
        rows = [a for a in c.get("/api/analyses").json() if a["provenance"] == "watch-folder" and a["status"] == "done"]
    assert rows and rows[0]["filename"] == "gw.log" and rows[0]["summary"]["tunnel_count"] == 6
    st = c.get("/api/ingest/status").json()
    assert st["watch"]["enabled"] and st["watch"]["files"][0]["analysis_id"] == rows[0]["id"]
    # a rotating log grows: the same analysis is refreshed, not duplicated
    (tmp / "watch" / "gw.log").write_text(GATEWAY.read_text() + INITIATOR.read_text().replace("<branch|1>", "<9>"))
    deadline = time.time() + 20
    while time.time() < deadline:
        time.sleep(0.3)
        mine = [a for a in c.get("/api/analyses").json() if a["filename"] == "gw.log"]
        if mine and mine[0]["status"] == "done" and mine[0]["summary"]["tunnel_count"] == 7:
            break
    assert len(mine) == 1 and mine[0]["summary"]["tunnel_count"] == 7
    # live syslog: send the gateway log over UDP, one datagram per line
    port = live.listener.port
    _send(port, *[f"<30>{ln}" for ln in GATEWAY.read_text().splitlines()])
    deadline = time.time() + 30
    live_rows = []
    while time.time() < deadline and not live_rows:
        time.sleep(0.4)
        live_rows = [a for a in c.get("/api/analyses").json() if a["provenance"] == "live-syslog" and a["status"] == "done"]
    assert live_rows and live_rows[0]["summary"]["tunnel_count"] == 6
    assert c.get("/api/ingest/status").json()["syslog"]["sources"][0]["lines"] == 76


def test_ingest_status_is_disabled_by_default(tmp_path, monkeypatch):
    for k in ("WATCH_DIR", "SYSLOG_LISTEN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    from fastapi.testclient import TestClient
    from ipsec_analyzer.api import db, live, main, service
    for m in (db, service, live, main):
        importlib.reload(m)
    with TestClient(main.app) as c:
        assert c.get("/api/ingest/status").json() == {"watch": {"enabled": False}, "syslog": {"enabled": False}}
