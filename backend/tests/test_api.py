"""API smoke tests against a real analysis of the bundled demo capture (SQLite, no mocks)."""
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(not (ROOT / "data/captures/synthetic/demo_gateway_audit.pcap").exists(),
                                reason="run `python -m synth.generate` first")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os
    os.environ["DATA_DIR"] = str(tmp_path_factory.mktemp("data"))
    os.environ["DATABASE_URL"] = f"sqlite:///{os.environ['DATA_DIR']}/t.db"
    import importlib
    from ipsec_analyzer.api import db, main
    importlib.reload(db)
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def _wait(client, aid):
    for _ in range(120):
        a = client.get(f"/api/analyses/{aid}").json()
        if a["status"] in ("done", "failed"):
            return a
        time.sleep(0.25)
    raise AssertionError("timeout")


def test_upload_rejects_non_pcap(client):
    r = client.post("/api/analyses", files={"pcap": ("x.pcap", b"not a pcap at all")})
    assert r.status_code == 400


def test_pcap_upload_end_to_end(client):
    pcap = ROOT / "data/captures/synthetic/demo_gateway_audit.pcap"
    keys = ROOT / "data/captures/synthetic/demo_gateway_audit.keys"
    r = client.post("/api/analyses", files={"pcap": ("demo.pcap", pcap.read_bytes()), "keys": ("k.txt", keys.read_bytes())})
    assert r.status_code == 202
    a = _wait(client, r.json()["id"])
    assert a["status"] == "done" and a["summary"]["tunnel_count"] >= 11
    tunnels = client.get(f"/api/analyses/{a['id']}/tunnels").json()
    assert tunnels == sorted(tunnels, key=lambda t: -t["risk"]["score"])
    ids = {m["id"] for t in tunnels for m in t["mitre"]}
    assert ids and ids == {m for t in tunnels for v in t["violations"] for m in v["mitre"]}
    detail = client.get(f"/api/analyses/{a['id']}/tunnels/{tunnels[0]['id']}").json()
    assert detail["findings"] and detail["tunnel"]["timeline"]
    assert client.get(f"/api/analyses/{a['id']}/report.pdf").content.startswith(b"%PDF")
    assert "CEF:0" in client.get(f"/api/analyses/{a['id']}/export.syslog").text
    assert client.get(f"/api/analyses/{a['id']}/remediation").json()


def test_unknown_analysis_404(client):
    assert client.get("/api/analyses/99999").status_code == 404


def _upload(client, stem):
    d = ROOT / "data/captures/lab"
    files = {"pcap": (f"{stem}.pcap", (d / f"{stem}.pcap").read_bytes())}
    if (d / f"{stem}.keys").exists():
        files["keys"] = ("k.txt", (d / f"{stem}.keys").read_bytes())
    return _wait(client, client.post("/api/analyses", files=files).json()["id"])


def test_compare_weak_vs_fixed(client):
    weak, ok = _upload(client, "weak_des_md5_modp768"), _upload(client, "ok_aes256gcm_ecp384")
    c = client.get(f"/api/compare?before={weak['id']}&after={ok['id']}").json()
    assert c["before_analysis"]["id"] == weak["id"] and c["after_analysis"]["id"] == ok["id"]
    assert c["after"]["max_score"] < c["before"]["max_score"]
    assert c["rules"]["fixed"] and not c["rules"]["new"]
    pair = next(r for r in c["tunnels"] if r["before"] and r["after"])  # same lab peers on both sides
    assert pair["delta"] < 0 and set(pair["fixed"]) == set(pair["before"]["rules"]) - set(pair["after"]["rules"])
    assert client.get(f"/api/compare?before={weak['id']}&after={weak['id']}").status_code == 400
    assert client.get(f"/api/compare?before={weak['id']}&after=99999").status_code == 404


def test_policy_lists_every_rule_with_sources(client):
    p = client.get("/api/policy").json()
    assert p["name"] and len(p["rules"]) >= 10 and set(p["tiers"]) == {"encryption", "integrity", "dh"}
    for r in p["rules"]:
        assert r["description"] and r["refs"] and r["remediation"]["title"]
        assert r["severity"] or r["severity_by_tier"]
        assert [m["id"] for m in r["mitre_detail"]] == r["mitre"] and all(m["url"].startswith("https://attack.mitre.org/") for m in r["mitre_detail"])
