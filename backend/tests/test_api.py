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
    detail = client.get(f"/api/analyses/{a['id']}/tunnels/{tunnels[0]['id']}").json()
    assert detail["findings"] and detail["tunnel"]["timeline"]
    assert client.get(f"/api/analyses/{a['id']}/report.pdf").content.startswith(b"%PDF")
    assert "CEF:0" in client.get(f"/api/analyses/{a['id']}/export.syslog").text
    assert client.get(f"/api/analyses/{a['id']}/remediation").json()


def test_unknown_analysis_404(client):
    assert client.get("/api/analyses/99999").status_code == 404
