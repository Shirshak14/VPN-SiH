"""Sample gallery: curated cards, with every number computed by the real pipeline."""
import importlib
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(not (ROOT / "data/captures/synthetic/demo_gateway_audit.pcap").exists(), reason="run `python -m synth.generate` first")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os
    os.environ["DATA_DIR"] = str(ROOT / "data")  # the bundled captures live under it; samples are read-only, the database is temporary
    os.environ["DATABASE_URL"] = f"sqlite:///{tmp_path_factory.mktemp('db')}/t.db"
    from ipsec_analyzer.api import db, gallery, main, service
    importlib.reload(db)
    importlib.reload(service)
    importlib.reload(gallery)
    importlib.reload(main)
    with TestClient(main.app) as c:
        yield c


def _cards(client, timeout=90):
    end = time.time() + timeout
    while True:
        cards = client.get("/api/samples").json()
        if all(c["preview"] for c in cards) or time.time() > end:
            return cards
        time.sleep(0.5)


def test_every_card_has_a_story_a_kind_and_a_preview(client):
    cards = _cards(client)
    assert len(cards) >= 5
    assert [c["order"] for c in cards] == sorted(c["order"] for c in cards)
    assert cards[0]["name"] == "demo_gateway_audit"  # the best first click leads
    for c in cards:
        assert c["title"] and c["story"] and c["kind"] in {"tour", "weak", "downgrade", "anomaly", "baseline", "real", "log", "vpn", "config"}
        assert c["preview"], f"{c['name']} was never scored"


def test_preview_equals_the_analysis_it_opens(client):
    cards = _cards(client)
    spread = cards[:6] + [next(c for c in cards if c["kind"] == "vpn"), next(c for c in cards if c["kind"] == "config")]
    for c in spread:  # a spread of real, lab and simulated captures, plus an OpenVPN/WireGuard capture and a configuration file
        a = client.post(f"/api/samples/{c['name']}/analyze").json()
        for _ in range(240):
            a = client.get(f"/api/analyses/{a['id']}").json()
            if a["status"] in ("done", "failed"):
                break
            time.sleep(0.25)
        assert a["status"] == "done"
        tunnels = client.get(f"/api/analyses/{a['id']}/tunnels").json()
        p = c["preview"]
        assert p["tunnels"] == len(tunnels) == a["summary"]["tunnel_count"]
        assert p["top_score"] == max(t["risk"]["score"] for t in tunnels)
        assert p["violations"] == sum(len(t["violations"]) for t in tunnels)
        assert {r["rule_id"] for r in p["rules"]} <= {v["rule_id"] for t in tunnels for v in t["violations"]}


def test_uncurated_samples_still_get_a_card():
    from ipsec_analyzer.api.gallery import describe
    d = describe("new_capture.pcap", "A description", "real-public")
    assert d["title"] == "new_capture.pcap" and d["story"] == "A description" and d["kind"] == "real" and d["preview"] is None


def test_previews_are_not_persisted(client):
    _cards(client)
    before = len(client.get("/api/analyses").json())
    _cards(client)
    assert len(client.get("/api/analyses").json()) == before
