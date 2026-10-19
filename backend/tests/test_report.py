"""Printable HTML report and the upgraded PDF, built from a real analysis of the bundled demo capture."""
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
PCAP = ROOT / "data/captures/synthetic/demo_gateway_audit.pcap"
pytestmark = pytest.mark.skipif(not PCAP.exists(), reason="run `python -m synth.generate` first")


@pytest.fixture(scope="module")
def ctx(tmp_path_factory):
    import importlib
    import os
    os.environ["DATA_DIR"] = str(tmp_path_factory.mktemp("data"))
    os.environ["DATABASE_URL"] = f"sqlite:///{os.environ['DATA_DIR']}/t.db"
    from ipsec_analyzer.api import db, main, service
    importlib.reload(db)
    importlib.reload(service)  # the worker thread writes through service's own SessionLocal, which must point at this test's DB
    importlib.reload(main)
    with TestClient(main.app) as c:
        r = c.post("/api/analyses", files={"pcap": ("demo.pcap", PCAP.read_bytes()), "keys": ("k.txt", PCAP.with_suffix(".keys").read_bytes())})
        aid = r.json()["id"]
        for _ in range(240):
            a = c.get(f"/api/analyses/{aid}").json()
            if a["status"] in ("done", "failed"):
                break
            time.sleep(0.25)
        assert a["status"] == "done"
        yield c, a, [c.get(f"/api/analyses/{aid}/tunnels/{t['id']}").json() for t in c.get(f"/api/analyses/{aid}/tunnels").json()]


def test_html_report_is_self_contained_and_complete(ctx):
    c, a, tunnels = ctx
    r = c.get(f"/api/analyses/{a['id']}/report.html")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "attachment" not in r.headers.get("content-disposition", "")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    h = r.text
    assert not re.search(r'(src|href)="https?://', h) and "<link" not in h  # nothing is fetched, so it works offline and prints anywhere
    for needle in ("Executive summary", "MITRE ATT&amp;CK techniques", "Remediation plan", "Findings per tunnel", "window.print()"):
        assert needle in h
    for t in tunnels:  # every tunnel and every violation is present
        assert t["tunnel"]["id"] in h
        for f in t["findings"]:
            if f["category"] == "violation":
                assert f["rule_id"] in h
    for step in c.get(f"/api/analyses/{a['id']}/remediation").json()[0]["steps"]:
        assert step.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;") in h


def test_html_report_download_and_unknown(ctx):
    c, a, _ = ctx
    r = c.get(f"/api/analyses/{a['id']}/report.html?download=1")
    assert f'filename="ipsec-report-{a["id"]}.html"' in r.headers["content-disposition"]
    assert c.get("/api/analyses/99999/report.html").status_code == 404


def test_html_report_escapes_hostile_values(ctx):
    from ipsec_analyzer.reports.html import build_html
    _, a, tunnels = ctx
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    a = {**a, "filename": evil}
    t0 = tunnels[0]
    tunnels = [{**t0, "findings": [{**f, "title": evil, "description": evil} for f in t0["findings"]]}]
    h = build_html(a, tunnels)
    assert "<script>alert" not in h and "<img src=x" not in h and "&lt;script&gt;alert(1)" in h
    assert h.count("<script") == 0


def test_html_report_handles_empty_capture(ctx):
    from ipsec_analyzer.reports.html import build_html
    _, a, _ = ctx
    h = build_html(a, [])
    assert "No IKE or ESP tunnels" in h and "No violations to remediate" in h


def test_pdf_builds_with_attack_and_plan_sections(ctx):
    c, a, tunnels = ctx
    r = c.get(f"/api/analyses/{a['id']}/report.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF") and len(r.content) > 4000
    from ipsec_analyzer.reports.pdf import build_pdf
    assert build_pdf(a, []).startswith(b"%PDF")  # an empty capture still renders


def test_rollups(ctx):
    from ipsec_analyzer.reports.summary import attack_rollup, remediation_plan
    _, _, tunnels = ctx
    plan, attack = remediation_plan(tunnels), attack_rollup(tunnels)
    assert plan and attack
    assert all(x["tunnels"] <= len(tunnels) for x in attack)
    assert [x["tunnels"] for x in attack] == sorted((x["tunnels"] for x in attack), reverse=True)
    rules = {f["rule_id"] for t in tunnels for f in t["findings"] if f["category"] == "violation"}
    assert {r for p in plan for r in p["rules"]} == rules
