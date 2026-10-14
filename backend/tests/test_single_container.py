"""UI_DIR makes the API also serve the built UI (single-container deployment), without shadowing any /api route."""
import importlib

from fastapi.testclient import TestClient


def test_ui_dir_serves_ui_and_keeps_api(tmp_path, monkeypatch):
    ui = tmp_path / "ui"
    (ui / "assets").mkdir(parents=True)
    (ui / "index.html").write_text("<!doctype html><title>ui</title>")
    (ui / "assets" / "app.js").write_text("console.log(1)")
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/t.db")
    monkeypatch.setenv("UI_DIR", str(ui))
    from ipsec_analyzer.api import db, main
    importlib.reload(db)
    importlib.reload(main)
    try:
        with TestClient(main.app) as c:
            assert "<title>ui</title>" in c.get("/").text
            assert c.get("/assets/app.js").status_code == 200
            assert c.get("/api/health").json()["ok"] is True
            assert c.get("/api/analyses/99999").status_code == 404
    finally:
        monkeypatch.delenv("UI_DIR")
        importlib.reload(main)
