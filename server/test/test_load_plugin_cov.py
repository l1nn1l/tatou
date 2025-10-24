"""
Coverage tests for /api/load-plugin route in server.py.
Simulates plugin loading from STORAGE_DIR/files/plugins/<filename>.
"""

import io
import os
import pickle
import pytest
from pathlib import Path
from flask import Flask

os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"

import server
import pickle

class DummyPlugin:
    name = "dummy-method"
    def add_watermark(self, *a, **kw): return b"%PDF"
    def read_secret(self, *a, **kw): return "secret"


@pytest.fixture
def client(monkeypatch, tmp_path):
    """Return a Flask test client with auth bypassed and temp storage dir."""
    monkeypatch.setattr("server.require_auth", lambda f: f)
    server.app.config["STORAGE_DIR"] = tmp_path
    return server.app.test_client()


# --- Tests ---


def test_load_plugin_missing_filename(client):
    """Missing filename should return 400."""
    resp = client.post("/api/load-plugin", json={})
    assert resp.status_code == 400
    assert "filename" in resp.get_data(as_text=True)


def test_load_plugin_file_not_found(client, tmp_path):
    """Nonexistent plugin file should return 404."""
    plugins_dir = tmp_path / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    resp = client.post("/api/load-plugin", json={"filename": "nope.pkl"})
    assert resp.status_code == 404 or "not found" in resp.get_data(as_text=True)


def test_load_plugin_bad_pickle(client, tmp_path):
    """Corrupt pickle file should yield 400."""
    plugins_dir = tmp_path / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    bad_path = plugins_dir / "broken.pkl"
    bad_path.write_bytes(b"not a pickle")

    resp = client.post("/api/load-plugin", json={"filename": "broken.pkl"})
    assert resp.status_code in (400, 422)
    assert "deserialize" in resp.get_data(as_text=True) or "failed" in resp.get_data(as_text=True)


