"""
Coverage tests for /api/load-plugin route in server.py.
Simulates plugin loading from STORAGE_DIR/files/plugins/<filename>.
Covers both negative paths and the happy path.
"""

import os
import pytest
from pathlib import Path

# Test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"

import server  # after env vars are set


@pytest.fixture
def client(monkeypatch, tmp_path):
    """
    Flask test client with:
      - auth bypassed
      - STORAGE_DIR pointed to a temp dir
      - WMUtils.METHODS isolated to an empty dict for deterministic assertions
    """
    # Bypass @require_auth
    monkeypatch.setattr("server.require_auth", lambda f: f)

    # Isolate registry
    monkeypatch.setattr("server.WMUtils.METHODS", {}, raising=False)

    # Point storage at temp
    server.app.config["STORAGE_DIR"] = tmp_path

    return server.app.test_client()


# -----------------
# Negative cases
# -----------------

def test_load_plugin_missing_filename(client):
    """Missing filename should return 400 with clear error."""
    resp = client.post("/api/load-plugin", json={})
    assert resp.status_code == 400
    assert "filename is required" in resp.get_data(as_text=True)


def test_load_plugin_file_not_found(client, tmp_path):
    """Nonexistent plugin file should return 404 with a helpful message."""
    plugins_dir = tmp_path / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    resp = client.post("/api/load-plugin", json={"filename": "nope.pkl"})
    assert resp.status_code == 404
    assert "plugin file not found" in resp.get_data(as_text=True)


def test_load_plugin_bad_pickle(client, tmp_path):
    """Corrupt pickle file should yield 400."""
    plugins_dir = tmp_path / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    bad_path = plugins_dir / "broken.pkl"
    bad_path.write_bytes(b"not a pickle")

    resp = client.post("/api/load-plugin", json={"filename": "broken.pkl"})
    assert resp.status_code == 400
    txt = resp.get_data(as_text=True).lower()
    assert "failed to deserialize" in txt or "deserialize" in txt


# -----------------
# Happy path
# -----------------

def test_load_plugin_happy_path(client, tmp_path):
    """
    Valid pickle (of a class) should load, register in WMUtils.METHODS,
    and return 201 with structured JSON.

    Your WatermarkingMethod base is abstract and requires:
      - add_watermark
      - read_secret
      - get_usage
      - is_watermark_applicable
    Implement all of them so cls() succeeds.
    """

    class DummyPluginOK(server.WatermarkingMethod):
        name = "dummy-method"

        def __init__(self):
            # Keep it no-arg so server can do cls() without parameters.
            # Don't call super().__init__() if it expects args.
            pass

        # Required abstract methods / API
        def add_watermark(self, *a, **kw):
            return b"%PDF"  # any bytes

        def read_secret(self, *a, **kw):
            return "secret"

        def get_usage(self) -> str:
            return "dummy usage text"

        def is_watermark_applicable(self, *a, **kw) -> bool:
            return True

    # Ensure plugins dir exists under STORAGE_DIR/files/plugins
    plugins_dir = tmp_path / "files" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)

    # Pickle the CLASS using the same loader server uses (dill if available, else pickle)
    plugin_path = plugins_dir / "dummy.pkl"
    with plugin_path.open("wb") as f:
        server._pickle.dump(DummyPluginOK, f)

    # Sanity: registry empty before
    assert server.WMUtils.METHODS == {}

    # Call the endpoint
    resp = client.post("/api/load-plugin", json={"filename": plugin_path.name})
    assert resp.status_code in (200, 201), resp.data
    data = resp.get_json()
    assert isinstance(data, dict)
    assert data.get("loaded") is True
    assert data.get("registered_as") == "dummy-method"
    assert isinstance(data.get("methods_count"), int)

    # The plugin should be present and implement the API
    assert "dummy-method" in server.WMUtils.METHODS
    inst = server.WMUtils.METHODS["dummy-method"]
    assert callable(getattr(inst, "add_watermark", None))
    assert callable(getattr(inst, "read_secret", None))
    assert callable(getattr(inst, "get_usage", None))
    assert callable(getattr(inst, "is_watermark_applicable", None))

    # Optional: re-load to ensure idempotency/overwrite assignment works
    resp2 = client.post("/api/load-plugin", json={"filename": plugin_path.name, "overwrite": False})
    assert resp2.status_code in (200, 201)
    assert "dummy-method" in server.WMUtils.METHODS
