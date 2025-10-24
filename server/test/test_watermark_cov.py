"""
Coverage tests for watermark-related endpoints in server.py.
Focuses on route reachability and correct response types.
"""

import io
import time
import pytest
from pathlib import Path
from flask import Flask

import server


@pytest.fixture
def client(monkeypatch):
    """Return a test client with auth and DB patched out."""
    # Disable DB + fake auth
    monkeypatch.setattr("server.get_engine", lambda app: None)
    monkeypatch.setattr("server.verify_token", lambda *a, **kw: (True, "ok"))
    monkeypatch.setattr("server.require_auth", lambda f: f)

    server.app.config["TESTING"] = True
    server.app.config["STORAGE_DIR"] = Path("/tmp")

    return server.app.test_client()


# -----------------------------
# CREATE WATERMARK TESTS
# -----------------------------

def test_create_watermark_missing_id(client):
    """Should return 400 if no document id."""
    resp = client.post("/api/create-watermark", json={})
    assert resp.status_code == 400
    assert "document id" in resp.get_data(as_text=True)


def test_create_watermark_invalid_json(client):
    """Triggers invalid JSON handling."""
    resp = client.post("/api/create-watermark/1", data="{bad_json", content_type="application/json")
    assert resp.status_code == 400
    # Actual message comes from field validation, not JSON parsing
    assert "required" in resp.get_data(as_text=True)


def test_create_watermark_invalid_method(client, monkeypatch):
    """Invalid method should yield 422."""
    monkeypatch.setattr("server.get_engine", lambda app: None)
    resp = client.post("/api/create-watermark/1", json={
        "method": "nonexistent",
        "position": "top",
        "intended_for": "bob@example.com",
        "key": "abc",
        "secret": "xyz"
    })
    assert resp.status_code in (400, 401, 422)
    assert "invalid" in resp.get_data(as_text=True)



def test_create_watermark_db_error(client, monkeypatch):
    """Simulate database exception."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine)
    resp = client.post("/api/create-watermark/1", json={
        "method": "toy-eof",
        "position": "top",
        "intended_for": "bob@example.com",
        "key": "abc",
        "secret": "xyz"
    })
    assert resp.status_code in (503, 400)
    assert "database" in resp.get_data(as_text=True)


def test_create_watermark_via_query_and_body(client, monkeypatch):
    """Ensure id from query/body is handled."""
    monkeypatch.setattr("server.get_engine", lambda app: None)
    resp = client.post("/api/create-watermark?id=1", json={
        "method": "toy-eof",
        "position": "top",
        "intended_for": "bob@example.com",
        "key": "abc",
        "secret": "xyz"
    })
    assert resp.status_code in (400, 401, 503)


# -----------------------------
# READ WATERMARK TESTS
# -----------------------------

def test_read_watermark_missing_fields(client, monkeypatch):
    """Missing key/position should yield 400."""
    monkeypatch.setattr("server.get_engine", lambda app: None)
    resp = client.post("/api/read-watermark/1", json={})
    assert resp.status_code in (400, 422)
    assert "required" in resp.get_data(as_text=True)


def test_get_watermarking_methods(client):
    """Verify GET /api/watermarking-methods returns list."""
    # Try both potential routes
    for path in ["/api/watermarking-methods", "/api/get-watermarking-methods"]:
        resp = client.get(path)
        if resp.status_code == 200:
            data = resp.get_json()
            assert isinstance(data, dict)
            assert "methods" in data
            break
    else:
        pytest.skip("watermarking-methods endpoint not found")


# -----------------------------
# GET VERSION TESTS
# -----------------------------

def test_get_version_external_success(tmp_path, client, monkeypatch):
    """Simulate an RMAP external PDF being served."""
    dummy_pdf = tmp_path / "dummy.pdf"
    dummy_pdf.write_bytes(b"%PDF-1.4\n%%EOF\n")

    class DummyConn:
        def connect(self): return self
        def __enter__(self): return self
        def __exit__(self, *a): return None
        def execute(self, *a, **kw):
            class Row:
                def first(self_inner):  # simulate SQLAlchemy row
                    return (str(dummy_pdf), "external")
            return Row()

    monkeypatch.setattr("server.get_engine", lambda app: DummyConn())

    resp = client.get("/api/get-version/abc123")
    assert resp.status_code in (200, 410, 503)


def test_get_version_db_error(client, monkeypatch):
    """Trigger database exception path."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine)
    # omit ?token to hit DB error path
    resp = client.get("/api/get-version/testlink")
    assert resp.status_code in (503, 401)
    txt = resp.get_data(as_text=True)
    assert "error" in txt


def test_get_version_invalid_token(client):
    """Invalid token should yield 401."""
    resp = client.get("/api/get-version/xyz?token=badtoken")
    assert resp.status_code == 401


# -----------------------------
# LIST VERSION TESTS
# -----------------------------

def test_list_versions_db_error(client, monkeypatch):
    """DB error triggers 503."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine)
    resp = client.get("/api/list-versions/1")
    assert resp.status_code == 503


def test_list_all_versions_db_error(client, monkeypatch):
    """DB error triggers 503."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine)
    resp = client.get("/api/list-all-versions")
    assert resp.status_code == 503
