"""
Coverage tests for watermark-related endpoints in server.py.
Covers both negative paths and true happy paths.
"""

import os
import io
import time
import pytest
from pathlib import Path
from flask import g

import server

# Ensure test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"


# -----------------------------
# Common fixtures
# -----------------------------

@pytest.fixture
def client(monkeypatch, tmp_path):
    """
    Test client with:
      - require_auth patched to inject g.user
      - STORAGE_DIR -> tmp_path
      - default DB disabled (tests override per-case as needed)
    """
    # Inject a user for all auth-protected routes
    def _require_auth(f):
        def _wrap(*a, **kw):
            g.user = {"id": 1, "login": "tester", "email": "tester@example.com"}
            return f(*a, **kw)
        return _wrap
    monkeypatch.setattr("server.require_auth", _require_auth, raising=False)

    # Default: no DB (tests that need DB will patch get_engine)
    monkeypatch.setattr("server.get_engine", lambda app: None, raising=False)

    # Token verifier (only used by /api/get-version token path)
    monkeypatch.setattr("server.verify_token", lambda *a, **kw: (True, "ok"), raising=False)

    # Storage root
    server.app.config["TESTING"] = True
    server.app.config["STORAGE_DIR"] = tmp_path

    return server.app.test_client()


# Helper: minimal SQLA-like result wrappers
class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)

class _Result:
    def __init__(self, rows=None):
        if rows is None:
            rows = []
        if not isinstance(rows, list):
            rows = [rows]
        self._rows = rows
    def first(self):
        return self._rows[0] if self._rows else None
    def all(self):
        return list(self._rows)
    def one(self):
        if len(self._rows) != 1:
            raise RuntimeError("expected exactly one row")
        return self._rows[0]
    def scalar(self):
        r = self.first()
        return None if r is None else getattr(r, "scalar", None)


# -----------------------------
# CREATE WATERMARK TESTS
# -----------------------------

def test_create_watermark_missing_id(client):
    """Should return 400 if no document id."""
    resp = client.post("/api/create-watermark", json={})
    assert resp.status_code == 400
    assert "document id" in resp.get_data(as_text=True).lower()


def test_create_watermark_invalid_json(client):
    """Triggers invalid JSON handling."""
    resp = client.post("/api/create-watermark/1", data="{bad_json", content_type="application/json")
    assert resp.status_code == 400
    # Actual message comes from field validation, not JSON parsing
    assert "required" in resp.get_data(as_text=True).lower()


def test_create_watermark_invalid_method(client, monkeypatch):
    """Invalid method should yield 422."""
    # No DB needed to reach method validation
    resp = client.post("/api/create-watermark/1", json={
        "method": "nonexistent",
        "position": "top",
        "intended_for": "bob@example.com",
        "key": "abc",
        "secret": "xyz"
    })
    assert resp.status_code in (400, 422)
    assert "invalid" in resp.get_data(as_text=True).lower()


def test_create_watermark_db_error(client, monkeypatch):
    """Simulate database exception during document lookup/insert."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine, raising=False)
    # Use a valid method name to get past validation quickly
    monkeypatch.setattr("server.WMUtils.METHODS", {"toy-eof": object()}, raising=False)
    resp = client.post("/api/create-watermark/1", json={
        "method": "toy-eof",
        "position": "top",
        "intended_for": "bob@example.com",
        "key": "abc",
        "secret": "xyz"
    })
    assert resp.status_code == 503
    assert "database" in resp.get_data(as_text=True).lower()


def test_create_watermark_happy_path(client, monkeypatch, tmp_path):
    """Full success path: valid method, existing doc on disk, DB insert OK."""
    storage = Path(server.app.config["STORAGE_DIR"]).resolve()
    # Create a real source PDF under storage
    files_dir = storage / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    src_pdf = files_dir / "doc.pdf"
    src_pdf.write_bytes(b"%PDF-1.4\n%source\n")

    # Mock WM applicability + watermarking output
    monkeypatch.setattr("server.WMUtils.is_watermarking_applicable", lambda **kw: True, raising=False)
    monkeypatch.setattr("server.WMUtils.apply_watermark", lambda **kw: b"%PDF-1.4\n%wm\n", raising=False)
    # Provide a valid method registry
    monkeypatch.setattr("server.WMUtils.METHODS", {"toy-eof": object()}, raising=False)

    # Fake DB to return the source document and accept INSERT into Versions
    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, sql, params=None):
            s = str(sql)
            p = params or {}
            # Document lookup by id
            if "FROM Documents" in s and "WHERE id = :id" in s and "SELECT id, name, path" in s:
                return _Result(_Row(id=1, name="doc.pdf", path=str(src_pdf)))
            # Versions insert
            if "INSERT INTO Versions" in s:
                return _Result([])
            # LAST_INSERT_ID()
            if "LAST_INSERT_ID" in s:
                return _Result(_Row(scalar=42))
            return _Result([])

    class _Engine:
        def connect(self): return _Conn()
        def begin(self):   return _Conn()

    monkeypatch.setattr("server.get_engine", lambda app: _Engine(), raising=False)

    # Call endpoint
    resp = client.post("/api/create-watermark/1", json={
        "method": "toy-eof",
        "position": "top",
        "intended_for": "bob@example.com",
        "key": "abcde12345",    # any string
        "secret": "xyz"
    })
    assert resp.status_code == 201, resp.data
    data = resp.get_json()
    assert isinstance(data, dict)
    assert {"id", "documentid", "link", "intended_for", "method", "filename", "size"} <= set(data.keys())
    # The watermarked file should have been written under storage/files/watermarks/
    wm_dir = src_pdf.parent / "watermarks"
    assert wm_dir.exists()


# -----------------------------
# READ WATERMARK TESTS
# -----------------------------

def test_read_watermark_missing_fields(client, monkeypatch):
    """Missing key/method should yield 400."""
    resp = client.post("/api/read-watermark/1", json={})
    assert resp.status_code in (400, 422)
    assert "required" in resp.get_data(as_text=True).lower()


def test_read_watermark_happy_path(client, monkeypatch, tmp_path):
    """Success path: owned document on disk, WM read returns a secret."""
    # Ensure the read_watermark handler gets g.user even if auth bypassed
    original_handler = server.app.view_functions["read_watermark"]
    def _with_user(*a, **kw):
        from flask import g as _g
        _g.user = {"id": 1, "login": "tester", "email": "tester@example.com"}
        return original_handler(*a, **kw)
    server.app.view_functions["read_watermark"] = _with_user

    storage = Path(server.app.config["STORAGE_DIR"]).resolve()
    files_dir = storage / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    src_pdf = files_dir / "owned.pdf"
    src_pdf.write_bytes(b"%PDF-1.4\n%owned\n")

    # No versions exist -> route should fall back to base document and call WM read
    monkeypatch.setattr("server.WMUtils.read_watermark", lambda **kw: "shh", raising=False)

    # Fake DB fulfilling ownership + fallback-to-base logic
    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, sql, params=None):
            s = str(sql)
            p = params or {}
            # Ownership check
            if "FROM Documents d" in s and "WHERE d.id = :id AND d.ownerid = :uid" in s and "SELECT d.id, d.name" in s:
                if int(p.get("id")) == 1 and int(p.get("uid")) == 1:
                    return _Result(_Row(id=1, name="owned.pdf"))
                return _Result([])
            # Try versions by id/link/latest -> return none so it falls back
            if "FROM Versions v" in s:
                return _Result([])
            # Fallback to base document path
            if "SELECT d.path" in s and "FROM Documents d" in s and "WHERE d.id = :did AND d.ownerid = :uid" in s:
                if int(p.get("did")) == 1 and int(p.get("uid")) == 1:
                    return _Result(_Row(path=str(src_pdf)))
                return _Result([])
            return _Result([])

    class _Engine:
        def connect(self): return _Conn()
        def begin(self):   return _Conn()

    monkeypatch.setattr("server.get_engine", lambda app: _Engine(), raising=False)

    resp = client.post("/api/read-watermark/1", json={
        "method": "toy-eof",
        "key": "abcde12345"
    })
    assert resp.status_code == 200, resp.data
    data = resp.get_json()
    assert isinstance(data, dict)
    assert data.get("secret") == "shh"


def test_get_watermarking_methods(client):
    """Verify GET /api/get-watermarking-methods returns list."""
    resp = client.get("/api/get-watermarking-methods")
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "methods" in data


# -----------------------------
# GET VERSION (external) TESTS
# -----------------------------

def test_get_version_external_success(tmp_path, client, monkeypatch):
    """Simulate an RMAP external PDF being served."""
    dummy_pdf = tmp_path / "dummy.pdf"
    dummy_pdf.write_bytes(b"%PDF-1.4\n%%EOF\n")

    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, sql, params=None):
            s = str(sql)
            p = params or {}
            # Early lookup SELECT path, intended_for FROM Versions WHERE link = :link LIMIT 1
            if "FROM Versions" in s and "WHERE link = :link" in s and "SELECT path, intended_for" in s:
                return _Result([(str(dummy_pdf), "external")])  # tuple-like so row[0]/row[1] works
            return _Result([])

    class _Engine:
        def connect(self): return _Conn()
        def begin(self):   return _Conn()

    monkeypatch.setattr("server.get_engine", lambda app: _Engine(), raising=False)

    resp = client.get("/api/get-version/abc123")
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert b"%PDF" in resp.data


def test_get_version_db_error(client, monkeypatch):
    """Trigger database exception path."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine, raising=False)
    # omit token to hit DB path first
    resp = client.get("/api/get-version/testlink")
    assert resp.status_code in (503, 401)
    txt = resp.get_data(as_text=True)
    assert "error" in txt.lower()


def test_get_version_invalid_token(client):
    """Invalid token should yield 401 on token-guarded path."""
    # Force route down token path by making early DB lookups fail (no engine)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("server.get_engine", lambda app: None, raising=False)
    resp = client.get("/api/get-version/xyz?token=badtoken")
    assert resp.status_code == 401


# -----------------------------
# LIST VERSION Negative paths
# -----------------------------

def test_list_versions_db_error(client, monkeypatch):
    """DB error triggers 503."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine, raising=False)
    resp = client.get("/api/list-versions/1")
    assert resp.status_code == 503


def test_list_all_versions_db_error(client, monkeypatch):
    """DB error triggers 503."""
    def fail_engine(app): raise Exception("db fail")
    monkeypatch.setattr("server.get_engine", fail_engine, raising=False)
    resp = client.get("/api/list-all-versions")
    assert resp.status_code == 503
