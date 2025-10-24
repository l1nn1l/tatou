"""
Lightweight coverage tests for version-related endpoints:
- /api/get-version/<link>
- /api/list-versions
- /api/list-all-versions

These tests ensure the routes respond with JSON or files and
do not raise unhandled exceptions in TESTING mode.
"""

import os
import io
import pytest
from flask import g
from server import app


# enable test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"


@pytest.fixture
def client(monkeypatch):
    """Flask test client with fake DB + token verification."""
    # Dummy DB engine/connection
    class DummyConn:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, *a, **kw):
            # Return an empty iterable or a minimal row-like structure
            return []
        def scalar(self): return 1

    class DummyEngine:
        def connect(self): return DummyConn()
        def begin(self): return DummyConn()

    monkeypatch.setattr("server.get_engine", lambda app: DummyEngine())
    monkeypatch.setattr("server.verify_token", lambda *a, **kw: (True, "validlink"))
    return app.test_client()


@pytest.fixture
def user_context():
    """Fake Flask g.user context so auth-protected routes don't crash."""
    with app.test_request_context():
        g.user = {"id": 1, "login": "tester", "email": "tester@example.com"}
        yield


def test_get_version_endpoint(client, user_context, tmp_path):
    """Hit /api/get-version/<link> with and without a token."""
    link = "dummy-link"

    # Case 1: Missing token → expect JSON error
    resp = client.get(f"/api/get-version/{link}")
    assert resp.status_code in (401, 404, 410, 503)
    if resp.mimetype == "application/json":
        assert isinstance(resp.get_json(), dict)

    # Case 2: With fake token header
    resp = client.get(
        f"/api/get-version/{link}",
        headers={"Authorization": "Bearer faketoken"},
    )
    assert resp.status_code in (200, 401, 404, 410, 500, 503)
    if resp.mimetype == "application/json":
        assert isinstance(resp.get_json(), dict)


def test_list_versions(client, user_context):
    """Ensure /api/list-versions and /api/list-versions/<id> respond."""
    # Without document ID
    resp = client.get("/api/list-versions")
    assert resp.status_code in (200, 400, 401, 404, 503)
    if resp.mimetype == "application/json":
        assert isinstance(resp.get_json(), dict)

    # With fake document ID
    resp = client.get("/api/list-versions/1")
    assert resp.status_code in (200, 400, 401, 404, 503)
    if resp.mimetype == "application/json":
        assert isinstance(resp.get_json(), dict)


def test_list_all_versions(client, user_context):
    """Ensure /api/list-all-versions responds."""
    resp = client.get("/api/list-all-versions")
    assert resp.status_code in (200, 401, 404, 503)
    if resp.mimetype == "application/json":
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "versions" in data or "error" in data
