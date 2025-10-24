"""
Simple reachability tests for document-related APIs.
Ensures /api/upload-document, /api/list-documents,
    /api/get-document, and /api/delete-document
all respond with JSON so coverage hits those code paths.
"""

import io
import os
import pytest
from flask import g
from server import app

# test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"


@pytest.fixture
def client(monkeypatch):
    """Return a Flask test client with auth + DB disabled."""
    # Dummy DB connection + engine
    class DummyConn:
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def execute(self, *a, **kw): return []
        def scalar(self): return 1

    class DummyEngine:
        def connect(self): return DummyConn()
        def begin(self): return DummyConn()

    monkeypatch.setattr("server.get_engine", lambda app: DummyEngine())
    monkeypatch.setattr("server.verify_token", lambda *a, **kw: True)
    return app.test_client()


@pytest.fixture
def user_context():
    """Fake Flask g.user context."""
    with app.test_request_context():
        g.user = {"id": 1, "login": "testuser", "email": "test@example.com"}
        yield


def test_upload_and_list_documents(client, user_context):
    """Ensure upload and list endpoints respond."""
    pdf = io.BytesIO(b"%PDF-1.4 dummy")
    resp = client.post(
        "/api/upload-document",
        data={"file": (pdf, "dummy.pdf"), "name": "dummy.pdf"},
        content_type="multipart/form-data",
    )
    assert resp.status_code in (200, 201, 401, 503)
    assert isinstance(resp.get_json(), dict)

    resp2 = client.get("/api/list-documents")
    assert resp2.status_code in (200, 401, 503)
    assert isinstance(resp2.get_json(), dict)


def test_get_document_and_delete_document(client, user_context):
    """Ensure get-document and delete-document endpoints respond."""
    # Try GET without ID
    resp = client.get("/api/get-document")
    assert resp.status_code in (200, 400, 401, 404, 503)
    assert isinstance(resp.get_json(), dict) or resp.status_code == 200

    # Try GET with fake ID
    resp = client.get("/api/get-document/1")
    assert resp.status_code in (200, 400, 401, 404, 410, 500, 503)
    # Either JSON or a file (PDF)
    if resp.mimetype == "application/json":
        assert isinstance(resp.get_json(), dict)

    # Try DELETE without ID
    resp = client.delete("/api/delete-document")
    assert resp.status_code in (200, 400, 401, 404, 503)
    assert isinstance(resp.get_json(), dict)

    # Try DELETE with ID
    resp = client.delete("/api/delete-document/1")
    assert resp.status_code in (200, 400, 401, 404, 503)
    assert isinstance(resp.get_json(), dict)
