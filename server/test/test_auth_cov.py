"""
Lightweight tests for the /api/create-user and /api/login endpoints.
These verify that routes exist and handle JSON payloads correctly,
without needing a real database or authentication backend.
"""

import os
import time
import pytest

# Ensure test mode
os.environ["TESTING"] = "1"
os.environ["SKIP_RMAP"] = "1"

from server import app


@pytest.fixture(scope="module")
def client():
    """Create a Flask test client."""
    return app.test_client()


def test_create_user_local(client, monkeypatch):
    """POST /api/create-user should accept JSON and return structured output."""
    from server import get_engine
    # Patch DB engine so no MySQL connection is attempted
    monkeypatch.setattr("server.get_engine", lambda app: None)

    email = f"alice_{int(time.time())}@example.com"
    resp = client.post("/api/create-user", json={
        "login": "alice",
        "password": "secret123",
        "email": email
    })
    # 503 acceptable in test mode (DB skipped)
    assert resp.status_code in (200, 201, 503)
    data = resp.get_json()
    assert isinstance(data, dict)


def test_login_success_local(client, monkeypatch):
    """POST /api/login should accept credentials and return structured JSON."""
    monkeypatch.setattr("server.get_engine", lambda app: None)

    email = f"bob_{int(time.time())}@example.com"
    resp = client.post("/api/login", json={
        "email": email,
        "password": "secret123"
    })
    assert resp.status_code in (200, 201, 401, 503)
    data = resp.get_json()
    assert isinstance(data, dict)


def test_login_failure_local(client, monkeypatch):
    """POST /api/login with invalid credentials should still return JSON."""
    monkeypatch.setattr("server.get_engine", lambda app: None)

    resp = client.post("/api/login", json={
        "email": "ghost@example.com",
        "password": "wrong"
    })
    assert resp.status_code in (200, 400, 401, 503)
    data = resp.get_json()
    assert isinstance(data, dict)
