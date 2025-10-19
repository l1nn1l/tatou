"""
Lightweight tests for the /api/rmap-initiate and /api/rmap-get-link endpoints.
These tests verify that the endpoints exist, accept JSON payloads, and return
properly structured responses (without requiring real RMAP key material).
"""

import os
import pytest

# Ensure test mode to disable heavy RMAP setup
os.environ["TESTING"] = "1"

from server import app


@pytest.fixture(scope="module")
def client():
    """Create a Flask test client."""
    return app.test_client()


def test_rmap_initiate_no_payload(client):
    """
    When called without a payload, the /api/rmap-initiate endpoint should return
    HTTP 400 and a JSON error object. In test mode, this may also return 200 with a dummy response.
    """
    resp = client.post("/api/rmap-initiate", json={})
    assert resp.status_code in (200, 400)
    data = resp.get_json()
    assert isinstance(data, dict), "Expected JSON dict response"
    assert "error" in data or "payload" in data or "result" in data


def test_rmap_initiate_with_fake_payload(client):
    """
    When called with a minimal fake payload, ensure we get a structured JSON response.
    """
    fake_msg1 = {"payload": "ZmFrZS1tZXNzYWdlLTE="}  # base64("fake-message-1")
    resp = client.post("/api/rmap-initiate", json=fake_msg1)
    assert resp.status_code in (200, 400)
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "error" in data or "payload" in data or "result" in data


def test_rmap_get_link_no_payload(client):
    """
    When called without a payload, /api/rmap-get-link should return 400 or a test stub response.
    """
    resp = client.post("/api/rmap-get-link", json={})
    assert resp.status_code in (200, 400)
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "error" in data or "result" in data


def test_rmap_get_link_with_fake_payload(client):
    """
    When called with a minimal fake payload, verify JSON structure is correct.
    """
    fake_msg2 = {"payload": "ZmFrZS1tZXNzYWdlLTI="}  # base64("fake-message-2")
    resp = client.post("/api/rmap-get-link", json=fake_msg2)
    assert resp.status_code in (200, 400)
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "error" in data or "result" in data
