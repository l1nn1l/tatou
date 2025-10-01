import os
os.environ["TESTING"] = "1"

from server import app

def test_rmap_initiate_endpoint():
    client = app.test_client()

    # no payload → should return JSON error
    resp = client.post("/api/rmap-initiate", json={})
    assert resp.status_code in (200, 400)
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "error" in data or "payload" in data


def test_rmap_get_link_endpoint():
    client = app.test_client()

    # no payload → should return JSON error
    resp = client.post("/api/rmap-get-link", json={})
    assert resp.status_code in (200, 400)
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "error" in data or "result" in data
