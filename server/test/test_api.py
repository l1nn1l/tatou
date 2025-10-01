import base64, json
from server import app

def test_healthz_route():
    client = app.test_client()
    resp = client.get("/healthz")

    assert resp.status_code == 200
    assert resp.is_json

def test_rmap_initiate():
    client = app.test_client()

    # fake client request
    msg = {"nonceClient": 12345, "identity": "groupA"}
    encoded = base64.b64encode(json.dumps(msg).encode()).decode()

    resp = client.post("/api/rmap-initiate", json={"payload": encoded})

    assert resp.status_code == 200
    assert resp.is_json
    data = resp.get_json()
    assert "payload" in data


def test_rmap_get_link():
    client = app.test_client()

    # First call initiate to get a server nonce
    init_msg = {"nonceClient": 999, "identity": "groupB"}
    init_encoded = base64.b64encode(json.dumps(init_msg).encode()).decode()
    init_resp = client.post("/api/rmap-initiate", json={"payload": init_encoded})
    assert init_resp.status_code == 200
    payload = json.loads(base64.b64decode(init_resp.get_json()["payload"]).decode())
    nonce_server = payload["nonceServer"]

    # Now call get-link with that nonce
    link_msg = {"nonceServer": nonce_server}
    link_encoded = base64.b64encode(json.dumps(link_msg).encode()).decode()
    link_resp = client.post("/api/rmap-get-link", json={"payload": link_encoded})

    assert link_resp.status_code == 200
    assert "payload" in link_resp.get_json()

    
