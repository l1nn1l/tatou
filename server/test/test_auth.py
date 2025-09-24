def test_create_user(client):
    resp = client.post("/api/create-user", json={
        "login": "alice",
        "password": "secret123",
        "email": "alice@example.com"
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["login"] == "alice"
    assert data["email"] == "alice@example.com"

def test_login_success(client):
    # First, create user
    client.post("/api/create-user", json={
        "login": "bob",
        "password": "secret123",
        "email": "bob@example.com"
    })
    # Then login
    resp = client.post("/api/login", json={
        "email": "bob@example.com",
        "password": "secret123"
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert "token" in data
    assert data["token_type"] == "bearer"

def test_login_failure(client):
    resp = client.post("/api/login", json={
        "email": "ghost@example.com",
        "password": "wrong"
    })
    assert resp.status_code == 401 or resp.status_code == 400
