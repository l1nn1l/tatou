import requests

def test_create_user():
    resp = requests.post(f"{BASE_URL}/api/create-user", json={
        "login": "alice",
        "password": "secret123",
        "email": "alice@example.com"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["login"] == "alice"
    assert data["email"] == "alice@example.com"

def test_login_success():
    requests.post(f"{BASE_URL}/api/create-user", json={
        "login": "bob",
        "password": "secret123",
        "email": "bob@example.com"
    })
    resp = requests.post(f"{BASE_URL}/api/login", json={
        "email": "bob@example.com",
        "password": "secret123"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["token_type"] == "bearer"

def test_login_failure():
    resp = requests.post(f"{BASE_URL}/api/login", json={
        "email": "ghost@example.com",
        "password": "wrong"
    })
    assert resp.status_code in (400, 401)
