import requests
import time

BASE_URL = "http://localhost:5000"

def test_create_user():
    unique_email = f"alice_{int(time.time())}@example.com"
    resp = requests.post(f"{BASE_URL}/api/create-user", json={
        "login": "alice",
        "password": "secret123",
        "email": unique_email
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["login"] == "alice"
    assert data["email"] == unique_email

def test_login_success():
    unique_email = f"bob_{int(time.time())}@example.com"
    requests.post(f"{BASE_URL}/api/create-user", json={
        "login": "bob",
        "password": "secret123",
        "email": unique_email
    })
    resp = requests.post(f"{BASE_URL}/api/login", json={
        "email": unique_email,
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
