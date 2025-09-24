# tatou/server/test/conftest.py
import sys
from pathlib import Path
import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from server import app  
#allows all test files to reuse the same Flask test client
@pytest.fixture
def client():
    """Provide a test client for the Flask app."""
    return app.test_client()


@pytest.fixture
def auth_headers(client):
    """Create a test user, log in, and return auth headers."""
    email = "tester@example.com"
    password = "testpass"

    # Create user
    client.post("/api/create-user", json={
        "login": "tester",
        "email": email,
        "password": password
    })

    # Login
    resp = client.post("/api/login", json={
        "email": email,
        "password": password
    })
    data = resp.get_json()
    token = data["token"]

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def uploaded_doc_id(client, auth_headers, tmp_path):
    """Upload a small PDF and return its document id."""
    pdf_path = tmp_path / "sample.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%EOF\n")  # minimal valid PDF

    with open(pdf_path, "rb") as f:
        resp = client.post(
            "/api/upload-document",
            data={"name": "sample.pdf", "file": f},
            headers=auth_headers,
            content_type="multipart/form-data"
        )

    assert resp.status_code == 200, resp.get_data(as_text=True)
    return resp.get_json()["id"]