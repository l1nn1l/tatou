import io

def test_upload_and_list_documents(client):
    # Create a test user and login to get token
    client.post("/api/create-user", json={
        "login": "charlie",
        "password": "docpass",
        "email": "charlie@example.com"
    })
    login_resp = client.post("/api/login", json={
        "email": "charlie@example.com",
        "password": "docpass"
    })
    token = login_resp.get_json()["token"]

    # Upload PDF
    data = {
        "name": "test.pdf",
        "file": (io.BytesIO(b"%PDF-1.4 test content"), "test.pdf")
    }
    resp = client.post(
        "/api/upload-document",
        data=data,
        headers={"Authorization": f"Bearer {token}"},
        content_type="multipart/form-data"
    )
    assert resp.status_code == 200
    doc = resp.get_json()
    assert doc["name"] == "test.pdf"
    assert doc["sha256"]

    # List documents
    resp = client.get(
        "/api/list-documents",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    docs = resp.get_json()["documents"]
    assert any(d["name"] == "test.pdf" for d in docs)
