# import io
# import requests
# import time

# BASE_URL = "http://localhost:5000"

# def test_upload_and_list_documents():
#     # Create user + login
#     unique_email = f"charlie_{int(time.time())}@example.com"
#     requests.post(f"{BASE_URL}/api/create-user", json={
#         "login": "charlie",
#         "password": "docpass",
#         "email": unique_email
#     })
#     login_resp = requests.post(f"{BASE_URL}/api/login", json={
#         "email": unique_email,
#         "password": "docpass"
#     })
#     token = login_resp.json()["token"]

#     headers = {"Authorization": f"Bearer {token}"}

#     # Upload PDF
#     files = {"file": ("test.pdf", b"%PDF-1.4 test content", "application/pdf")}
#     resp = requests.post(f"{BASE_URL}/api/upload-document", data={"name": "test.pdf"}, files=files, headers=headers)

#     # Accept either 200 OK or 201 Created
#     assert resp.status_code in (200, 201)
#     doc = resp.json()
#     assert doc["name"] == "test.pdf"

#     # List documents
#     resp = requests.get(f"{BASE_URL}/api/list-documents", headers=headers)
#     assert resp.status_code == 200
#     docs = resp.json()["documents"]
#     assert any(d["name"] == "test.pdf" for d in docs)
