import requests
import time

BASE_URL = "http://localhost:5000"

def test_create_and_read_watermark():
    # Register + login
    unique_email = f"wmuser_{int(time.time())}@example.com"
    requests.post(f"{BASE_URL}/api/create-user", json={
        "login": "wmuser",
        "password": "wmpass",
        "email": unique_email
    })
    login_resp = requests.post(f"{BASE_URL}/api/login", json={
        "email": unique_email,
        "password": "wmpass"
    })
    token = login_resp.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Upload document
    files = {"file": ("wm.pdf", b"%PDF-1.4 watermark test", "application/pdf")}
    doc_resp = requests.post(f"{BASE_URL}/api/upload-document", data={"name": "wm.pdf"}, files=files, headers=headers)
    doc_id = doc_resp.json()["id"]

    # Create watermark
    wm_resp = requests.post(f"{BASE_URL}/api/create-watermark/{doc_id}", json={
        "method": "AddAfterEOF",
        "position": "top",
        "key": "unit-test-key",
        "secret": "hidden-msg",
        "intended_for": "bob@example.com"
    }, headers=headers)

    # Debug output if fails
    if wm_resp.status_code != 200:
        print("Create watermark failed:", wm_resp.status_code, wm_resp.text)

    assert wm_resp.status_code == 200
    wm_info = wm_resp.json()

    # Read watermark
    read_resp = requests.post(f"{BASE_URL}/api/read-watermark/{doc_id}", json={
        "method": wm_info["method"],
        "position": wm_info["position"],
        "key": "unit-test-key"
    }, headers=headers)

    assert read_resp.status_code == 200
    assert read_resp.json()["secret"] == "hidden-msg"
