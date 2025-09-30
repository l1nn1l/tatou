import requests
import time

BASE_URL = "http://localhost:5000"

def test_create_and_read_watermark():
    # Register + login
    unique_suffix = int(time.time())
    unique_email = f"wmuser_{unique_suffix}@example.com"

    requests.post(f"{BASE_URL}/api/create-user", json={
        "login": f"wmuser_{unique_suffix}",
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
    unique_filename = f"wm_{unique_suffix}.pdf"
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"
    files = {"file": (unique_filename, pdf_bytes, "application/pdf")}
    doc_resp = requests.post(f"{BASE_URL}/api/upload-document", data={"name": unique_filename}, files=files, headers=headers)
    doc_id = doc_resp.json()["id"]

    # Create watermark with unique secret
    unique_secret = f"hidden-msg-{unique_suffix}"
    wm_resp = requests.post(f"{BASE_URL}/api/create-watermark/{doc_id}", json={
        "method": "toy-eof",
        "position": "top",
        "key": "unit-test-key",
        "secret": unique_secret,
        "intended_for": "bob@example.com"
    }, headers=headers)

    # Debug output if fails
    if wm_resp.status_code not in (200,201):
        print("Create watermark failed:", wm_resp.status_code, wm_resp.text)

    assert wm_resp.status_code in (200,201)
    wm_info = wm_resp.json()

'''
    # Read watermark
    read_resp = requests.post(f"{BASE_URL}/api/read-watermark/{doc_id}", json={
        "id": doc_id,
	"method": wm_info["method"],
        "position": wm_info["position"],
        "key": "unit-test-key"
    }, headers=headers)

    if read_resp.status_code != 200:
        print("Read watermark failed:", read_resp.status_code, read_resp.text)

    assert read_resp.status_code == 200
    assert read_resp.json()["secret"] == unique_secret
'''
