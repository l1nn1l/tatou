import os, pathlib, requests

BASE = os.environ.get("TATOU_BASE","http://127.0.0.1:5050") + "/api"

def test_upload_filename_traversal_rejected():
    token = os.environ.get("TOKEN","")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    p = pathlib.Path(__file__).with_name("min.pdf")
    if not p.exists():
        p.write_bytes(b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n")
    files = {"file": ("../../x.pdf", p.read_bytes(), "application/pdf")}
    r = requests.post(f"{BASE}/upload-document", files=files, data={"name":"t"}, headers=headers, timeout=10)
    assert r.status_code < 500
    assert r.status_code != 201
