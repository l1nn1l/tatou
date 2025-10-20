import os, requests, pathlib, json, time

BASE = os.environ.get("TATOU_BASE","http://127.0.0.1:5000") + "/api"
TOKEN = os.environ.get("TOKEN","")

def _token():
    if TOKEN: return TOKEN
    email = f"t_{int(time.time())}@example.com"
    pwd = "P@ssw0rd123"
    requests.post(f"{BASE}/create-user", json={"login": email.split("@")[0], "password": pwd, "email": email}, timeout=10)
    r = requests.post(f"{BASE}/login", json={"email": email, "password": pwd}, timeout=10)
    return r.json()["token"]

def _upload_min(token):
    p = pathlib.Path(__file__).with_name("min.pdf")
    if not p.exists(): p.write_bytes(b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n")
    r = requests.post(f"{BASE}/upload-document",
                      headers={"Authorization": f"Bearer {token}"},
                      files={"file": ("min.pdf", p.read_bytes(), "application/pdf")},
                      data={"name":"min"},
                      timeout=10)
    assert r.status_code in (200,201)
    return r.json()["id"]

def test_create_watermark_bad_schema_no_5xx():
    token = _token()
    did = _upload_min(token)
    bad = {"method": None, "position": [], "key": {}, "secret": False, "__weird__":"x"}
    r = requests.post(f"{BASE}/create-watermark/{did}",
                      headers={"Authorization": f"Bearer {token}"},
                      json=bad, timeout=10)
    assert r.status_code < 500
    assert r.status_code in (400, 422)
