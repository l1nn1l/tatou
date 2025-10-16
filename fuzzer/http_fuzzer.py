#!/usr/bin/env python3
import os, json, time, random, string, hashlib, subprocess, pathlib
import requests
from pathlib import Path #ny

BASE = os.environ.get("TATOU_BASE", "http://127.0.0.1:5050")
SEED = int(os.environ.get("FUZZ_SEED", "1337"))
TIMEOUT = float(os.environ.get("FUZZ_TIMEOUT", "8.0"))
RUNS = int(os.environ.get("FUZZ_RUNS", "2000"))

# ny helper för att matcha endpoints
API_PREFIX = "/api"

MAX_SAVED = 50
_saved = 0

def should_save(resp, note=""):
    # spara bara serverfel (5xx) eller rena nätverksfel (resp=None)
    return (resp is None) or (getattr(resp, "status_code", 0) >= 500)


def API(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"{BASE}{API_PREFIX}{path}"


random.seed(SEED)

DIR = pathlib.Path(__file__).resolve().parent
CRASH_DIR = DIR / "crashes"
IN_DIR = DIR / "fuzz_in"
CRASH_DIR.mkdir(exist_ok=True)
IN_DIR.mkdir(exist_ok=True)

s = requests.Session()
token = None
headers = {}

def save_crash(name, req, resp=None, note=""):
    ts = int(time.time()*1000)
    p = CRASH_DIR / f"{ts}_{name}"
    p.mkdir(exist_ok=True)
    (p / "note.txt").write_text(note)
    (p / "request.json").write_text(json.dumps(req, indent=2, ensure_ascii=False))
    if resp is not None:
        meta = {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "text_prefix": resp.text[:2000]
        }
        (p / "response.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False))
    print(f"[!] Saved crash at {p}")

def jwt_set(t):
    global headers
    headers = {"Authorization": f"Bearer {t}"} if t else {}

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# --- Radamsa helpers ---
def radamsa_mutate(b: bytes) -> bytes:
    try:
        p = subprocess.run(["radamsa", "-n", "1"], input=b, capture_output=True, check=True)
        return p.stdout if p.stdout else b
    except Exception:
        # tiny fallback mutations
        if not b: 
            return os.urandom(8)
        b = bytearray(b)
        for _ in range(random.randint(1, min(8, len(b)))):
            i = random.randrange(len(b))
            b[i] = random.randrange(256)
        if random.random() < 0.3:
            b.extend(os.urandom(random.randint(1,32)))
        return bytes(b)

# --- Seed builders (valid-ish) from spec ---
def seed_login_email():  # unique per run
    suffix = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
    return f"fuzzer_{suffix}@ex.ample"

def create_user_and_login():
    global token, headers
    # gör email unikt (minskar 409), men 409 ska ändå räknas som OK
    suffix = str(int(time.time()*1000)) + ''.join(random.choice(string.ascii_lowercase) for _ in range(4))
    email = f"fuzzer_{suffix}@ex.ample"
    pwd = "P@ssw0rd!"

    # försök skapa
    try:
        r = s.post(API("create-user"),
                   json={"login": email.split("@")[0], "password": pwd, "email": email},
                   timeout=TIMEOUT)
        # 200/201 = skapad, 409 = fanns redan (OK för oss)
        if r.status_code not in (200, 201, 409):
            # spara bara om det faktiskt är 5xx
            if r.status_code >= 500:
                save_crash("create-user", {"email": email}, r, "Unexpected 5xx on create-user")
            return False
    except requests.RequestException:
        # nätverksfel kan sparas
        save_crash("create-user", {"email": email}, None, "Network error")
        return False

    # login
    r = s.post(API("login"), json={"email": email, "password": pwd}, timeout=TIMEOUT)
    if r.status_code != 200:
        # spara bara om 5xx
        if r.status_code >= 500:
            save_crash("login", {"email": email}, r, "Unexpected 5xx on login")
        return False

    try:
        token = r.json().get("token")
    except Exception:
        token = None

    if not token:
        # inte 5xx, bara “no token” → return False utan att spara brus
        return False

    headers = {"Authorization": f"Bearer {token}"}
    return True


def mutate_json(obj: dict) -> dict:
    # simple structural & value mutations
    out = dict(obj)
    keys = list(out.keys())
    if random.random() < 0.5 and keys:
        k = random.choice(keys)
        v = out[k]
        choices = [None, "", "A"*random.randint(1,2048), -1, 0, 2**63-1, [], {}, True, False]
        out[k] = random.choice(choices)
    if random.random() < 0.3:
        out["\x00dup"] = out.get(keys[0], "x")  # duplicate/odd key
    if random.random() < 0.2:
        # sprinkle Unicode
        out["unicode"] = "𝔽uzz🚀" * random.randint(1,20)
    return out

def random_pdf_bytes():
    # choose a seed file or synthesize
    seeds = [p for p in IN_DIR.glob("*.pdf")] + [DIR / "sample.pdf"]
    for p in list(seeds):
        if not p or not p.exists():
            seeds.remove(p)
    if seeds:
        b = (random.choice(seeds)).read_bytes()
    else:
        b = b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n"
    # Radamsa or fallback
    return radamsa_mutate(b)  

def upload_random_pdf():
    global _saved
    pdf = random_pdf_bytes()
    fname = "../../" + ("x"*random.randint(0,8)) + ".pdf"   # sparar filnamnet
    files = {"file": (fname, pdf, "application/pdf")}
    name = "seed-" + sha256_bytes(pdf)[:8]
    data = {"name": name}

    try:
        r = s.post(API("upload-document"), files=files, data=data, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        # Nätverksfel: spara en liten .exception bara om vi inte har för många
        if _saved < MAX_SAVED and should_save(None, note=str(e)):
            ts = int(time.time()*1000)
            (Path("crashes") / f"{ts}_upload.exception").write_text(str(e))
            _saved += 1
        return None, pdf

    # --- spara ENDAST 5xx ---
    if r.status_code >= 500 and _saved < MAX_SAVED:
        ts = int(time.time()*1000)
        case = Path("crashes") / f"{ts}_upload"
        case.mkdir(parents=True, exist_ok=True)

        (case / "request.json").write_text(json.dumps({
            "endpoint": "/api/upload-document",
            "name": name,
            "size": len(pdf),
            "filename": fname            # spara original-filnamnet
        }, indent=2))

        (case / "response.json").write_text(json.dumps({
            "status": r.status_code,
            "headers": dict(r.headers),
            "text_prefix": r.text[:2000]
        }, indent=2))

        (case / "input.pdf").write_bytes(pdf)

        # auth-extra_h 
        auth = headers.get("Authorization") if headers else None
        extra_h = f'-H "Authorization: {auth}" ' if auth else '${TOKEN:+-H "Authorization: Bearer ${TOKEN}"} '

        # använd samma filnamn via curl: filename=<fname> 
        (case / "repro.sh").write_text(f"""#!/usr/bin/env bash
    set -euo pipefail
    DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
    curl -v {extra_h}-F "file=@${{DIR}}/input.pdf;filename={fname};type=application/pdf" -F "name={name}" "{BASE}{API_PREFIX}/upload-document"
    """)
        os.chmod(case / "repro.sh", 0o755)
        _saved += 1
        print(f"[!] 5xx saved at {case}")
        return None, pdf

    # 2xx/201 → OK; alla 4xx ignoreras nu tyst
    if r.status_code in (200, 201):
        j = r.json()
        if not {"id","sha256","size"} <= set(j.keys()):
            # schema-avvikelse *kan* vara intressant – välj själv om du vill spara
            pass
        return j.get("id"), pdf

    # 4xx: gör inget (ingen save), gå vidare
    return None, pdf


def create_watermark(doc_id: int):
    body = {
        "method": random.choice(["text", "meta", "bits", "best"]),  # your methods here
        "position": random.choice(["tl","tr","bl","br","center"]),
        "key": ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(16)),
        "secret": ''.join(random.choice(string.ascii_letters) for _ in range(12)),
        "intended for": "FUZZ"
    }
    body = mutate_json(body) if random.random()<0.6 else body
    r = s.post(API(f"create-watermark/{doc_id}"), json=body, headers=headers, timeout=TIMEOUT)
    if r.status_code not in (200,201,400,422):
        save_crash("create-watermark", {"doc_id": doc_id, "body": body}, r, "Unexpected status")
    return r

def list_and_get(doc_id: int):
    r = s.get(API(f"list-versions/{doc_id}"), headers=headers, timeout=TIMEOUT)
    if r.status_code == 500:
        save_crash("list-versions-500", {"doc_id": doc_id}, r)
        return
    if r.status_code == 200:
        try:
            versions = r.json().get("versions", [])
        except Exception:
            versions = []
            save_crash("list-versions-json", {"doc_id": doc_id}, r, "JSON parse fail")
        for v in versions[:3]:
            link = v.get("link")
            if link:
                rr = s.get(API(f"get-version/{link}"), timeout=TIMEOUT)
                if rr.status_code >= 500:
                    save_crash("get-version-5xx", {"link": link}, rr)

def delete_twice(doc_id: int):
    r1 = s.delete(API(f"delete-document/{doc_id}"), headers=headers, timeout=TIMEOUT)
    r2 = s.delete(API(f"delete-document/{doc_id}"), headers=headers, timeout=TIMEOUT)
    if r2.status_code >= 500:
        save_crash("delete-idempotence", {"doc_id": doc_id, "first": r1.status_code, "second": r2.status_code}, r2, "Idempotence broken")

def main():
    if not create_user_and_login():
        return
    for i in range(RUNS):
        try:
            if random.random() < 0.2:
                # fuzz public endpoints quickly
                s.get(f"{BASE}/healthz", timeout=TIMEOUT)
                s.get(API("get-watermarking-methods"), timeout=TIMEOUT)
            # upload -> watermark -> list/get -> delete twice
            doc_id, pdf = upload_random_pdf()
            if doc_id is None:
                continue
            create_watermark(doc_id)
            list_and_get(doc_id)
            delete_twice(doc_id)
        except requests.exceptions.RequestException as e:
            save_crash("network", {"step": "req", "i": i}, None, f"Exception: {e}")
        except Exception as e:
            save_crash("internal", {"i": i}, None, f"Exception: {e}")

if __name__ == "__main__":
    main()
