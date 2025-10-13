#Regression test. Reproducerar en kraschfil som fuzzern hittat. När servern är fixad ska testet vara grönt.

import requests
import os

BASE="http://127.0.0.1:5000"
ENDPOINT="/upload-document"

def test_no_500_for_known_crash_file():
    # sätt hit en fil som fuzzern hittade: t.ex. crashes/mut_42.pdf
    path = "fuzz/crashes/mut_42.pdf"
    assert os.path.exists(path), f"Testfil saknas: {path}"
    with open(path,"rb") as fh:
        files = {"file": ("mut_42.pdf", fh, "application/pdf")}
        r = requests.post(BASE+ENDPOINT, files=files, timeout=10)
    assert r.status_code != 500, f"Server svarade 500 för {path}: {r.text}"
