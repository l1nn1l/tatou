#!/usr/bin/env python3
# requirements: pip install requests
import os
import requests

BASE="http://127.0.0.1:5000"   # Ändra till VM-ip om du kör från Mac
ENDPOINT="/upload-document"
IN_DIR="fuzz_in"
CRASH_DIR="crashes"
LOG="fuzz_results.log"

os.makedirs(CRASH_DIR, exist_ok=True)

with open(LOG,"w") as log:
    for fname in sorted(os.listdir(IN_DIR)):
        if not fname.endswith(".pdf"):
            continue
        path = os.path.join(IN_DIR, fname)
        with open(path,"rb") as fh:
            files = {"file": (fname, fh, "application/pdf")}
            try:
                r = requests.post(BASE+ENDPOINT, files=files, timeout=15)
                status = r.status_code
                line = f"{fname} {status}\n"
                log.write(line)
                print(line.strip())
                if status >= 500:
                    # spara reproducible input
                    with open(os.path.join(CRASH_DIR, fname), "wb") as out:
                        out.write(open(path,"rb").read())
            except Exception as e:
                line = f"{fname} EXCEPTION {e}\n"
                log.write(line)
                print(line.strip())
                with open(os.path.join(CRASH_DIR, fname + ".exception"), 
"w") as out:
                    out.write(str(e))

