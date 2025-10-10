#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "src"))

from utils.signed_links import make_token
from urllib.parse import quote_plus


if __name__ == "__main__":
    link = sys.argv[1]   # e.g. 1914aca0ab8e31af...
    valid_seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 3600
    token = make_token(link, valid_seconds)
    # produce full URL (adjust host/port)
    url = f"http://<your_vm_ip>:5000/get_version/{quote_plus(link)}?token={quote_plus(token)}"
    print(url)
