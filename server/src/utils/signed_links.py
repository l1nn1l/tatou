# server/src/utils/signed_links.py
import time
import hmac
import hashlib
import base64
import os
from urllib.parse import urlencode, quote_plus


SECRET = os.environ.get("TATOU_LINK_KEY")
if not SECRET:
    raise RuntimeError("TATOU_LINK_KEY not set in environment")


# token format: base64url( link | expires | signature )
# signature = HMAC_SHA256(secret, f"{link}|{expires}")


def _hmac(link: str, expires: int) -> str:
    msg = f"{link}|{expires}".encode("utf-8")
    return hmac.new(SECRET.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def make_token(link: str, valid_seconds: int = 3600) -> str:
    expires = int(time.time()) + int(valid_seconds)
    sig = _hmac(link, expires)
    payload = f"{link}|{expires}|{sig}"
    # base64url encode
    token = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8").rstrip("=")
    return token


def verify_token(token: str) -> (bool, str):
    try:
        # pad base64
        padding = '=' * (-len(token) % 4)
        payload = base64.urlsafe_b64decode(token + padding).decode("utf-8")
        parts = payload.split("|")
        if len(parts) != 3:
            return False, "bad-format"
        link, expires_s, sig = parts
        expires = int(expires_s)
        if time.time() > expires:
            return False, "expired"
        expected = _hmac(link, expires)
        # Use hmac.compare_digest to avoid timing attacks
        if not hmac.compare_digest(expected, sig):
            return False, "bad-signature"
        return True, link
    except Exception as e:
        return False, "decode-error"
