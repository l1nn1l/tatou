"""
Tests for utils/signed_links.py

Covers:
- make_token / verify_token happy path
- expired token
- tampered token with valid base64 (bad-signature)
- bad format (decodes but wrong number of parts)
- decode error (invalid base64)
"""

import os
import base64
import importlib
import sys
from pathlib import Path
import pytest

# Ensure we can import from server/src
ROOT = Path(__file__).resolve().parents[1]        # .../server
SRC = ROOT / "src"                                 # .../server/src
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def sl(monkeypatch):
    """
    Import utils.signed_links with a known secret and return the module.
    Re-imports to ensure SECRET is picked up from env each test.
    """
    os.environ["TATOU_LINK_KEY"] = "test-secret-123"  # must exist at import time
    mod = importlib.import_module("utils.signed_links")
    mod = importlib.reload(mod)
    return mod


def _b64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("utf-8").rstrip("=")


# -------------------------
# Happy path
# -------------------------

def test_make_and_verify_token_happy(sl, monkeypatch):
    # Freeze "now" so expiry is deterministic
    base_now = 1_700_000_000
    monkeypatch.setattr(sl.time, "time", lambda: base_now)

    token = sl.make_token("link-abc", valid_seconds=600)  # expires at base_now + 600
    ok, value = sl.verify_token(token)
    assert ok is True
    assert value == "link-abc"


# -------------------------
# Expired token
# -------------------------

def test_verify_token_expired(sl, monkeypatch):
    base_now = 1_700_000_000
    # Create with a frozen "now"
    monkeypatch.setattr(sl.time, "time", lambda: base_now)
    token = sl.make_token("link-xyz", valid_seconds=60)  # expires at +60

    # Advance time past expiry when verifying
    monkeypatch.setattr(sl.time, "time", lambda: base_now + 120)
    ok, msg = sl.verify_token(token)
    assert ok is False
    assert msg == "expired"


# -------------------------
# Tampered token (valid base64 but bad signature)
# -------------------------

def test_verify_token_bad_signature(sl, monkeypatch):
    base_now = 1_700_100_000
    monkeypatch.setattr(sl.time, "time", lambda: base_now)
    token = sl.make_token("original-link", valid_seconds=600)

    # Decode token → payload: "link|expires|sig"
    padding = "=" * (-len(token) % 4)
    payload = base64.urlsafe_b64decode(token + padding).decode("utf-8")
    link, expires, sig = payload.split("|")

    # Tamper the link but keep the same signature, re-encode valid base64url
    tampered_payload = f"tampered-link|{expires}|{sig}"
    tampered_token = _b64url_encode(tampered_payload)

    ok, msg = sl.verify_token(tampered_token)
    assert ok is False
    assert msg == "bad-signature"


# -------------------------
# Bad format (decodes but wrong number of parts)
# -------------------------

def test_verify_token_bad_format(sl):
    bad_payload = "just-one-part"
    token = _b64url_encode(bad_payload)
    ok, msg = sl.verify_token(token)
    assert ok is False
    assert msg == "bad-format"


# -------------------------
# Decode error (invalid base64)
# -------------------------

def test_verify_token_decode_error(sl):
    # Not valid base64url → base64 decoder should raise → function returns decode-error
    token = "###not_base64###"
    ok, msg = sl.verify_token(token)
    assert ok is False
    assert msg == "decode-error"

