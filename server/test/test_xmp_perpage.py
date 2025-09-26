# server/test/test_xmp_perpage.py
from pathlib import Path
import io

import pikepdf
import pytest

from plugins.xmp_perpage import XmpPerPageMethod
from watermarking_method import InvalidKeyError

# Hitta sample.pdf oavsett om den ligger i server/ (CI) eller repo-roten (lokalt)
ROOT = Path(__file__).resolve().parents[1]        # .../server
CANDIDATES = [
    ROOT / "sample.pdf",                          # CI: tatou/server/sample.pdf
    ROOT.parent / "sample.pdf",                   # Lokalt: tatou/sample.pdf
]
for _p in CANDIDATES:
    if _p.exists():
        SAMPLE_PDF = _p
        break
else:
    raise FileNotFoundError(
        f"sample.pdf not found. Checked: {', '.join(map(str, CANDIDATES))}"
    )


def _read_bytes(p: Path) -> bytes:
    with open(p, "rb") as fh:
        return fh.read()


def test_roundtrip_embed_extract():
    m = XmpPerPageMethod()
    key = "1234567890abcdef1234567890abcdef"
    secret = "abc123"

    pdf = _read_bytes(SAMPLE_PDF)
    wm = m.add_watermark(pdf, secret, key)
    got = m.read_secret(wm, key)
    assert got == secret

    # sanity: minst en sida har salt+mac
    with pikepdf.open(io.BytesIO(wm)) as doc:
        with doc.open_metadata() as x:
            # pikepdf kan exponera nycklar både som lokalnamn och i {URI}format
            page_count = int(
                str(
                    x.get("page_count")
                    or x.get("{https://tatou.local/wm/1.0/}page_count")
                )
            )
            assert page_count >= 1
            assert x.get("p0_salt") or x.get("{https://tatou.local/wm/1.0/}p0_salt")
            assert x.get("p0_mac") or x.get("{https://tatou.local/wm/1.0/}p0_mac")


def test_wrong_key_fails():
    m = XmpPerPageMethod()
    pdf = _read_bytes(SAMPLE_PDF)
    good_key = "1234567890abcdef1234567890abcdef"
    bad_key = "ffffffffffffffffffffffffffffffff"

    wm = m.add_watermark(pdf, "abc123", good_key)
    with pytest.raises(InvalidKeyError):
        m.read_secret(wm, bad_key)


def test_tamper_mac_fails():
    m = XmpPerPageMethod()
    key = "1234567890abcdef1234567890abcdef"
    pdf = _read_bytes(SAMPLE_PDF)
    wm = m.add_watermark(pdf, "abc123", key)

    # Förvanska p0_mac i XMP
    bio = io.BytesIO(wm)
    with pikepdf.open(bio) as doc:
        with doc.open_metadata() as x:
            if x.get("p0_mac") is not None:
                x["p0_mac"] = "00" * 32
            else:
                x["{https://tatou.local/wm/1.0/}p0_mac"] = "00" * 32
        out = io.BytesIO()
        doc.save(out)
    tampered = out.getvalue()

    # Rätt nyckel men manipulerat -> InvalidKeyError
    with pytest.raises(InvalidKeyError):
        m.read_secret(tampered, key)
