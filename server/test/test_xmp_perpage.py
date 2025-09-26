# server/test/test_xmp_perpage.py
from pathlib import Path
import io
import pikepdf

from plugins.xmp_perpage import XmpPerPageMethod
from watermarking_method import InvalidKeyError

# Test-PDF i repo-roten ligger i containern som /app/softsecPDF.pdf
SAMPLE_PDF = Path(__file__).resolve().parents[1] / "sample.pdf"

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
            page_count = int(str(x.get("page_count") or x.get("{https://tatou.local/wm/1.0/}page_count")))
            assert page_count >= 1
            assert x.get("p0_salt") or x.get("{https://tatou.local/wm/1.0/}p0_salt")
            assert x.get("p0_mac")  or x.get("{https://tatou.local/wm/1.0/}p0_mac")

def test_wrong_key_fails():
    m = XmpPerPageMethod()
    pdf = _read_bytes(SAMPLE_PDF)
    good_key = "1234567890abcdef1234567890abcdef"
    bad_key  = "ffffffffffffffffffffffffffffffff"
    wm = m.add_watermark(pdf, "abc123", good_key)

    # Fel nyckel -> InvalidKeyError
    try:
        m.read_secret(wm, bad_key)
        assert False, "Expected InvalidKeyError"
    except InvalidKeyError:
        pass

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
                x["p0_mac"] = "00"*32
            else:
                x["{https://tatou.local/wm/1.0/}p0_mac"] = "00"*32
        out = io.BytesIO()
        doc.save(out)
        tampered = out.getvalue()

    # Rätt nyckel men manipulerat -> InvalidKeyError
    try:
        m.read_secret(tampered, key)
        assert False, "Expected InvalidKeyError"
    except InvalidKeyError:
        pass
