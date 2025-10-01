# server/test/test_xmp_perpage.py
import io
import pikepdf

from plugins.xmp_perpage import XmpPerPageMethod
from watermarking_method import InvalidKeyError


def _pdf_bytes(pages: int = 1) -> bytes:
    """Skapa en minimal PDF (pages sidor) helt i minnet."""
    buf = io.BytesIO()
    with pikepdf.new() as doc:
        for _ in range(pages):
            doc.add_blank_page()
        doc.save(buf)
    return buf.getvalue()


def test_roundtrip_embed_extract():
    m = XmpPerPageMethod()
    key = "1234567890abcdef1234567890abcdef"
    secret = "abc123"

    pdf = _pdf_bytes(1)
    wm = m.add_watermark(pdf, secret, key)
    got = m.read_secret(wm, key)
    assert got == secret

    # sanity: minst en sida har salt+mac i XMP
    with pikepdf.open(io.BytesIO(wm)) as doc:
        with doc.open_metadata() as x:
            page_count = int(str(x.get("page_count") or "0"))
            assert page_count >= 1
            assert x.get("p0_salt") is not None
            assert x.get("p0_mac") is not None


def test_wrong_key_fails():
    m = XmpPerPageMethod()
    pdf = _pdf_bytes(1)
    good_key = "1234567890abcdef1234567890abcdef"
    bad_key = "ffffffffffffffffffffffffffffffff"

    wm = m.add_watermark(pdf, "abc123", good_key)

    try:
        m.read_secret(wm, bad_key)
        assert False, "Expected InvalidKeyError"
    except InvalidKeyError:
        pass


def test_tamper_mac_fails():
    m = XmpPerPageMethod()
    key = "1234567890abcdef1234567890abcdef"
    pdf = _pdf_bytes(1)
    wm = m.add_watermark(pdf, "abc123", key)

    # Förvanska p0_mac i metadata
    bio = io.BytesIO(wm)
    with pikepdf.open(bio) as doc:
        with doc.open_metadata() as x:
            if x.get("p0_mac") is not None:
                x["p0_mac"] = "00" * 32
            else:
                # fallback (bör inte behövas med nuvarande skrivning)
                x["{https://tatou.local/wm/1.0/}p0_mac"] = "00" * 32
        out = io.BytesIO()
        doc.save(out)
        tampered = out.getvalue()

    try:
        m.read_secret(tampered, key)
        assert False, "Expected InvalidKeyError"
    except InvalidKeyError:
        pass
