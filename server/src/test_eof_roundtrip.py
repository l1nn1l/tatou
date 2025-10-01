import io
import fitz
from add_after_eof import AddAfterEOF

def _blank_pdf() -> bytes:
    doc = fitz.open()
    doc.new_page()
    out = io.BytesIO(); doc.save(out); doc.close()
    return out.getvalue()

def test_eof_roundtrip():
    m = AddAfterEOF()
    key = "1234567890abcdef1234567890abcdef"
    secret = "xyz789"
    pdf = _blank_pdf()
    wm = m.add_watermark(pdf, secret, key)
    got = m.read_secret(wm, key)
    assert got == secret
