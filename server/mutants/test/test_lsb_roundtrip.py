import io
import fitz
from PIL import Image
from lsb_image import LSBImageMethod

def _pdf_with_png(size=(128, 128)) -> bytes:
    # Build a one-page PDF and embed a PNG (so LSB has pixels to use)
    im = Image.new("RGB", size, (255, 255, 255))
    bio = io.BytesIO(); im.save(bio, format="PNG"); png = bio.getvalue()

    doc = fitz.open()
    page = doc.new_page(width=300, height=300)
    rect = fitz.Rect(50, 50, 50 + size[0], 50 + size[1])
    page.insert_image(rect, stream=png)
    out = io.BytesIO(); doc.save(out); doc.close()
    return out.getvalue()

def test_lsb_roundtrip():
    m = LSBImageMethod()
    key = "0" * 32
    secret = "abc123"
    pdf = _pdf_with_png()
    wm = m.add_watermark(pdf, secret, key)
    got = m.read_secret(wm, key)
    assert got == secret

def test_lsb_no_capacity_raises():
    # 4x4 image has capacity 4*4*3 = 48 bits, which is < header(64) + 8*len(secret)
    m = LSBImageMethod()
    key = "0" * 32
    pdf = _pdf_with_png(size=(4, 4))
    import pytest
    with pytest.raises(RuntimeError):
        m.add_watermark(pdf, "A", key)

