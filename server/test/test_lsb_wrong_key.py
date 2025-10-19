# wrong key should raise
from lsb_image import LSBImageMethod
from watermarking_method import InvalidKeyError
from test_lsb_roundtrip import _pdf_with_png

def test_wrong_key_fails():
    m = LSBImageMethod()
    good = "1234567890abcdef1234567890abcdef"
    bad  = "ffffffffffffffffffffffffffffffff"
    pdf = _pdf_with_png()
    wm = m.add_watermark(pdf, "abc123", good)
    try:
        m.read_secret(wm, bad)
        assert False, "Expected InvalidKeyError"
    except InvalidKeyError:
        pass