import io
import fitz
from PIL import Image
from lsb_image import LSBImageMethod, HEADER_BYTES
from watermarking_method import InvalidKeyError
from test_lsb_roundtrip import _pdf_with_png

def test_tamper_mac_fails():
    key = "1234567890abcdef1234567890abcdef"
    secret = "abc123"
    m = LSBImageMethod()

    # Build a simple PDF with an embeddable PNG and add the watermark
    pdf = _pdf_with_png(size=(128, 128))
    wm = m.add_watermark(pdf, secret, key)

    # Open the watermarked PDF and get the newest image (the method inserts / replaces last)
    doc = fitz.open(stream=wm)
    try:
        page = doc[0]
        xref = page.get_images()[-1][0]
        base = doc.extract_image(xref)

        # Load the image and flip one bit at the start of the MAC (keep header intact)
        pil = Image.open(io.BytesIO(base["image"])).convert("RGBA"); pil.load()
        w, h = pil.size

        # MAC starts after MAGIC(4) + SALT(16) + LEN(4) + SECRET
        secret_len = len(secret.encode("utf-8"))
        bit_index = 8 * (HEADER_BYTES + secret_len)  # starting bit of MAC

        px_index, chan = divmod(bit_index, 3)
        x = px_index % w
        y = px_index // w
        if y >= h:
            # Shouldn't happen with 128x128, but guard anyway
            x, y, chan = 0, 0, 0

        r, g, b, a = pil.getpixel((x, y))
        if chan == 0:
            r ^= 1
        elif chan == 1:
            g ^= 1
        else:
            b ^= 1
        pil.putpixel((x, y), (r, g, b, a))

        # Reinsert the tampered PNG as a tiny, on-page image (matches method fallback)
        out = io.BytesIO(); pil.save(out, format="PNG")
        rect = fitz.Rect(page.rect.x0 + 1, page.rect.y0 + 1,
                         page.rect.x0 + 2, page.rect.y0 + 2)
        page.insert_image(rect, stream=out.getvalue())

        bio = io.BytesIO(); doc.save(bio); tampered = bio.getvalue()
    finally:
        doc.close()

    # The MAC should fail → InvalidKeyError
    try:
        m.read_secret(tampered, key)
        assert False, "Expected InvalidKeyError"
    except InvalidKeyError:
        pass
