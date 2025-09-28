from __future__ import annotations
from io import BytesIO
from typing import Optional
import fitz  # PyMuPDF
from PIL import Image
from watermarking_method import WatermarkingMethod, PdfSource
import os, hmac, hashlib
from watermarking_method import InvalidKeyError

MAGIC = b"LSB1"      # 4-byte marker
HEADER_BYTES = 4 + 16 + 4  # MAGIC + SALT + LEN
MAC_BYTES = 32

def _pack_u32(n: int) -> bytes:
    return n.to_bytes(4, "big")

def _unpack_u32(b: bytes) -> int:
    return int.from_bytes(b, "big")

def _bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def _bits_to_bytes(bits: str) -> bytes:
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits) - 7, 8))


def _text_to_bits(s: str) -> str:
    payload = s.encode("utf-8")
    header = MAGIC + len(payload).to_bytes(4, "big")
    data = header + payload
    return _bytes_to_bits(data)

def _bits_to_text(bits: str) -> str:
    # need at least magic (32) + length (32) bits
    if len(bits) < 64:
        return ""
    magic = int(bits[0:32], 2).to_bytes(4, "big")
    if magic != MAGIC:
        return ""
    n = int(bits[32:64], 2)
    need = 64 + n * 8
    if len(bits) < need:
        return ""
    payload_bits = bits[64:need]
    try:
        return _bits_to_bytes(payload_bits).decode("utf-8")
    except UnicodeDecodeError:
        return ""

def _extract_bits_png(img_bytes: bytes, max_bits=(1 << 20)) -> str:
    """
    Read LSBs from R,G,B. Recognize MAGIC+LEN header and stop exactly at the end
    of the payload. If MAGIC doesn't match, return "" to signal 'not found here'.
    """
    img = Image.open(BytesIO(img_bytes)).convert("RGBA")
    px = img.load()
    w, h = img.size

    bits = []
    target = None  # total bits to read once header is known

    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            for v in (r, g, b):  # RGB only
                bits.append(str(v & 1))
                n = len(bits)

                if n == 32:
                    magic = int("".join(bits[:32]), 2).to_bytes(4, "big")
                    if magic != MAGIC:
                        return ""  # not our payload

                if n >= 64 and target is None:
                    length = int("".join(bits[32:64]), 2)
                    target = 64 + length * 8

                if target is not None and n >= target:
                    return "".join(bits[:target])

                if n >= max_bits:
                    return "".join(bits if target is None else bits[:min(n, target)])

    return "".join(bits if target is None else bits[:min(len(bits), target)])

class LSBImageMethod(WatermarkingMethod):
    """
    Invisible LSB watermark embedded in the first image stream found in the PDF.
    Fragile to heavy recompression/print-scan; fine for short tokens.
    """
    name = "lsb_image"
    description = "Hide short secret in LSBs of first embedded image (lossless)."

    def get_usage(self) -> str:
        return "params: method='lsb_image', key=<str>, secret=<str>, position(optional)"

    def is_watermark_applicable(self, pdf: str, position: Optional[str] = None) -> bool:
        try:
            doc = fitz.open(pdf)
            ok = any(doc.get_page_images(i) for i in range(len(doc)))
            doc.close()
            return ok
        except Exception:
            return False

    def add_watermark(
        self, pdf: PdfSource, secret: str, key: str, position: str | None = None
    ) -> bytes:
        # Build payload: MAGIC(4) | SALT(16) | LEN(4) | SECRET | MAC(32)
        secret_bytes = secret.encode("utf-8")
        salt = os.urandom(16)

        try:
            key_bytes = bytes.fromhex(key)  # key is a hex string
        except ValueError:
            raise InvalidKeyError("Key must be a hex string")
        
        mac = hmac.new(key_bytes, salt + secret_bytes, hashlib.sha256).digest()
        payload = MAGIC + salt + _pack_u32(len(secret_bytes)) + secret_bytes + mac
        bits = _bytes_to_bits(payload)


        # Open from bytes or path
        doc = fitz.open(stream=pdf) if isinstance(pdf, (bytes, bytearray)) else fitz.open(pdf)
        try:
            for pno in range(len(doc)):
                for xref, *_ in doc.get_page_images(pno):
                    base = doc.extract_image(xref)
                    raw = base.get("image")
                    if not raw:
                        continue

                    # Decode image via Pillow
                    try:
                        pil = Image.open(BytesIO(raw)).convert("RGBA")
                        pil.load()
                    except Exception:
                        continue

                    w, h = pil.size
                    capacity = w * h * 3  # RGB channels only
                    if capacity < len(bits):
                        continue  # too small; try next image

                    # Embed bits in y, x order; channels R, G, B (leave alpha)
                    px = pil.load()
                    i = 0
                    for y in range(h):
                        for x in range(w):
                            r, g, b, a = px[x, y]
                            if i < len(bits):
                                r = (r & 0xFE) | (bits[i] == "1"); i += 1
                            if i < len(bits):
                                g = (g & 0xFE) | (bits[i] == "1"); i += 1
                            if i < len(bits):
                                b = (b & 0xFE) | (bits[i] == "1"); i += 1
                            px[x, y] = (r, g, b, a)
                            if i >= len(bits):
                                break
                        if i >= len(bits):
                            break

                    # ---- build PNG bytes and / or a pixmap ----
                    # (We already modified 'pil' pixels with the secret)
                    emb_png_bio = BytesIO()
                    pil.save(emb_png_bio, format="PNG")          # lossless, preserves LSBs
                    emb_png = emb_png_bio.getvalue()

                    # also try a Pixmap path (some builds prefer this)
                    rgb = pil.convert("RGB")
                    samples = rgb.tobytes()
                    w, h = rgb.size

                    # get Page object
                    page = doc[pno]

                    # ---- attempt 1: replace using a Pixmap (older API variants) ----
                    pix = None
                    try:
                        try:
                            # signature: Pixmap(colorspace, (w, h), samples)
                            pix = fitz.Pixmap(fitz.csRGB, (w, h), samples)
                        except Exception:
                            # fallback signature: Pixmap(colorspace, w, h, samples, alpha=False)
                            pix = fitz.Pixmap(fitz.csRGB, w, h, samples, 0)

                        # Some 1.26.x builds have replace_image(xref, new_xref) only.
                        # This will raise TypeError if (xref, pix) is unsupported.
                        page.replace_image(xref, pix)   # may raise TypeError
                        del pix

                    except TypeError:
                        # Fallback: insert edited PNG as a tiny, on-page image (1x1 point)
                        rect = fitz.Rect(page.rect.x0 + 1, page.rect.y0 + 1, page.rect.x0 + 2, page.rect.y0 + 2)
                        page.insert_image(rect, stream=emb_png)

                    # ---- save and return the modified PDF ----
                    buf = BytesIO()
                    doc.save(buf)
                    return buf.getvalue()

            # No image had enough capacity
            raise RuntimeError("No suitable image found to embed payload")
        finally:
            doc.close()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        def _extract_bits_from_pil(pil: Image.Image, need_bits: int | None = None) -> str:
            w, h = pil.size
            px = pil.convert("RGBA").load()
            bits = []
            for y in range(h):
                for x in range(w):
                    r, g, b, a = px[x, y]
                    bits.append("1" if (r & 1) else "0")
                    bits.append("1" if (g & 1) else "0")
                    bits.append("1" if (b & 1) else "0")
                    if need_bits is not None and len(bits) >= need_bits:
                        return "".join(bits[:need_bits])
            return "".join(bits)

        doc = fitz.open(stream=pdf) if isinstance(pdf, (bytes, bytearray)) else fitz.open(pdf)
        try:
            for pno in range(len(doc)):
                imgs = list(doc.get_page_images(pno))
                for xref, *_ in reversed(imgs):
                    base = doc.extract_image(xref)
                    raw = base.get("image")
                    if not raw:
                        continue
                    try:
                        pil = Image.open(BytesIO(raw))
                        pil.load()
                    except Exception:
                        continue

                    # Read only header first: MAGIC(4) + SALT(16) + LEN(4)
                    hdr_bits = _extract_bits_from_pil(pil, 8 * HEADER_BYTES)
                    if len(hdr_bits) < 8 * HEADER_BYTES:
                        continue
                    header = _bits_to_bytes(hdr_bits)

                    magic = header[0:4]
                    if magic != MAGIC:
                        continue
                    salt  = header[4:20]
                    dlen  = _unpack_u32(header[20:24])

                    # Now read the rest: data + MAC
                    total_bytes = HEADER_BYTES + dlen + MAC_BYTES
                    all_bits = _extract_bits_from_pil(pil, 8 * total_bytes)
                    if len(all_bits) < 8 * total_bytes:
                        continue

                    blob   = _bits_to_bytes(all_bits)
                    data   = blob[HEADER_BYTES : HEADER_BYTES + dlen]
                    macgot = blob[HEADER_BYTES + dlen : HEADER_BYTES + dlen + MAC_BYTES]

                    # Verify MAC
                    try:
                        key_bytes = bytes.fromhex(key)
                    except ValueError:
                        raise InvalidKeyError("Key must be a hex string")
                    macexp = hmac.new(key_bytes, salt + data, hashlib.sha256).digest()
                    if not hmac.compare_digest(macgot, macexp):
                        raise InvalidKeyError("MAC check failed (wrong key or tampered)")

                    return data.decode("utf-8")


            return ""  # nothing found
        finally:
            doc.close()