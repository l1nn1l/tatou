from __future__ import annotations
from io import BytesIO
from typing import Optional
import fitz  # PyMuPDF
from PIL import Image
from watermarking_method import WatermarkingMethod, PdfSource

def _bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def _bits_to_bytes(bits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i+8], 2))
    return bytes(out)

MAGIC = b"LSB1"  # 4-byte marker

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
        bits = _text_to_bits(secret)
        doc = fitz.open(pdf)
        try:
            replaced = False

            for pno in range(len(doc)):
                for xref, *_ in doc.get_page_images(pno):
                    base = doc.extract_image(xref)
                    if not base or "image" not in base:
                        continue

                    # Load with Pillow; skip encodings Pillow can't decode
                    try:
                        pil = Image.open(BytesIO(base["image"])).convert("RGBA")
                        pil.load()
                    except Exception:
                        continue

                    # Embed into PIL pixels (RGB channels)
                    w, h = pil.size
                    capacity = w * h * 3  # R,G,B
                    if len(bits) > capacity:
                        continue

                    px = pil.load()
                    it = iter(bits)
                    done = False
                    for y in range(h):
                        for x in range(w):
                            r, g, b, a = px[x, y]
                            try:
                                r = (r & ~1) | int(next(it))
                                g = (g & ~1) | int(next(it))
                                b = (b & ~1) | int(next(it))
                            except StopIteration:
                                done = True
                            px[x, y] = (r, g, b, a)
                            if done:
                                break
                        if done:
                            break

                    # Replace image using a Pixmap constructed from RGBA samples
                    rgba = pil.tobytes()
                    pix = fitz.Pixmap(fitz.csRGBA, w, h, rgba)
                    doc.update_image(xref, pix)
                    replaced = True
                    break

                if replaced:
                    break

            if not replaced:
                raise RuntimeError("No embeddable RGB image with enough capacity")

            out = BytesIO()
            doc.save(out)
            return out.getvalue()
        finally:
            doc.close()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Return the embedded secret as str; return '' when not found."""
        doc = fitz.open(pdf)
        try:
            for pno in range(len(doc)):
                for xref, *_ in doc.get_page_images(pno):
                    base = doc.extract_image(xref)
                    if not base or "image" not in base:
                        continue
                    raw = base["image"]
                    # Only attempt if Pillow can decode
                    try:
                        Image.open(BytesIO(raw)).load()
                    except Exception:
                        continue
                    bits = _extract_bits_png(raw)
                    if not bits:
                        continue
                    text = _bits_to_text(bits)
                    if text:
                        return text
            return ""
        finally:
            doc.close()
