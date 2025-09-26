from __future__ import annotations
from io import BytesIO
from typing import Optional
import fitz  # PyMuPDF
from PIL import Image
from watermarking_method import WatermarkingMethod, PdfSource

def _bytes_to_bits(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def _bits_to_bytes(bits: str) -> bytes:
    # consume in 8-bit chunks
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        out.append(int(bits[i:i+8], 2))
    return bytes(out)

MAGIC = b"LSB1"  # 4-byte marker

def _text_to_bits(s: str) -> str:
    payload = s.encode("utf-8")
    header = MAGIC + len(payload).to_bytes(4, "big")
    data = header + payload
    return "".join(f"{byte:08b}" for byte in data)

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
    b = bytearray()
    for i in range(0, len(payload_bits), 8):
        b.append(int(payload_bits[i:i+8], 2))
    try:
        return bytes(b).decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _embed_bits_png(img_bytes: bytes, bits: str, channels=(0, 1, 2)) -> bytes:
    img = Image.open(BytesIO(img_bytes)).convert("RGBA")
    px = img.load()
    w, h = img.size
    capacity = w * h * len(channels)  # bits
    if len(bits) > capacity:
        raise ValueError(f"Secret too large for image capacity ({len(bits)} > {capacity})")

    it = iter(bits)
    done = False
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            vals = [r, g, b, a]
            for idx in channels:      # write into R,G,B LSBs
                try:
                    bit = next(it)
                except StopIteration:
                    done = True
                    break
                vals[idx] = (vals[idx] & ~1) | int(bit)
            px[x, y] = tuple(vals)
            if done:
                break
        if done:
            break

    out = BytesIO()
    img.save(out, format="PNG")  # keep it lossless
    return out.getvalue()

def _extract_bits_png(img_bytes: bytes, max_bits=(1 << 20)) -> str:
    """
    Read LSBs from R,G,B. Recognize MAGIC+LEN header and stop exactly at the end
    of the payload. If MAGIC doesn't match, return "" to signal "not found here".
    """
    img = Image.open(BytesIO(img_bytes)).convert("RGBA")
    px = img.load()
    w, h = img.size

    bits = []
    target = None  # total bits to read once header is known

    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            for v in (r, g, b):           # RGB only
                bits.append(str(v & 1))
                n = len(bits)

                # Once we have MAGIC (32) + LEN (32), compute target
                if n == 32:
                    # check MAGIC early; if not ours, bail out
                    magic = int("".join(bits[:32]), 2).to_bytes(4, "big")
                    if magic != MAGIC:
                        return ""          # this image doesn't carry our mark

                if n >= 64 and target is None:
                    length = int("".join(bits[32:64]), 2)
                    target = 64 + length * 8

                if target is not None and n >= target:
                    return "".join(bits[:target])

                if n >= max_bits:
                    # safety guard; but if header known and still not enough, stop anyway
                    return "".join(bits if target is None else bits[:min(n, target)])

    # end of image
    return "".join(bits if target is None else bits[:min(len(bits), target)])



class LSBImageMethod(WatermarkingMethod):
    """
    Invisible LSB watermark embedded in the first image stream found in the PDF.
    Fragile to heavy recompression/print-scan; fine for short tokens.
    """
    name = "lsb_image"
    description = "Hide short secret in LSBs of first embedded image (lossless)."

    # ----- interface required by your base class -----

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

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None,) -> bytes:
        bits = _text_to_bits(secret)
        doc = fitz.open(pdf)
        replaced = False

        try:
            for pno in range(len(doc)):
                for xref, *_ in doc.get_page_images(pno):
                    base = doc.extract_image(xref)
                    if not base or "image" not in base:
                        continue

                    raw = base["image"]

                    # Try to open with Pillow; skip images Pillow can’t read (JBIG2/CCITT)
                    try:
                        Image.open(BytesIO(raw)).load()
                    except Exception:
                        continue

                    # Embed our bits into an RGBA PNG (lossless)
                    new_png = _embed_bits_png(raw, bits)

                    # Replace image stream. Some encodings don’t like stream swap;
                    # try update_stream first, then fall back to Pixmap route.
                    try:
                        doc.update_stream(xref, new_png)
                        replaced = True
                    except Exception:
                        # Fallback: replace via Pixmap (more compatible)
                        try:
                            pix = fitz.Pixmap(new_png)  # PyMuPDF can read PNG bytes directly
                            doc.update_image(xref, pix)
                            replaced = True
                        except Exception:
                            continue  # try next image

                    if replaced:
                        break
                if replaced:
                    break

            if not replaced:
                raise RuntimeError("No embeddable image found (or unsupported image encoding)")

            out = BytesIO()
            doc.save(out)
            return out.getvalue()
        finally:
            doc.close()


    def read_secret(self, pdf: PdfSource, key: str) -> str:
    # must return str (use "" when not found)
        doc = fitz.open(pdf)
        try:
            for pno in range(len(doc)):
                for xref, *_ in doc.get_page_images(pno):
                    base = doc.extract_image(xref)
                    if not base or "image" not in base:
                        continue
                    raw = base["image"]
                    try:
                        Image.open(BytesIO(raw)).load()
                    except Exception:
                        continue
                    bits = _extract_bits_png(raw)
                    text = _bits_to_text(bits)
                    if text:
                        return text
            return ""  # ← return empty string, not None
        finally:
            doc.close()
