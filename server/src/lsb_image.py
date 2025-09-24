# lsb_image.py
from __future__ import annotations
from io import BytesIO
from typing import Optional
import fitz  # PyMuPDF
from PIL import Image
from watermarking_method import WatermarkingMethod

def _text_to_bits(s: str) -> str:
    # UTF-8 bytes → bits with null terminator
    return "".join(f"{b:08b}" for b in s.encode("utf-8")) + "00000000"

def _bits_to_text(bits: str) -> str:
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = int(bits[i:i+8], 2)
        if b == 0:
            break
        out.append(b)
    return out.decode("utf-8", errors="ignore")

def _embed_bits_png(img_bytes: bytes, bits: str, channels=(0,1,2)) -> bytes:
    """Embed bits into RGBA image R,G,B LSBs; return PNG bytes."""
    img = Image.open(BytesIO(img_bytes)).convert("RGBA")
    px = img.load()
    w, h = img.size
    capacity = w * h * len(channels)
    if len(bits) > capacity:
        raise ValueError("Secret too large for first image capacity")

    it = iter(bits)
    done = False
    for y in range(h):
        for x in range(w):
            r,g,b,a = px[x, y]
            vals = [r,g,b,a]
            for idx in channels:
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
    img.save(out, format="PNG")  # lossless
    return out.getvalue()

def _extract_bits_png(img_bytes: bytes, max_bits=(1<<18), channels=(0,1,2)) -> str:
    img = Image.open(BytesIO(img_bytes)).convert("RGBA")
    px = img.load()
    w, h = img.size
    bits = []
    for y in range(h):
        for x in range(w):
            r,g,b,a = px[x, y]
            for idx, val in enumerate((r,g,b,a)):
                if idx in channels:
                    bits.append(str(val & 1))
                    if len(bits) >= max_bits:
                        return "".join(bits)
    return "".join(bits)

class LSBImageMethod(WatermarkingMethod):
    name = "lsb_image"
    description = "Invisible LSB watermark hidden in the first image inside the PDF."

    def is_applicable(self, pdf_path: str, position: Optional[str] = None) -> bool:
        try:
            doc = fitz.open(pdf_path)
            ok = any(doc.get_page_images(i) for i in range(len(doc)))
            doc.close()
            return ok
        except Exception:
            return False

    def apply(self, pdf_path: str, secret: str, key: str, position: Optional[str] = None) -> bytes:
        bits = _text_to_bits(secret)
        doc = fitz.open(pdf_path)
        replaced = False

        for pno in range(len(doc)):
            imgs = doc.get_page_images(pno)
            for xref, *_ in imgs:
                base = doc.extract_image(xref)
                new_png = _embed_bits_png(base["image"], bits)
                doc.update_stream(xref, new_png)  # replace image stream
                replaced = True
                break
            if replaced:
                break

        if not replaced:
            doc.close()
            raise RuntimeError("No embeddable image found in PDF")

        out = BytesIO()
        doc.save(out)
        doc.close()
        return out.getvalue()

    def read(self, pdf_path: str, key: str, position: Optional[str] = None) -> Optional[str]:
        doc = fitz.open(pdf_path)
        try:
            for pno in range(len(doc)):
                imgs = doc.get_page_images(pno)
                for xref, *_ in imgs:
                    base = doc.extract_image(xref)
                    bits = _extract_bits_png(base["image"])
                    txt = _bits_to_text(bits)
                    if txt:
                        return txt
            return None
        finally:
            doc.close()
