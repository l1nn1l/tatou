# watermarking_dct.py
from __future__ import annotations
from typing import Final
import io

import fitz  # PyMuPDF
import numpy as np
from PIL import Image

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
)


class LSBWatermark(WatermarkingMethod):
    """Simplified robust watermark using pixel LSB embedding on first page."""

    name: Final[str] = "pdf-lsb"

    @staticmethod
    def get_usage() -> str:
        return "Embed secret in LSBs of first-page raster image. Position/key ignored."

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            data = load_pdf_bytes(pdf)
            doc = fitz.open(stream=data, filetype="pdf")
            ok = doc.page_count > 0
            doc.close()
            return ok
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        if not secret:
            raise ValueError("Secret must be non-empty")

        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        page = doc[0]

        # Rasterize to grayscale
        pix = page.get_pixmap(dpi=150)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples).convert("L")
        g = np.array(img)

        # # Flatten pixels
        # flat = g.flatten()

        # # Secret to bits
        # secret_bytes = secret.encode("utf-8")
        # secret_bits = [int(b) for ch in secret_bytes for b in f"{ch:08b}"]

        # if len(secret_bits) + 16 > len(flat):
        #     doc.close()
        #     raise ValueError("Secret too long for available pixels")

        # # Encode length (16 bits)
        # length = len(secret_bits)
        # length_bits = f"{length:016b}"
        # for i, b in enumerate(length_bits):
        #     flat[i] = (flat[i] & 0xFE) | int(b)

        # # Encode secret bits
        # for i, bit in enumerate(secret_bits, start=16):
        #     flat[i] = (flat[i] & 0xFE) | bit

        # Flatten pixels
        flat = g.flatten()

        # Secret to bits
        secret_bytes = secret.encode("utf-8")
        secret_bits = [int(b) for ch in secret_bytes for b in f"{ch:08b}"]

        if len(secret_bits) + 16 > len(flat):
            doc.close()
            raise ValueError("Secret too long for available pixels")

        # Keyed shuffle of pixel positions
        import hashlib
        rng = np.random.default_rng(int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big"))
        positions = np.arange(len(flat))
        rng.shuffle(positions)

        # Encode length (16 bits) in first 16 chosen positions
        length = len(secret_bits)
        length_bits = f"{length:016b}"
        for i, b in enumerate(length_bits):
            pos = positions[i]
            flat[pos] = (flat[pos] & 0xFE) | int(b)

        # Encode secret bits in the following positions
        for i, bit in enumerate(secret_bits, start=16):
            pos = positions[i]
            flat[pos] = (flat[pos] & 0xFE) | bit


        # Reshape back
        g2 = flat.reshape(g.shape)

        # Save as PNG and insert into a fresh page
        buf = io.BytesIO()
        Image.fromarray(g2.astype(np.uint8)).save(buf, format="PNG")

        px_w, px_h = pix.width, pix.height
        pt_w = px_w * 72.0 / 150
        pt_h = px_h * 72.0 / 150
        rect = fitz.Rect(0, 0, pt_w, pt_h)

        doc.delete_page(0)
        new_page = doc.new_page(width=pt_w, height=pt_h)
        new_page.insert_image(rect, stream=buf.getvalue())

        out = io.BytesIO()
        doc.save(out)
        doc.close()
        return out.getvalue()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        page = doc[0]

        # Extract largest image
        imgs = page.get_images(full=True)
        if not imgs:
            doc.close()
            raise SecretNotFoundError("No images found in PDF")

        best = None
        best_area = -1
        for im in imgs:
            xref = im[0]
            info = doc.extract_image(xref)
            w = int(info.get("width", 0) or 0)
            h = int(info.get("height", 0) or 0)
            area = w * h
            if area > best_area and info.get("image"):
                best = info
                best_area = area
        doc.close()

        if not best or not best.get("image"):
            raise SecretNotFoundError("Failed to extract embedded image")

        img = Image.open(io.BytesIO(best["image"])).convert("L")
        g = np.array(img)
        flat = g.flatten()

        # # Decode length (first 16 bits)
        # length_bits = [str(flat[i] & 1) for i in range(16)]
        # length = int("".join(length_bits), 2)
        # if length <= 0 or length > len(flat) - 16:
        #     raise SecretNotFoundError("Invalid embedded length")

        # # Decode payload
        # payload_bits = [str(flat[i] & 1) for i in range(16, 16 + length)]

        # Keyed shuffle of pixel positions (same as embed)
        import hashlib
        rng = np.random.default_rng(int.from_bytes(hashlib.sha256(key.encode()).digest()[:8], "big"))
        positions = np.arange(len(flat))
        rng.shuffle(positions)

        # Decode length
        length_bits = [str(flat[positions[i]] & 1) for i in range(16)]
        length = int("".join(length_bits), 2)
        if length <= 0 or length > len(flat) - 16:
            raise SecretNotFoundError("Invalid embedded length")

        # Decode payload
        payload_bits = [str(flat[positions[i]] & 1) for i in range(16, 16 + length)]

        chars = []
        for i in range(0, len(payload_bits), 8):
            byte = payload_bits[i:i + 8]
            if len(byte) < 8:
                break
            chars.append(int("".join(byte), 2))
        try:
            return bytes(chars).decode("utf-8", errors="ignore")
        except Exception:
            raise SecretNotFoundError("Failed to decode embedded secret")


__all__ = ["DCTWatermark"]
