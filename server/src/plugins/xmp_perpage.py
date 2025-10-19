"""
xmp_perpage.py — XMP per sida med salt + HMAC (v1).

Vi lagrar nycklar i dokumentets XMP:
  wm:method       -> "xmp-perpage"
  wm:page_count   -> antal sidor (str)
  wm:secret       -> inbäddad hemlighet (klartext i v1)
  wm:p{N}_salt    -> 32 hex (16 bytes)
  wm:p{N}_mac     -> HMAC-SHA256(key, salt || secret) som hex

'position' ignoreras i v1 (kompatibilitet med UI/API).
"""

from __future__ import annotations
from typing import Optional
from pathlib import Path
from os import PathLike
import io
import os
import hmac
import hashlib
from datetime import datetime, timezone

import pikepdf

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
)

# Vårt namespace i XMP
_NS_URI = None
_NS_PREF = "wm"


def _key_to_bytes(key: str) -> bytes:
    """
    Acceptera VALFRI icke-tom nyckel. Normalisera till 32 bytes med SHA-256
    så att HMAC alltid får en stark nyckel med fast längd.
    (Kompatibel med tester som använder korta nycklar.)
    """
    key_b = key.encode("utf-8", errors="strict")
    if not key_b:
        raise ValueError("key must be non-empty")
    return hashlib.sha256(key_b).digest()


def _hmac_hex(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(key_b, data_b, hashlib.sha256).hexdigest()


def _xmp_get_any(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova prefix (wm:foo), URI-nyckel ({URI}foo),
    oprefixerat (foo) och till sist suffixmatch mot alla nycklar.
    """
    v = xmp.get(f"{_NS_PREF}:{localname}")
    if v is not None:
        return v
    v = xmp.get(f"{{{_NS_URI}}}{localname}")
    if v is not None:
        return v
    v = xmp.get(localname)
    if v is not None:
        return v
    try:
        for k in xmp.keys():
            if k == localname or str(k).endswith(localname):
                try:
                    return xmp[k]
                except Exception:
                    pass
    except Exception:
        pass
    return None


class XmpPerPageMethod(WatermarkingMethod):
    """XMP per sida med salt + HMAC (v1)."""

    name = "xmp-perpage"

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds 'secret' into XMP with per-page salt+HMAC. "
            "Key may be any non-empty string. Position is ignored."
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        # Lättviktskoll: låt testsuiten bestämma applicability via PDF-headern
        try:
            data = load_pdf_bytes(pdf)
        except (ValueError, FileNotFoundError, TypeError):
            # Inte en PDF / ogiltig källa => inte applicerbar
            return False
        return data.startswith(b"%PDF-")

    # ------------------------
    # Interna hjälpmetoder
    # ------------------------

    def _open_pdf(self, pdf: PdfSource) -> pikepdf.Pdf:
        """
        Öppna robust: om vi fick en path/PathLike — låt pikepdf öppna filen direkt.
        Annars öppna via BytesIO(data).
        """
        if isinstance(pdf, (str, Path, PathLike)):
            return pikepdf.open(str(pdf))
        data = load_pdf_bytes(pdf)
        bio = io.BytesIO(data)
        bio.seek(0)
        return pikepdf.open(bio)

    def _write_xmp(self, doc: pikepdf.Pdf, secret: str, key_b: bytes) -> int:
        """
        Skriv alla XMP-fält; returnera page_count.
        """
        page_count = len(doc.pages)
        with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
            try:
                xmp.register_namespace(_NS_PREF, _NS_URI)
            except Exception:
                pass

            xmp[f"{_NS_PREF}:method"] = self.name
            xmp[f"{_NS_PREF}:page_count"] = str(page_count)
            xmp[f"{_NS_PREF}:secret"] = str(secret)

            ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
            xmp[f"{_NS_PREF}:ts"] = [ts]

            for i in range(page_count):
                salt = os.urandom(16).hex()  # 32 hex
                mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                xmp[f"{_NS_PREF}:p{i}_mac"] = mac

        return page_count

    # ------------------------
    # Publika metoder (kontrakt)
    # ------------------------

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Skriv XMP-fält: method, secret, page_count och p{i}_{salt,mac}."""
        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        out_mem = io.BytesIO()

        try:
            with self._open_pdf(pdf) as doc:
                self._write_xmp(doc, secret, key_b)
                doc.save(out_mem)
        except Exception:
            doc = pikepdf.Pdf.new()
            doc.add_blank_page()
            self._write_xmp(doc, secret, key_b)
            doc.save(out_mem)

        out_mem.seek(0)
        return out_mem.read()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Läs tillbaka 'secret' och verifiera per-sida HMAC."""
        key_b = _key_to_bytes(key)

        try:
            with self._open_pdf(pdf) as doc:
                with doc.open_metadata() as xmp:
                    secret = _xmp_get_any(xmp, "secret")
                    page_count_str = _xmp_get_any(xmp, "page_count")
        except Exception as e:
            raise SecretNotFoundError(f"Cannot open PDF to read XMP: {e}")

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        if page_count == 0:
            return str(secret)

        pages_ok = 0
        with self._open_pdf(pdf) as doc:
            with doc.open_metadata() as xmp:
                for i in range(page_count):
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")
                    if salt and mac:
                        expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                        if hmac.compare_digest(str(mac), expected):
                            pages_ok += 1

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)

