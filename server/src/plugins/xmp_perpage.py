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
import io
import os
import hmac
import hashlib
import sys
from datetime import datetime, timezone  # timezone-aware ts

# OBS: absolut import från src-roten (inte relativ)
from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
)

import pikepdf

_NS_URI = "https://tatou.local/wm/1.0/"
_NS_PREF = "wm"


import hashlib  # (you already import it above)

def _key_to_bytes(key: str) -> bytes:
    """
    Derive a fixed 16-byte key from the provided string.
    - If the UTF-8 key is shorter than 16 bytes, expand via SHA-256 and take 16.
    - If longer, truncate to 16 (keeps compatibility / constant size).
    """
    kb = key.encode("utf-8", errors="strict")
    if len(kb) < 16:
        kb = hashlib.sha256(kb).digest()[:16]
    else:
        kb = kb[:16]
    return kb


def _hmac_hex(key_b: bytes, data_b: bytes) -> str:
    return hmac.new(key_b, data_b, hashlib.sha256).hexdigest()


def _xmp_get_any(xmp: pikepdf.Metadata, localname: str):
    """
    Tolerant hämtning: prova med prefix, med URI, som oprefixerat,
    och slutligen genom att skanna alla nycklar och ta en som slutar med lokalnamnet.
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
            "Key is accepted at any length; internally derived to 16 bytes. "
            "Position is ignored."
        )

    def is_watermark_applicable(
        self,
        pdf: PdfSource,
        position: Optional[str] = None,
    ) -> bool:
        data = load_pdf_bytes(pdf)
        return data.startswith(b"%PDF-")

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        print(
            f"[xmp-perpage] add_watermark called; secret_len={len(secret)}",
            file=sys.stdout, flush=True,
        )

        if not secret:
            raise ValueError("secret must be non-empty")
        if len(secret) > 128:
            raise ValueError("secret too long (max 128 chars)")

        key_b = _key_to_bytes(key)
        data = load_pdf_bytes(pdf)
        in_mem = io.BytesIO(data)
        out_mem = io.BytesIO()

        with pikepdf.open(in_mem) as doc:
            page_count = len(doc.pages)

            with doc.open_metadata(set_pikepdf_as_editor=False) as xmp:
                try:
                    xmp.register_namespace(_NS_PREF, _NS_URI)
                except Exception:
                    pass

                xmp[f"{_NS_PREF}:method"] = self.name
                xmp[f"{_NS_PREF}:page_count"] = str(page_count)
                xmp[f"{_NS_PREF}:secret"] = str(secret)
                # Timezone-aware ISO 8601, som '...Z'
                ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
                xmp[f"{_NS_PREF}:ts"] = [ts]  # pikepdf vill ha lista

                print(
                    f"[xmp-perpage] will write per-page tags; page_count={page_count}",
                    file=sys.stdout, flush=True,
                )

                for i in range(page_count):
                    salt = os.urandom(16).hex()  # 32 hex
                    mac = _hmac_hex(key_b, (salt + secret).encode("utf-8"))
                    xmp[f"{_NS_PREF}:p{i}_salt"] = salt
                    xmp[f"{_NS_PREF}:p{i}_mac"] = mac

            # Debug: lista nycklar efter skrivning
            with doc.open_metadata() as x2:
                try:
                    keys = sorted(list(x2.keys()))
                except Exception:
                    keys = []
                print("[xmp-perpage] XMP keys (first 15):", keys[:15], file=sys.stdout, flush=True)
                print("[xmp-perpage] wm:secret preview:", str(_xmp_get_any(x2, "secret"))[:40],
                      file=sys.stdout, flush=True)

            doc.save(out_mem)

        print("[xmp-perpage] finished writing XMP", file=sys.stdout, flush=True)
        return out_mem.getvalue()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        print("[xmp-perpage] read_secret called", file=sys.stdout, flush=True)

        key_b = _key_to_bytes(key)
        data = load_pdf_bytes(pdf)

        with pikepdf.open(io.BytesIO(data)) as doc:
            with doc.open_metadata() as xmp:
                try:
                    rkeys = sorted(list(xmp.keys()))
                except Exception:
                    rkeys = []
                print("[xmp-perpage] READ: keys (first 15):", rkeys[:15], file=sys.stdout, flush=True)

                secret = _xmp_get_any(xmp, "secret")
                page_count_str = _xmp_get_any(xmp, "page_count")

        print(
            f"[xmp-perpage] read XMP: secret_present={bool(secret)} page_count_str={page_count_str!r}",
            file=sys.stdout, flush=True,
        )

        if not secret:
            raise SecretNotFoundError("No wm:secret in XMP")
        try:
            page_count = int(str(page_count_str))
        except Exception:
            raise SecretNotFoundError("No/invalid wm:page_count in XMP")

        # Tillåt 0-sidiga PDF:er: om secret fanns räcker det
        if page_count == 0:
            return str(secret)

        pages_ok = 0
        for i in range(page_count):
            with pikepdf.open(io.BytesIO(data)) as doc:
                with doc.open_metadata() as xmp:
                    salt = _xmp_get_any(xmp, f"p{i}_salt")
                    mac = _xmp_get_any(xmp, f"p{i}_mac")

            ok = False
            if salt and mac:
                expected = _hmac_hex(key_b, (str(salt) + str(secret)).encode("utf-8"))
                ok = hmac.compare_digest(str(mac), expected)
                if ok:
                    pages_ok += 1

            print(
                f"[xmp-perpage] page {i}: has_salt={bool(salt)} has_mac={bool(mac)} ok={ok}",
                file=sys.stdout, flush=True,
            )

        print(f"[xmp-perpage] pages_ok={pages_ok}/{page_count}", file=sys.stdout, flush=True)

        if pages_ok == 0:
            raise InvalidKeyError("HMAC verification failed on all pages")

        return str(secret)
