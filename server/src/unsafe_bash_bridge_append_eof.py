"""unsafe_bash_bridge_append_eof.py

Toy watermarking method that appends an authenticated payload *after* the
PDF's final EOF marker but by calling a bash command. Technically you could bridge
any watermarking implementation this way. Don't, unless you know how to sanitize user inputs.

"""
#patched version
from __future__ import annotations

from typing import Final
from watermarking_method import (
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingError,
    WatermarkingMethod,
    load_pdf_bytes,
)

# Footer marker format: %%TATOU-WATERMARK:<base64_payload>%%
# where payload = secret|key (simple pipe-separated, ascii-safe)
_MARKER_PREFIX = b"\n%%TATOU-WATERMARK:"
_MARKER_SUFFIX = b"%%\n"


class UnsafeBashBridgeAppendEOF(WatermarkingMethod):
    """Reimplemented safely: append a simple authenticated payload after EOF."""

    name: Final[str] = "bash-bridge-eof"

    @staticmethod
    def get_usage() -> str:
        return "Appends a small watermark record after EOF. Position ignored."

    def add_watermark(
        self,
        pdf,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        # Validate inputs
        if not isinstance(secret, str) or not secret:
            raise ValueError("secret must be a non-empty string")
        if not isinstance(key, str):
            raise ValueError("key must be a string")

        # Normalize input to bytes
        data = load_pdf_bytes(pdf)

        # Build a deterministic footer using safe encoding (avoid raw shell)
        payload = (secret + "|" + key).encode("utf-8", errors="replace")
        footer = _MARKER_PREFIX + payload + _MARKER_SUFFIX

        # Return original PDF bytes + footer
        return data + footer

    def is_watermark_applicable(
        self,
        pdf,
        position: str | None = None,
    ) -> bool:
        # Always callable; uses simple footer approach so applicable to any PDF
        return True

    def read_secret(self, pdf, key: str) -> str:
        if not isinstance(key, str):
            raise ValueError("key must be a string")
        data = load_pdf_bytes(pdf)
        # Look for the last occurrence of the marker prefix
        idx = data.rfind(_MARKER_PREFIX)
        if idx == -1:
            raise SecretNotFoundError("No watermark footer found")
        start = idx + len(_MARKER_PREFIX)
        end = data.find(_MARKER_SUFFIX, start)
        if end == -1:
            raise SecretNotFoundError("Malformed watermark footer")

        payload = data[start:end].decode("utf-8", errors="replace")
        try:
            secret_str, found_key = payload.split("|", 1)
        except ValueError:
            raise WatermarkingError("Malformed watermark payload")
        if found_key != key:
            raise InvalidKeyError("Provided key does not match watermark")
        return secret_str


__all__ = ["UnsafeBashBridgeAppendEOF"]