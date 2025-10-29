from pathlib import Path
import hashlib, hmac
import pytest

from watermarking_utils import apply_watermark, read_watermark


def test_pdf_lsb_roundtrip_hashed(tmp_path):
    """Test that pdf-lsb now embeds a SHA-256/HMAC hash of the secret, not plaintext."""
    secret = "softsec-42"
    key = "k2"

    # Path to a small test PDF stored in test/data/
    infile = Path(__file__).parent / "data" / "sample.pdf"
    outfile = tmp_path / "out.pdf"

    # Ensure the sample PDF exists
    assert infile.exists(), f"Missing test PDF fixture: {infile}"

    # Embed watermark (this now writes the SHA-256 hash of the secret)
    wm_bytes = apply_watermark("pdf-lsb", infile, secret, key)
    outfile.write_bytes(wm_bytes)

    # Extract watermark
    recovered_hash = read_watermark("pdf-lsb", outfile, key)

    # Compute expected hash (using the same HMAC-SHA256 scheme as the code)
    expected_hash = hmac.new(key.encode(), secret.encode(), hashlib.sha256).hexdigest()

    # Verify that the embedded hash matches the expected one
    assert recovered_hash == expected_hash, (
        f"Recovered hash {recovered_hash} does not match expected {expected_hash}"
    )

    # ensure plaintext is not directly embedded
    assert "softsec" not in recovered_hash, "Plaintext secret leaked instead of hash"
