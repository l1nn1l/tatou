from pathlib import Path

from watermarking_utils import apply_watermark, read_watermark


def test_pdf_lsb_roundtrip(tmp_path):
    """Test that a watermark embedded with pdf-lsb can be correctly read back."""
    secret = "softsec-42"
    key = "k2"

    # Path to a small test PDF stored in test/data/
    infile = Path(__file__).parent / "data" / "sample.pdf"
    outfile = tmp_path / "out.pdf"

    # Ensure the sample PDF exists
    assert infile.exists(), f"Missing test PDF fixture: {infile}"

    # Embed watermark
    wm_bytes = apply_watermark("pdf-lsb", infile, secret, key)
    outfile.write_bytes(wm_bytes)

    # Extract watermark
    recovered = read_watermark("pdf-lsb", outfile, key)

    # Verify roundtrip integrity
    assert recovered == secret
