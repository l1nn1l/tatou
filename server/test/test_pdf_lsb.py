from watermarking_utils import apply_watermark, read_watermark

def test_pdf_lsb_roundtrip(tmp_path):
    secret = "softsec-42"
    key = "k2"
    infile = "sample.pdf"   # put a small test PDF in tests/data or similar
    outfile = tmp_path / "out.pdf"

    # Embed watermark
    wm_bytes = apply_watermark("pdf-lsb", infile, secret, key)
    outfile.write_bytes(wm_bytes)

    # Extract watermark
    recovered = read_watermark("pdf-lsb", outfile, key)
    assert recovered == secret
