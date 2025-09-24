# quick_test.py
import sys
from watermarking_utils import apply_watermark, read_watermark, is_watermarking_applicable

src = "sample.pdf"          # a small PDF; for lsb_image, make sure it has at least one image
out_visible = "out_visible.pdf"
out_lsb = "out_lsb.pdf"

# Visible
if is_watermarking_applicable("visible", src):
    vb = apply_watermark(src, secret="TEST-VISIBLE-123", key="k", method="visible")
    open(out_visible, "wb").write(vb)
    print("visible extracted:", read_watermark("visible", out_visible, key="k"))
else:
    print("visible: not applicable")

# LSB
if is_watermarking_applicable("lsb_image", src):
    lb = apply_watermark(src, secret="SECRET-XYZ", key="k", method="lsb_image")
    open(out_lsb, "wb").write(lb)
    print("lsb extracted:", read_watermark("lsb_image", out_lsb, key="k"))
else:
    print("lsb_image: not applicable (PDF probably has no images)")
