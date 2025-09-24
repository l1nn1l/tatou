# visible_stamp.py
from __future__ import annotations
from io import BytesIO
from typing import Optional
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

# import your base class
from watermarking_method import WatermarkingMethod

def _make_stamp_page(text: str, w: float, h: float,
                     font="Helvetica-Bold", font_size=36,
                     opacity=0.18, angle=45) -> BytesIO:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=(w, h))
    try:
        # some reportlab versions lack setFillAlpha; best-effort
        c.setFillAlpha(opacity)
    except Exception:
        pass
    c.saveState()
    c.translate(w/2, h/2)
    c.rotate(angle)
    c.setFont(font, font_size)
    c.drawCentredString(0, 0, text)
    c.restoreState()
    c.showPage()
    c.save()
    buf.seek(0)
    return buf

class VisibleStampMethod(WatermarkingMethod):
    name = "visible"
    description = "Overlay visible diagonal text on each page and store secret in PDF metadata."

    def is_applicable(self, pdf_path: str, position: Optional[str] = None) -> bool:
        try:
            r = PdfReader(pdf_path)
            return len(r.pages) > 0
        except Exception:
            return False

    def apply(self, pdf_path: str, secret: str, key: str, position: Optional[str] = None) -> bytes:
        reader = PdfReader(pdf_path)
        writer = PdfWriter()
        for page in reader.pages:
            w = float(page.mediabox.width)
            h = float(page.mediabox.height)
            stamp_pdf = _make_stamp_page(f"TATOU {secret}", w, h)
            stamp_reader = PdfReader(stamp_pdf)
            page.merge_page(stamp_reader.pages[0])
            writer.add_page(page)

        # keep existing metadata and add our field
        meta = dict(reader.metadata or {})
        meta["/TatouSecret"] = secret
        writer.add_metadata(meta)

        out = BytesIO()
        writer.write(out)
        return out.getvalue()

    def read(self, pdf_path: str, key: str, position: Optional[str] = None) -> Optional[str]:
        try:
            r = PdfReader(pdf_path)
            meta = r.metadata or {}
            s = meta.get("/TatouSecret")
            return s if isinstance(s, str) and s else None
        except Exception:
            return None
