from __future__ import annotations
from io import BytesIO
from typing import Optional
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from watermarking_method import WatermarkingMethod

def _make_stamp_page(text: str, w: float, h: float,
                     font="Helvetica-Bold", font_size=36,
                     opacity=0.18, angle=45) -> BytesIO:
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=(w, h))
    try:
        c.setFillAlpha(opacity)  # some reportlab builds lack this; best effort
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
    """
    Overlay a visible diagonal stamp that includes the secret.
    Also stores the secret in PDF metadata (/TatouSecret) for deterministic readout.
    """
    name = "visible"
    description = "Visible diagonal text overlay + metadata field (/TatouSecret)."

    # ----- interface required by your base class -----

    def get_usage(self) -> str:
        # Keep it simple; your teacher’s CLI uses this for help text
        return "params: method='visible', key=<str>, secret=<str>, position(optional)"

    def is_watermark_applicable(self, pdf: str, position: Optional[str] = None) -> bool:
        try:
            r = PdfReader(pdf)
            return len(r.pages) > 0
        except Exception:
            return False

    def add_watermark(self, pdf: str, secret: str, key: str,
                      position: Optional[str] = None) -> bytes:
        reader = PdfReader(pdf)
        writer = PdfWriter()

        for page in reader.pages:
            w = float(page.mediabox.width)
            h = float(page.mediabox.height)
            stamp_pdf = _make_stamp_page(f"TATOU {secret}", w, h)
            stamp_reader = PdfReader(stamp_pdf)
            page.merge_page(stamp_reader.pages[0])
            writer.add_page(page)

        meta = dict(reader.metadata or {})
        meta["/TatouSecret"] = secret
        meta["TatouSecret"] = secret       # tolerance for readers/writers that drop the slash
        writer.add_metadata(meta)


        out = BytesIO()
        writer.write(out)
        return out.getvalue()

    def read_secret(self, pdf: str, key: str, position: Optional[str] = None) -> Optional[str]:
        try:
            r = PdfReader(pdf)
            meta = r.metadata or {}

            # handle both styles and odd objects
            val = (meta.get("/TatouSecret")
                or meta.get("TatouSecret")
                or meta.get("tatou_secret"))
            if val is None:
                return None

            s = str(val).strip()
            return s if s else None
        except Exception:
            return None
