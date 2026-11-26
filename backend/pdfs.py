"""Render the markdown-ish patent documents to PDF with reportlab."""
import io
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], fontSize=18, spaceAfter=10, textColor=colors.HexColor("#E64A19"))
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=6)
H3 = ParagraphStyle("h3", parent=_ss["Heading3"], fontSize=11, spaceBefore=6, spaceAfter=4)
BODY = ParagraphStyle("b", parent=_ss["BodyText"], fontSize=9.5, leading=13)
BUL = ParagraphStyle("li", parent=BODY, leftIndent=14, bulletIndent=4)
CODE = ParagraphStyle("code", parent=_ss["Code"], fontSize=7.2, leading=8.6, backColor=colors.HexColor("#F3F3F3"))


def _inline(t: str) -> str:
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    return re.sub(r"`(.+?)`", r"<font face='Courier'>\1</font>", t)


def render_pdf(title: str, markdown: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=LETTER, leftMargin=0.8 * inch, rightMargin=0.8 * inch, topMargin=0.7 * inch,
                            bottomMargin=0.7 * inch, title=title, author="Passtate")
    flow, code, table = [], None, None
    for line in markdown.splitlines() + [""]:
        if line.startswith("```"):
            if code is None:
                code = []
            else:
                flow.append(Preformatted("\n".join(code), CODE))
                flow.append(Spacer(1, 6))
                code = None
            continue
        if code is not None:
            code.append(line)
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("-: ") for c in cells):
                continue
            table = table or []
            table.append([Paragraph(_inline(c), BODY) for c in cells])
            continue
        if table:
            t = Table(table, repeatRows=1, colWidths=[(doc.width / len(table[0]))] * len(table[0]))
            t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FFE0D6")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
            flow += [t, Spacer(1, 8)]
            table = None
        if line.startswith("# "):
            flow.append(Paragraph(_inline(line[2:]), H1))
        elif line.startswith("## "):
            flow.append(Paragraph(_inline(line[3:]), H2))
        elif line.startswith("### "):
            flow.append(Paragraph(_inline(line[4:]), H3))
        elif re.match(r"^\s*[-*] ", line):
            flow.append(Paragraph(_inline(re.sub(r"^\s*[-*] ", "", line)), BUL, bulletText="•"))
        elif re.match(r"^\d+\. ", line):
            n, rest = line.split(". ", 1)
            flow.append(Paragraph(_inline(rest), BUL, bulletText=f"{n}."))
        elif line.strip():
            flow.append(Paragraph(_inline(line), BODY))
        else:
            flow.append(Spacer(1, 4))
    footer = "Passtate — confidential draft prepared to brief a patent attorney. Not a filing and not legal advice."

    def on_page(canvas, d):
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.grey)
        canvas.drawString(d.leftMargin, 0.4 * inch, footer)
        canvas.drawRightString(d.pagesize[0] - d.rightMargin, 0.4 * inch, f"Page {d.page}")

    doc.build(flow, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
