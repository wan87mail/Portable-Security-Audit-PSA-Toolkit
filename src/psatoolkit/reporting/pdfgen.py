"""Minimal, dependency-free PDF writer (PDF 1.4).

Supports what the report needs: A4 pages, the standard Helvetica /
Helvetica-Bold / Courier fonts (WinAnsi encoding, no embedding), word-wrapped
text, filled rectangles, lines, simple tables, Flate-compressed content
streams and document metadata. Text outside Windows-1252 is replaced with '?'.

Keeping this in the standard library means the portable Windows executable
needs no third-party PDF package.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

A4 = (595.28, 841.89)

# Glyph widths (1/1000 em) for WinAnsi codes 32..126, from the Adobe Core 14 AFM files.
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556,
         556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278,
         500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469,
         556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
         278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_HELV_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556,
              556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722,
              278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333,
              584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389,
              556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584]
FONTS = {"F1": ("Helvetica", _HELV), "F2": ("Helvetica-Bold", _HELV_BOLD), "F3": ("Courier", None)}
REGULAR, BOLD, MONO = "F1", "F2", "F3"


def encode(text: str) -> bytes:
    return text.encode("cp1252", errors="replace")


def text_width(text: str, font: str, size: float) -> float:
    widths = FONTS[font][1]
    total = 0
    for b in encode(text):
        if widths is None:
            total += 600
        elif 32 <= b <= 126:
            total += widths[b - 32]
        else:
            total += 600   # conservative for accented/punctuation glyphs
    return total * size / 1000


def pdf_string(text: str) -> str:
    out = []
    for b in encode(text):
        ch = chr(b)
        if ch in "\\()":
            out.append("\\" + ch)
        elif 32 <= b <= 126:
            out.append(ch)
        else:
            out.append(f"\\{b:03o}")
    return "(" + "".join(out) + ")"


def wrap(text: str, font: str, size: float, width: float) -> list[str]:
    """Greedy word wrap; very long words are broken by character."""
    lines: list[str] = []
    for para in (text or "").replace("\r", "").split("\n"):
        words = para.split(" ")
        current = ""
        for word in words:
            candidate = f"{current} {word}" if current else word
            if text_width(candidate, font, size) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            while text_width(word, font, size) > width:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], font, size) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines


Color = tuple[float, float, float]


def hex_color(value: str) -> Color:
    value = value.lstrip("#")
    return tuple(int(value[i:i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


@dataclass
class Page:
    ops: list[str] = field(default_factory=list)


class PdfDocument:
    def __init__(self, title: str, author: str = "", subject: str = "", size: tuple[float, float] = A4) -> None:
        self.title, self.author, self.subject = title, author, subject
        self.width, self.height = size
        self.pages: list[Page] = []

    def new_page(self) -> Page:
        page = Page()
        self.pages.append(page)
        return page

    # -- drawing primitives (y measured from the bottom, PDF convention) -----------
    @staticmethod
    def text(page: Page, x: float, y: float, text: str, font: str = REGULAR, size: float = 10,
             color: Color = (0, 0, 0)) -> None:
        page.ops.append(f"BT {color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg /{font} {size:.2f} Tf "
                        f"{x:.2f} {y:.2f} Td {pdf_string(text)} Tj ET")

    @staticmethod
    def rect(page: Page, x: float, y: float, w: float, h: float, fill: Color) -> None:
        page.ops.append(f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f")

    @staticmethod
    def line(page: Page, x1: float, y1: float, x2: float, y2: float, color: Color = (0.8, 0.8, 0.8),
             width: float = 0.6) -> None:
        page.ops.append(f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} RG {width:.2f} w "
                        f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    # -- serialisation ----------------------------------------------------------------
    def to_bytes(self, created: datetime | None = None) -> bytes:
        created = created or datetime.now(timezone.utc)
        objects: list[bytes] = []

        def add(obj: bytes) -> int:
            objects.append(obj)
            return len(objects)

        catalog_id = add(b"")            # placeholders, filled below
        pages_id = add(b"")
        font_ids = {}
        for key, (name, _w) in FONTS.items():
            font_ids[key] = add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>"
                                .encode())
        font_res = " ".join(f"/{k} {v} 0 R" for k, v in font_ids.items())
        page_ids = []
        for page in self.pages:
            stream = zlib.compress("\n".join(page.ops).encode("latin-1"), 9)
            content_id = add(b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream) + stream +
                             b"\nendstream")
            page_ids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.width:.2f} "
                                f"{self.height:.2f}] /Resources << /Font << {font_res} >> >> "
                                f"/Contents {content_id} 0 R >>".encode()))
        objects[pages_id - 1] = (f"<< /Type /Pages /Kids [{' '.join(f'{i} 0 R' for i in page_ids)}] "
                                 f"/Count {len(page_ids)} >>").encode()
        objects[catalog_id - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode()
        stamp = created.strftime("D:%Y%m%d%H%M%SZ")
        info_id = add(("<< /Title " + pdf_string(self.title) + " /Author " + pdf_string(self.author) +
                       " /Subject " + pdf_string(self.subject) + " /Producer (Portable Security Audit) "
                       f"/CreationDate ({stamp}) >>").encode("latin-1"))
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for i, obj in enumerate(objects, 1):
            offsets.append(len(out))
            out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
        xref = len(out)
        out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R /Info {info_id} 0 R >>\n"
                f"startxref\n{xref}\n%%EOF\n").encode()
        return bytes(out)


class Flow:
    """Top-to-bottom flowing layout with automatic page breaks and a footer."""

    def __init__(self, doc: PdfDocument, margin: float = 48, footer: str = "") -> None:
        self.doc, self.margin, self.footer = doc, margin, footer
        self.width = doc.width - 2 * margin
        self.page = doc.new_page()
        self.y = doc.height - margin

    @property
    def left(self) -> float:
        return self.margin

    def ensure(self, height: float) -> None:
        if self.y - height < self.margin + 24:
            self.page_break()

    def page_break(self) -> None:
        self.page = self.doc.new_page()
        self.y = self.doc.height - self.margin

    def space(self, h: float) -> None:
        self.y -= h

    def paragraph(self, text: str, size: float = 10, font: str = REGULAR, color: Color = (0.1, 0.12, 0.16),
                  indent: float = 0, leading: float = 1.35, width: float | None = None) -> None:
        avail = (width or self.width) - indent
        for line in wrap(text, font, size, avail):
            self.ensure(size * leading)
            self.y -= size * leading
            self.doc.text(self.page, self.left + indent, self.y + size * 0.25, line, font, size, color)

    def heading(self, text: str, level: int = 1, color: Color = (0.12, 0.31, 0.55)) -> None:
        size = {1: 18, 2: 14, 3: 11.5}[level]
        self.ensure(size * 3)
        self.space(size * (0.9 if level > 1 else 0.4))
        self.paragraph(text, size, BOLD, color)
        if level <= 2:
            self.space(3)
            self.doc.line(self.page, self.left, self.y, self.left + self.width, self.y, (0.78, 0.82, 0.88), 1)
        self.space(6)

    def key_values(self, rows: list[tuple[str, str]], key_width: float = 170, size: float = 9.5) -> None:
        for key, value in rows:
            lines = wrap(str(value), REGULAR, size, self.width - key_width)
            height = len(lines) * size * 1.35 + 3
            self.ensure(height)
            top = self.y
            self.doc.text(self.page, self.left, top - size * 1.1, key, BOLD, size, (0.35, 0.4, 0.46))
            for i, line in enumerate(lines):
                self.doc.text(self.page, self.left + key_width, top - size * 1.1 - i * size * 1.35, line,
                              REGULAR, size)
            self.y -= height
            self.doc.line(self.page, self.left, self.y + 1, self.left + self.width, self.y + 1, (0.9, 0.91, 0.93))

    def table(self, header: list[str], rows: list[list[str]], widths: list[float], size: float = 8.5,
              cell_colors: dict[tuple[int, int], Color] | None = None) -> None:
        total = sum(widths)
        widths = [w * self.width / total for w in widths]
        pad = 3

        def draw_row(cells: list[str], font: str, shade: Color | None, row_index: int) -> None:
            wrapped = [wrap(str(c), font, size, w - 2 * pad) for c, w in zip(cells, widths)]
            height = max(len(w) for w in wrapped) * size * 1.3 + 2 * pad
            if self.y - height < self.margin + 24:
                self.page_break()
                if row_index >= 0:
                    draw_row(header, BOLD, (0.93, 0.95, 0.97), -1)
            top = self.y
            if shade:
                self.doc.rect(self.page, self.left, top - height, self.width, height, shade)
            x = self.left
            for col, (lines, w) in enumerate(zip(wrapped, widths)):
                color = (cell_colors or {}).get((row_index, col))
                if color:
                    self.doc.rect(self.page, x + 1, top - height + 1, w - 2, height - 2, color)
                for i, line in enumerate(lines):
                    self.doc.text(self.page, x + pad, top - pad - size - i * size * 1.3, line, font, size,
                                  (1, 1, 1) if color else (0.1, 0.12, 0.16))
                x += w
            self.y -= height
            self.doc.line(self.page, self.left, self.y, self.left + self.width, self.y, (0.85, 0.87, 0.9), 0.5)

        draw_row(header, BOLD, (0.93, 0.95, 0.97), -1)
        for i, row in enumerate(rows):
            draw_row(row, REGULAR, None, i)

    def box(self, height: float, fill: Color) -> float:
        """Reserve a filled box of the given height; returns its top y."""
        self.ensure(height)
        top = self.y
        self.doc.rect(self.page, self.left, top - height, self.width, height, fill)
        self.y -= height
        return top

    def finish(self) -> None:
        total = len(self.doc.pages)
        for n, page in enumerate(self.doc.pages, 1):
            label = f"{self.footer}  -  Page {n} of {total}"
            self.doc.line(page, self.margin, self.margin - 6, self.doc.width - self.margin, self.margin - 6)
            self.doc.text(page, self.margin, self.margin - 20, label, REGULAR, 7.5, (0.4, 0.45, 0.5))
