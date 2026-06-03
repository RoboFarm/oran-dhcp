#!/usr/bin/env python3
"""Strict Markdown -> .docx converter (Python standard library only).

Supports the constrained Markdown subset used by the project's generated
documents: ATX headings (#..####), paragraphs with **bold** and `inline code`,
fenced code blocks (``` delimited), '- ' bullet lists, '1. ' numbered lists,
GitHub pipe tables, and a literal [[PAGEBREAK]] marker line.

It emits a valid Office Open XML (WordprocessingML) package using only zipfile
and string templating -- no third-party dependencies.

Usage:
    python3 tools/md_to_docx.py INPUT.md OUTPUT.docx [--title "Doc Title"]
"""
from __future__ import annotations

import argparse
import re
import sys
import zipfile

# --------------------------------------------------------------------------
# XML helpers
# --------------------------------------------------------------------------

def xml_escape(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def attr_escape(text: str) -> str:
    return xml_escape(text).replace('"', "&quot;")


# --------------------------------------------------------------------------
# Inline parsing: produce a list of runs (text, bold, code)
# --------------------------------------------------------------------------

_INLINE = re.compile(r"\*\*(.+?)\*\*|`([^`]+)`")
_CODE_ONLY = re.compile(r"`([^`]+)`")


def inline_runs(text):
    """Return a list of (text, bold, code) tuples.

    Bold may wrap inline code (``**run `x` now**``); inline code is literal and
    never reparsed for bold. Bold is matched at the top level first so its
    markers never leak when it spans a code span.
    """
    runs = []
    pos = 0
    for m in _INLINE.finditer(text):
        if m.start() > pos:
            runs.append((text[pos:m.start()], False, False))
        if m.group(1) is not None:  # **bold** (may contain code spans)
            for seg_text, seg_code in _code_split(m.group(1)):
                runs.append((seg_text, True, seg_code))
        else:                       # `code`
            runs.append((m.group(2), False, True))
        pos = m.end()
    if pos < len(text):
        runs.append((text[pos:], False, False))
    return runs or [("", False, False)]


def _code_split(text):
    """Split text into (segment, is_code) pairs on backtick code spans."""
    out = []
    pos = 0
    for m in _CODE_ONLY.finditer(text):
        if m.start() > pos:
            out.append((text[pos:m.start()], False))
        out.append((m.group(1), True))
        pos = m.end()
    if pos < len(text):
        out.append((text[pos:], False))
    return out or [("", False)]


def runs_to_xml(text, base_bold=False, base_code=False):
    out = []
    for t, bold, code in inline_runs(text):
        bold = bold or base_bold
        code = code or base_code
        rpr = []
        if code:
            rpr.append('<w:rStyle w:val="CodeChar"/>')
        if bold:
            rpr.append("<w:b/>")
        rpr_xml = f"<w:rPr>{''.join(rpr)}</w:rPr>" if rpr else ""
        out.append(
            f'<w:r>{rpr_xml}<w:t xml:space="preserve">{xml_escape(t)}</w:t></w:r>'
        )
    return "".join(out)


# --------------------------------------------------------------------------
# Block-level parsing
# --------------------------------------------------------------------------

_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET = re.compile(r"^[-*]\s+(.*)$")
_NUMBERED = re.compile(r"^\d+[.)]\s+(.*)$")
_TABLE_SEP = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$")
_FENCE = re.compile(r"^\s*```")


def parse_blocks(lines):
    """Yield block dicts describing the document structure."""
    blocks = []
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.rstrip("\n")
        stripped = line.strip()

        # Fenced code block
        if _FENCE.match(line):
            code_lines = []
            i += 1
            while i < n and not _FENCE.match(lines[i].rstrip("\n")):
                code_lines.append(lines[i].rstrip("\n"))
                i += 1
            i += 1  # consume closing fence
            blocks.append({"type": "code", "lines": code_lines})
            continue

        # Page break marker
        if stripped == "[[PAGEBREAK]]":
            blocks.append({"type": "pagebreak"})
            i += 1
            continue

        # Blank line
        if stripped == "":
            i += 1
            continue

        # Heading
        m = _HEADING.match(line)
        if m:
            level = len(m.group(1))
            blocks.append({"type": "heading", "level": level, "text": m.group(2).strip()})
            i += 1
            continue

        # Table: current line starts with '|' and next line is a separator
        if stripped.startswith("|") and i + 1 < n and _TABLE_SEP.match(lines[i + 1].rstrip("\n")):
            header = lines[i].rstrip("\n")
            aligns = _parse_aligns(lines[i + 1].rstrip("\n"))
            i += 2
            rows = []
            while i < n:
                t = lines[i].rstrip("\n")
                if t.strip().startswith("|"):
                    rows.append(t)
                    i += 1
                else:
                    break
            blocks.append({
                "type": "table",
                "header": _split_row(header),
                "aligns": aligns,
                "rows": [_split_row(r) for r in rows],
            })
            continue

        # Bullet list
        if _BULLET.match(stripped):
            items = []
            while i < n:
                s = lines[i].rstrip("\n").strip()
                mm = _BULLET.match(s)
                if mm and not _TABLE_SEP.match(lines[i].rstrip("\n")):
                    items.append(mm.group(1))
                    i += 1
                elif s == "":
                    break
                else:
                    break
            blocks.append({"type": "bullet", "items": items})
            continue

        # Numbered list
        if _NUMBERED.match(stripped):
            items = []
            while i < n:
                s = lines[i].rstrip("\n").strip()
                mm = _NUMBERED.match(s)
                if mm:
                    items.append(mm.group(1))
                    i += 1
                elif s == "":
                    break
                else:
                    break
            blocks.append({"type": "numbered", "items": items})
            continue

        # Paragraph: gather consecutive plain lines
        para = [stripped]
        i += 1
        while i < n:
            s = lines[i].rstrip("\n")
            ss = s.strip()
            if ss == "" or _HEADING.match(s) or _FENCE.match(s) or ss == "[[PAGEBREAK]]":
                break
            if ss.startswith("|") or _BULLET.match(ss) or _NUMBERED.match(ss):
                break
            para.append(ss)
            i += 1
        blocks.append({"type": "para", "text": " ".join(para)})
    return blocks


def _split_row(row):
    row = row.strip()
    if row.startswith("|"):
        row = row[1:]
    if row.endswith("|"):
        row = row[:-1]
    return [c.strip() for c in row.split("|")]


def _parse_aligns(sep):
    cells = _split_row(sep)
    aligns = []
    for c in cells:
        c = c.strip()
        left = c.startswith(":")
        right = c.endswith(":")
        if left and right:
            aligns.append("center")
        elif right:
            aligns.append("right")
        else:
            aligns.append("left")
    return aligns


# --------------------------------------------------------------------------
# WordprocessingML emission
# --------------------------------------------------------------------------

class DocBuilder:
    def __init__(self):
        self.body = []
        self.num_defs = []          # list of ('bullet'|'decimal')
        self._title_emitted = False

    def _new_num(self, kind):
        """Allocate a numbering instance; returns numId."""
        self.num_defs.append(kind)
        return len(self.num_defs)  # numId, 1-based

    def add_heading(self, level, text):
        if level == 1 and not self._title_emitted:
            self._title_emitted = True
            self.body.append(
                f'<w:p><w:pPr><w:pStyle w:val="Title"/></w:pPr>{runs_to_xml(text)}</w:p>'
            )
            return
        style = f"Heading{min(level, 4)}"
        self.body.append(
            f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr>{runs_to_xml(text)}</w:p>'
        )

    def add_para(self, text):
        self.body.append(f"<w:p>{runs_to_xml(text)}</w:p>")

    def add_pagebreak(self):
        self.body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')

    def add_code(self, lines):
        if not lines:
            lines = [""]
        runs = []
        for idx, ln in enumerate(lines):
            if idx > 0:
                runs.append("<w:br/>")
            runs.append(
                f'<w:r><w:t xml:space="preserve">{xml_escape(ln)}</w:t></w:r>'
            )
        self.body.append(
            f'<w:p><w:pPr><w:pStyle w:val="CodeBlock"/></w:pPr>{"".join(runs)}</w:p>'
        )

    def add_list(self, items, kind):
        num_id = self._new_num("bullet" if kind == "bullet" else "decimal")
        style = "ListBullet" if kind == "bullet" else "ListNumber"
        for it in items:
            ppr = (
                f'<w:pPr><w:pStyle w:val="{style}"/>'
                f'<w:numPr><w:ilvl w:val="0"/><w:numId w:val="{num_id}"/></w:numPr></w:pPr>'
            )
            self.body.append(f"<w:p>{ppr}{runs_to_xml(it)}</w:p>")

    def add_table(self, header, aligns, rows):
        ncols = len(header)

        def norm(cells):
            cells = list(cells)
            if len(cells) < ncols:
                cells += [""] * (ncols - len(cells))
            return cells[:ncols]

        def jc(i):
            a = aligns[i] if i < len(aligns) else "left"
            return a if a in ("center", "right") else "left"

        def cell(text, i, is_header):
            run = runs_to_xml(text, base_bold=is_header)
            shade = '<w:shd w:val="clear" w:color="auto" w:fill="D9E2F3"/>' if is_header else ""
            tcpr = f"<w:tcPr>{shade}</w:tcPr>"
            ppr = f'<w:pPr><w:jc w:val="{jc(i)}"/></w:pPr>'
            return f"<w:tc>{tcpr}<w:p>{ppr}{run}</w:p></w:tc>"

        borders = (
            "<w:tblBorders>"
            '<w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
            '<w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
            '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
            '<w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
            '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
            '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
            "</w:tblBorders>"
        )
        tblpr = (
            "<w:tblPr>"
            '<w:tblStyle w:val="TableGrid"/>'
            '<w:tblW w:w="0" w:type="auto"/>'
            f"{borders}"
            '<w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" '
            'w:firstColumn="0" w:lastColumn="0" w:noHBand="0" w:noVBand="1"/>'
            "</w:tblPr>"
        )
        grid = "<w:tblGrid>" + "".join("<w:gridCol/>" for _ in range(ncols)) + "</w:tblGrid>"
        out = [f"<w:tbl>{tblpr}{grid}"]
        hcells = "".join(cell(c, i, True) for i, c in enumerate(norm(header)))
        out.append(f'<w:tr><w:trPr><w:tblHeader/></w:trPr>{hcells}</w:tr>')
        for r in rows:
            rcells = "".join(cell(c, i, False) for i, c in enumerate(norm(r)))
            out.append(f"<w:tr>{rcells}</w:tr>")
        out.append("</w:tbl>")
        # A table must be followed by a paragraph for Word to be happy.
        self.body.append("".join(out))
        self.body.append("<w:p/>")

    # ---- package assembly ----

    def numbering_xml(self):
        abstracts = []
        nums = []
        # abstractNum 0: bullet ; abstractNum 1: decimal
        bullet_levels = "".join(
            f'<w:lvl w:ilvl="{lvl}"><w:start w:val="1"/><w:numFmt w:val="bullet"/>'
            f'<w:lvlText w:val="&#8226;"/><w:lvlJc w:val="left"/>'
            f'<w:pPr><w:ind w:left="{720 + lvl*360}" w:hanging="360"/></w:pPr>'
            f'<w:rPr><w:rFonts w:ascii="Symbol" w:hAnsi="Symbol" w:hint="default"/></w:rPr></w:lvl>'
            for lvl in range(3)
        )
        abstracts.append(
            f'<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="hybridMultilevel"/>{bullet_levels}</w:abstractNum>'
        )
        dec_levels = "".join(
            f'<w:lvl w:ilvl="{lvl}"><w:start w:val="1"/><w:numFmt w:val="decimal"/>'
            f'<w:lvlText w:val="%{lvl+1}."/><w:lvlJc w:val="left"/>'
            f'<w:pPr><w:ind w:left="{720 + lvl*360}" w:hanging="360"/></w:pPr></w:lvl>'
            for lvl in range(3)
        )
        abstracts.append(
            f'<w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="hybridMultilevel"/>{dec_levels}</w:abstractNum>'
        )
        for idx, kind in enumerate(self.num_defs):
            num_id = idx + 1
            abs = 0 if kind == "bullet" else 1
            override = ""
            if kind == "decimal":
                override = '<w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride>'
            nums.append(
                f'<w:num w:numId="{num_id}"><w:abstractNumId w:val="{abs}"/>{override}</w:num>'
            )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            + "".join(abstracts) + "".join(nums) + "</w:numbering>"
        )

    def document_xml(self):
        sect = (
            "<w:sectPr>"
            '<w:pgSz w:w="12240" w:h="15840"/>'
            '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
            'w:header="720" w:footer="720" w:gutter="0"/>'
            "</w:sectPr>"
        )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body>" + "".join(self.body) + sect + "</w:body></w:document>"
        )


STYLES_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:docDefaults><w:rPrDefault><w:rPr>"
    '<w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/><w:sz w:val="22"/><w:szCs w:val="22"/>'
    "</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr>"
    '<w:spacing w:after="160" w:line="276" w:lineRule="auto"/>'
    "</w:pPr></w:pPrDefault></w:docDefaults>"
    # Normal
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
    # Title
    '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:spacing w:before="240" w:after="120"/></w:pPr>'
    '<w:rPr><w:b/><w:color w:val="1F3864"/><w:sz w:val="56"/><w:szCs w:val="56"/></w:rPr></w:style>'
    # Heading1..4
    '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="120"/>'
    '<w:outlineLvl w:val="0"/></w:pPr>'
    '<w:rPr><w:b/><w:color w:val="1F3864"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/>'
    '<w:outlineLvl w:val="1"/></w:pPr>'
    '<w:rPr><w:b/><w:color w:val="2E74B5"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="80"/>'
    '<w:outlineLvl w:val="2"/></w:pPr>'
    '<w:rPr><w:b/><w:color w:val="2E74B5"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="Heading4"><w:name w:val="heading 4"/><w:basedOn w:val="Normal"/>'
    '<w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="80"/>'
    '<w:outlineLvl w:val="3"/></w:pPr>'
    '<w:rPr><w:b/><w:i/><w:color w:val="2E74B5"/><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:style>'
    # CodeChar (inline code)
    '<w:style w:type="character" w:styleId="CodeChar"><w:name w:val="Code Char"/>'
    '<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>'
    '<w:sz w:val="20"/><w:szCs w:val="20"/><w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/></w:rPr></w:style>'
    # CodeBlock (fenced)
    '<w:style w:type="paragraph" w:styleId="CodeBlock"><w:name w:val="Code Block"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:keepLines/><w:spacing w:before="80" w:after="80" w:line="240" w:lineRule="auto"/>'
    '<w:ind w:left="120" w:right="120"/>'
    '<w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/>'
    '<w:pBdr><w:top w:val="single" w:sz="4" w:space="2" w:color="DDDDDD"/>'
    '<w:left w:val="single" w:sz="4" w:space="2" w:color="DDDDDD"/>'
    '<w:bottom w:val="single" w:sz="4" w:space="2" w:color="DDDDDD"/>'
    '<w:right w:val="single" w:sz="4" w:space="2" w:color="DDDDDD"/></w:pBdr></w:pPr>'
    '<w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style>'
    # List styles
    '<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:spacing w:after="40"/><w:ind w:left="720" w:hanging="360"/></w:pPr></w:style>'
    '<w:style w:type="paragraph" w:styleId="ListNumber"><w:name w:val="List Number"/><w:basedOn w:val="Normal"/>'
    '<w:pPr><w:spacing w:after="40"/><w:ind w:left="720" w:hanging="360"/></w:pPr></w:style>'
    # Table style
    '<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/>'
    '<w:tblPr><w:tblBorders>'
    '<w:top w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
    '<w:left w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
    '<w:bottom w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
    '<w:right w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
    '<w:insideH w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
    '<w:insideV w:val="single" w:sz="4" w:space="0" w:color="999999"/>'
    '</w:tblBorders></w:tblPr></w:style>'
    "</w:styles>"
)

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
    '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>'
    '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    "</Types>"
)

ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
    '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
    "</Relationships>"
)

DOC_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>'
    "</Relationships>"
)


def core_xml(title, created):
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties '
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        f"<dc:title>{xml_escape(title)}</dc:title>"
        "<dc:creator>DHCP O-RU Toolkit</dc:creator>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>'
        f'<dcterms:modified xsi:type="dcterms:W3CDTF">{created}</dcterms:modified>'
        "</cp:coreProperties>"
    )


APP_XML = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    "<Application>dhcp-oru-toolkit md_to_docx</Application>"
    "</Properties>"
)


def build_docx(markdown_text, out_path, title="Document", created="2026-06-03T00:00:00Z"):
    lines = markdown_text.splitlines()
    blocks = parse_blocks(lines)
    doc = DocBuilder()
    for b in blocks:
        t = b["type"]
        if t == "heading":
            doc.add_heading(b["level"], b["text"])
        elif t == "para":
            doc.add_para(b["text"])
        elif t == "code":
            doc.add_code(b["lines"])
        elif t == "bullet":
            doc.add_list(b["items"], "bullet")
        elif t == "numbered":
            doc.add_list(b["items"], "numbered")
        elif t == "table":
            doc.add_table(b["header"], b["aligns"], b["rows"])
        elif t == "pagebreak":
            doc.add_pagebreak()

    parts = {
        "[Content_Types].xml": CONTENT_TYPES,
        "_rels/.rels": ROOT_RELS,
        "word/document.xml": doc.document_xml(),
        "word/styles.xml": STYLES_XML,
        "word/numbering.xml": doc.numbering_xml(),
        "word/_rels/document.xml.rels": DOC_RELS,
        "docProps/core.xml": core_xml(title, created),
        "docProps/app.xml": APP_XML,
    }
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return len(blocks)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Convert a constrained Markdown file to .docx")
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--title", default="Document")
    ap.add_argument("--created", default="2026-06-03T00:00:00Z")
    args = ap.parse_args(argv)
    with open(args.input, "r", encoding="utf-8") as fh:
        text = fh.read()
    nblocks = build_docx(text, args.output, title=args.title, created=args.created)
    print(f"Wrote {args.output} ({nblocks} blocks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
