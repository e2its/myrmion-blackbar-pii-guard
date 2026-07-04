"""
extract.py
==========
Zero-dependency text extraction from documents, for feeding the anonymizer.

OOXML (docx/pptx/xlsx) and ODF (odt/ods) are ZIP containers of XML parts, so we
read them with the standard library only (`zipfile` + a small regex/entity
unescape) — no python-docx / openpyxl. CSV/JSON/TXT/MD are trivial. PDF is the
sole exception: it needs a real parser, so `pypdf` is imported lazily and is an
OPTIONAL extra (`pip install -r web/requirements-docs.txt`); if it is missing,
PDF extraction raises `PdfSupportMissing` and the rest keeps working.

Design notes
------------
- We extract text with regex over the well-known leaf elements (``w:t`` for Word,
  ``a:t`` for PowerPoint, ``t`` for Excel shared strings, ``text:*`` for ODF).
  Those elements never nest, so regex is safe here — and because we never run a
  real XML parser, XML-entity-expansion ("billion laughs") and external-entity
  (XXE) attacks are structurally impossible.
- A per-member uncompressed-size cap guards against zip bombs.
- The extracted text is plain text; formatting is intentionally dropped.
"""

from __future__ import annotations

import csv
import io
import json
import re
import zipfile

# Caps (bytes / chars). Tunable via the caller if needed.
MAX_UNCOMPRESSED = 64 * 1024 * 1024   # reject a document whose parts exceed this
MAX_TEXT_CHARS = 2_000_000            # truncate extracted text beyond this

# extension -> logical kind
_KINDS = {
    "docx": "docx", "pptx": "pptx", "xlsx": "xlsx",
    "odt": "odt", "ods": "ods",
    "csv": "csv", "tsv": "csv",
    "json": "json",
    "txt": "text", "md": "text", "markdown": "text", "log": "text",
    "pdf": "pdf",
}

SUPPORTED_EXTENSIONS = sorted(_KINDS.keys())


class ExtractError(Exception):
    """A document could not be read (corrupt, unsupported, too large)."""


class PdfSupportMissing(ExtractError):
    """PDF requested but the optional `pypdf` dependency is not installed."""


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
_TAG_RE = re.compile(r"<[^>]+>")
_ENTITIES = {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'"}
_ENTITY_RE = re.compile(r"&(?:amp|lt|gt|quot|apos|#\d+|#x[0-9A-Fa-f]+);")


def _unescape(s: str) -> str:
    def repl(m: "re.Match[str]") -> str:
        tok = m.group(0)
        if tok in _ENTITIES:
            return _ENTITIES[tok]
        try:
            if tok.startswith("&#x") or tok.startswith("&#X"):
                return chr(int(tok[3:-1], 16))
            return chr(int(tok[2:-1]))
        except (ValueError, OverflowError):
            return tok
    return _ENTITY_RE.sub(repl, s)


def _strip_tags(chunk: str) -> str:
    return _unescape(_TAG_RE.sub("", chunk))


def _decode(data: bytes) -> str:
    """Decode bytes with a tolerant fallback (UTF-8 → UTF-16 BOM → latin-1)."""
    for enc in ("utf-8-sig", "utf-8"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            pass
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    return data.decode("latin-1", "replace")


def _open_zip(data: bytes) -> zipfile.ZipFile:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ExtractError("not a valid Office/OpenDocument file (bad zip)") from exc
    total = sum(max(0, i.file_size) for i in z.infolist())
    if total > MAX_UNCOMPRESSED:
        raise ExtractError("document is too large to extract safely")
    return z


def _read_part(z: zipfile.ZipFile, name: str) -> str:
    try:
        return _decode(z.read(name))
    except KeyError:
        return ""


def _sorted_parts(z: zipfile.ZipFile, prefix: str, suffix: str = ".xml") -> list[str]:
    names = [n for n in z.namelist() if n.startswith(prefix) and n.endswith(suffix)]
    # natural-ish sort so slide2 < slide10
    def key(n: str):
        m = re.search(r"(\d+)", n.rsplit("/", 1)[-1])
        return (int(m.group(1)) if m else 0, n)
    return sorted(names, key=key)


# --------------------------------------------------------------------------- #
# OOXML: Word / PowerPoint / Excel
# --------------------------------------------------------------------------- #
def _extract_docx(z: zipfile.ZipFile) -> tuple[str, list[str]]:
    xml = _read_part(z, "word/document.xml")
    if not xml:
        return "", ["no document.xml found"]
    # Split on paragraph boundaries, join the runs (w:t) inside each.
    paras = re.split(r"</w:p>", xml)
    lines: list[str] = []
    for p in paras:
        runs = re.findall(r"<w:t\b[^>]*>(.*?)</w:t>", p, re.DOTALL)
        # tabs and explicit breaks
        p = p.replace("<w:tab/>", "\t").replace("<w:br/>", "\n")
        text = "".join(_unescape(r) for r in runs)
        lines.append(text)
    body = "\n".join(lines).strip("\n")
    warnings = [] if body.strip() else ["no extractable text (image-only or empty)"]
    return body, warnings


def _extract_pptx(z: zipfile.ZipFile) -> tuple[str, list[str]]:
    slides = _sorted_parts(z, "ppt/slides/slide")
    out: list[str] = []
    for i, name in enumerate(slides, 1):
        xml = _read_part(z, name)
        texts = re.findall(r"<a:t\b[^>]*>(.*?)</a:t>", xml, re.DOTALL)
        if texts:
            out.append(f"--- slide {i} ---")
            out.append("\n".join(_unescape(t) for t in texts))
    body = "\n\n".join(out).strip()
    warnings = [] if body else ["no extractable text on any slide"]
    return body, warnings


def _excel_shared_strings(z: zipfile.ZipFile) -> list[str]:
    xml = _read_part(z, "xl/sharedStrings.xml")
    if not xml:
        return []
    out: list[str] = []
    for si in re.findall(r"<si\b[^>]*>(.*?)</si>", xml, re.DOTALL):
        parts = re.findall(r"<t\b[^>]*>(.*?)</t>", si, re.DOTALL)
        out.append("".join(_unescape(p) for p in parts))
    return out


def _extract_xlsx(z: zipfile.ZipFile) -> tuple[str, list[str]]:
    shared = _excel_shared_strings(z)
    sheets = _sorted_parts(z, "xl/worksheets/sheet")
    out: list[str] = []
    for name in sheets:
        xml = _read_part(z, name)
        rows = re.findall(r"<row\b[^>]*>(.*?)</row>", xml, re.DOTALL)
        for row in rows:
            cells: list[str] = []
            for cell in re.findall(r"<c\b([^>]*)>(.*?)</c>", row, re.DOTALL):
                attrs, inner = cell
                t = re.search(r'\bt="([^"]+)"', attrs)
                ctype = t.group(1) if t else "n"
                if ctype == "s":  # shared string index in <v>
                    v = re.search(r"<v\b[^>]*>(.*?)</v>", inner, re.DOTALL)
                    if v:
                        try:
                            cells.append(shared[int(v.group(1))])
                        except (ValueError, IndexError):
                            cells.append("")
                elif ctype in ("inlineStr", "str"):
                    parts = re.findall(r"<t\b[^>]*>(.*?)</t>", inner, re.DOTALL)
                    cells.append("".join(_unescape(p) for p in parts))
                else:  # numeric / boolean
                    v = re.search(r"<v\b[^>]*>(.*?)</v>", inner, re.DOTALL)
                    cells.append(_unescape(v.group(1)) if v else "")
            if any(c.strip() for c in cells):
                out.append("\t".join(cells))
    body = "\n".join(out).strip()
    warnings = [] if body else ["no extractable cell text"]
    return body, warnings


# --------------------------------------------------------------------------- #
# ODF: OpenDocument text / spreadsheet
# --------------------------------------------------------------------------- #
def _extract_odt(z: zipfile.ZipFile) -> tuple[str, list[str]]:
    xml = _read_part(z, "content.xml")
    if not xml:
        return "", ["no content.xml found"]
    body_m = re.search(r"<office:body\b[^>]*>(.*?)</office:body>", xml, re.DOTALL)
    scope = body_m.group(1) if body_m else xml
    # paragraphs and headings carry the visible text
    blocks = re.findall(r"<text:(?:p|h)\b[^>]*>(.*?)</text:(?:p|h)>", scope, re.DOTALL)
    lines = [_strip_tags(b) for b in blocks]
    body = "\n".join(lines).strip("\n")
    warnings = [] if body.strip() else ["no extractable text"]
    return body, warnings


def _extract_ods(z: zipfile.ZipFile) -> tuple[str, list[str]]:
    xml = _read_part(z, "content.xml")
    if not xml:
        return "", ["no content.xml found"]
    out: list[str] = []
    for row in re.findall(r"<table:table-row\b[^>]*>(.*?)</table:table-row>", xml, re.DOTALL):
        cells: list[str] = []
        for cell in re.findall(r"<table:table-cell\b[^>]*>(.*?)</table:table-cell>", row, re.DOTALL):
            paras = re.findall(r"<text:p\b[^>]*>(.*?)</text:p>", cell, re.DOTALL)
            cells.append(" ".join(_strip_tags(p) for p in paras))
        # also account for self-closing empty cells (with a column-repeat) as blanks
        if any(c.strip() for c in cells):
            out.append("\t".join(cells))
    body = "\n".join(out).strip()
    warnings = [] if body else ["no extractable cell text"]
    return body, warnings


# --------------------------------------------------------------------------- #
# Plain formats
# --------------------------------------------------------------------------- #
def _extract_csv(data: bytes) -> tuple[str, list[str]]:
    text = _decode(data)
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    body = "\n".join("\t".join(cell for cell in row) for row in rows).strip()
    return body, []


def _json_leaves(value, out: list[str]) -> None:
    if isinstance(value, str):
        if value.strip():
            out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _json_leaves(v, out)
    elif isinstance(value, list):
        for v in value:
            _json_leaves(v, out)


def _extract_json(data: bytes) -> tuple[str, list[str]]:
    try:
        obj = json.loads(_decode(data))
    except json.JSONDecodeError as exc:
        raise ExtractError(f"invalid JSON: {exc}") from exc
    leaves: list[str] = []
    _json_leaves(obj, leaves)
    return "\n".join(leaves).strip(), []


def _extract_pdf(data: bytes) -> tuple[str, list[str]]:
    try:
        import pypdf  # type: ignore
    except ImportError as exc:
        raise PdfSupportMissing(
            "PDF support needs the optional 'pypdf' dependency"
        ) from exc
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 — pypdf raises many types
        raise ExtractError(f"could not read PDF: {exc}") from exc
    pages = []
    for page in reader.pages:
        try:
            pages.append(page.extract_text() or "")
        except Exception:  # noqa: BLE001
            pages.append("")
    body = "\n\n".join(p.strip() for p in pages if p.strip()).strip()
    warnings = [] if body else ["no text layer (scanned/image PDF?) — OCR not supported"]
    return body, warnings


# --------------------------------------------------------------------------- #
# public entry point
# --------------------------------------------------------------------------- #
def _ext(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def extract_document(filename: str, data: bytes) -> dict:
    """Extract plain text from an uploaded document.

    Returns {filename, kind, ext, text, chars, truncated, warnings}.
    Raises PdfSupportMissing / ExtractError on failure.
    """
    ext = _ext(filename)
    kind = _KINDS.get(ext)
    if kind is None:
        raise ExtractError(
            f"unsupported file type '.{ext or '?'}' "
            f"(supported: {', '.join(SUPPORTED_EXTENSIONS)})"
        )

    if kind == "text":
        text, warnings = _decode(data), []
    elif kind == "csv":
        text, warnings = _extract_csv(data)
    elif kind == "json":
        text, warnings = _extract_json(data)
    elif kind == "pdf":
        text, warnings = _extract_pdf(data)
    else:  # zip-based office formats
        z = _open_zip(data)
        text, warnings = {
            "docx": _extract_docx,
            "pptx": _extract_pptx,
            "xlsx": _extract_xlsx,
            "odt": _extract_odt,
            "ods": _extract_ods,
        }[kind](z)

    truncated = False
    if len(text) > MAX_TEXT_CHARS:
        text = text[:MAX_TEXT_CHARS]
        truncated = True
        warnings = list(warnings) + [f"text truncated to {MAX_TEXT_CHARS} characters"]

    return {
        "filename": filename,
        "kind": kind,
        "ext": ext,
        "text": text,
        "chars": len(text),
        "truncated": truncated,
        "warnings": warnings,
    }
