"""Sniff the format of an uploaded diagram: content first, extension second."""
from __future__ import annotations

import io
import os
import re

from . import xmlsafe
from .importers import ImportFailed

SUPPORTED_EXTENSIONS = (".drawio", ".dio", ".xml", ".svg", ".vsdx", ".vdx", ".pdf",
                        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff",
                        ".mmd", ".mermaid", ".dot", ".gv")

_EXT = {".drawio": "drawio", ".dio": "drawio", ".svg": "svg", ".vsdx": "vsdx", ".vsdm": "vsdx",
        ".vdx": "vdx", ".pdf": "pdf", ".png": "raster", ".jpg": "raster", ".jpeg": "raster",
        ".gif": "raster", ".webp": "raster", ".bmp": "raster", ".tif": "raster",
        ".tiff": "raster", ".mmd": "mermaid", ".mermaid": "mermaid", ".dot": "dot", ".gv": "dot"}

_SUPPORTED = ("draw.io (.drawio, .xml), SVG, Visio (.vsdx, .vdx), PDF, images "
              "(PNG, JPEG, GIF, WEBP, BMP, TIFF), Mermaid (.mmd) and Graphviz DOT (.dot, .gv)")

VSD_MESSAGE = ("Legacy binary Visio (.vsd) cannot be read; save it as .vsdx in Visio and import that.")

_MERMAID_RE = re.compile(r"^(?:flowchart|graph)(?:\s+(?:TD|TB|BT|RL|LR))?\s*;?\s*$", re.I)
_DOT_RE = re.compile(r'^(?:strict\s+)?(?:di)?graph\b\s*(?:"(?:[^"\\]|\\.)*"|[\w.\-]+)?\s*\{', re.I)
_SVG_TAG_RE = re.compile(rb"<svg\b(?:[^>\"']|\"[^\"]*\"|'[^']*')*>", re.I)
_ROOT_RE = re.compile(r"<([A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*)")


def _decode(head: bytes) -> str:
    if head.startswith(b"\xef\xbb\xbf"):
        return head[3:].decode("utf-8", "replace")
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return head.decode("utf-16", "replace")
    return head.decode("utf-8", "replace")


def _xml_root(text: str) -> str:
    """Local name of the first real element (skipping prolog, comments, DOCTYPE)."""
    i = 0
    n = len(text)
    while i < n:
        j = text.find("<", i)
        if j < 0:
            return ""
        if text.startswith("<!--", j):
            k = text.find("-->", j + 4)
            if k < 0:
                return ""
            i = k + 3
        elif text.startswith("<?", j):
            k = text.find("?>", j + 2)
            if k < 0:
                return ""
            i = k + 2
        elif text.startswith("<!", j):
            # DOCTYPE, possibly with an internal subset in brackets
            depth, k = 0, j + 2
            while k < n:
                c = text[k]
                if c == "[":
                    depth += 1
                elif c == "]":
                    depth -= 1
                elif c == ">" and depth <= 0:
                    break
                k += 1
            i = k + 1
        else:
            m = _ROOT_RE.match(text, j)
            return m.group(2) if m else ""
    return ""


def _strip_code_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith(("//", "#", "%%")))


def _first_statement(text: str) -> str:
    if text.startswith("---"):  # mermaid front matter
        end = text.find("\n---", 3)
        if end > 0:
            text = text[end + 4:]
    for ln in _strip_code_comments(text).splitlines():
        if ln.strip():
            return ln.strip()
    return ""


def _is_dot(text: str) -> bool:
    body = _strip_code_comments(text).lstrip()
    return bool(_DOT_RE.match(body))


def _is_mermaid(text: str) -> bool:
    first = _first_statement(text)
    if not first:
        return False
    head = first.split(";")[0].strip() if first.lower().startswith(("flowchart", "graph")) else first
    return bool(_MERMAID_RE.match(head))


def _ext(filename: str) -> str:
    return os.path.splitext(str(filename or "").lower())[1]


def detect(data: bytes, filename: str) -> str:
    """One of: drawio, drawio-svg, svg, vsdx, vdx, pdf, raster, mermaid, dot.

    Raises :class:`ImportFailed` for legacy .vsd and for unknown content.
    """
    if not isinstance(data, (bytes, bytearray)) or not data.strip():
        raise ImportFailed("The file is empty.")
    data = bytes(data)
    ext = _ext(filename)
    head = data[:4096]

    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") or ext == ".vsd":
        raise ImportFailed(VSD_MESSAGE)
    if b"%PDF-" in head[:1024]:
        return "pdf"
    bmp = (head.startswith(b"BM") and len(head) >= 18
           and int.from_bytes(head[14:18], "little") in (12, 40, 52, 56, 64, 108, 124))
    if (bmp or head.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
                               b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+"))
            or (head[:4] == b"RIFF" and head[8:12] == b"WEBP")):
        return "raster"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        zf = xmlsafe.open_zip(io.BytesIO(data))
        names = {n.lower() for n in zf.namelist()}
        if "visio/document.xml" in names:
            return "vsdx"
        if "[content_types].xml" in names:
            ct = xmlsafe.read_member(zf, next(n for n in zf.namelist()
                                              if n.lower() == "[content_types].xml"), 4 * 1024 * 1024)
            if b"visio" in ct.lower():
                return "vsdx"
        raise ImportFailed("This ZIP container is not a Visio drawing. Supported formats: %s." % _SUPPORTED)

    text = _decode(data[:262144])
    if text.startswith("﻿"):
        text = text[1:]
    stripped = text.lstrip()
    if stripped.startswith("<"):
        root = _xml_root(stripped)
        if root in ("mxfile", "mxGraphModel"):
            return "drawio"
        if root == "svg":
            for m in _SVG_TAG_RE.finditer(data[:4 * 1024 * 1024]):
                tag = m.group(0)
                if re.search(rb"\bcontent\s*=\s*[\"']\s*(?:&lt;|<)(?:mxfile|mxGraphModel)", tag):
                    return "drawio-svg"
                break
            return "svg"
        if root == "VisioDocument":
            return "vdx"
        if ext in _EXT and _EXT[ext] != "raster":
            return _EXT[ext]
        raise ImportFailed("Unrecognised XML document (root element %r). Supported formats: %s."
                           % (root[:40], _SUPPORTED))
    if _is_dot(stripped):
        return "dot"
    if _is_mermaid(stripped):
        return "mermaid"
    if ext in (".mmd", ".mermaid"):
        return "mermaid"
    if ext in (".dot", ".gv"):
        return "dot"
    raise ImportFailed("Unsupported or unrecognised file. Supported formats: %s." % _SUPPORTED)
