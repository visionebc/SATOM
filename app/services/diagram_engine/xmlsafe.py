"""Hostile-input guards shared by every reader: XML and ZIP.

XML: stdlib ElementTree (expat) never fetches external entities, and expat
>= 2.4.1 caps entity amplification, but SATOM does not rely on either: any
``<!DOCTYPE`` / ``<!ENTITY`` is refused BEFORE parsing (a diagram format never
needs one), the same rule as ``services/artifact_fetch._DTD``.

ZIP (VSDX is OPC = ZIP): bounded entry count, bounded uncompressed size per
entry and in total, bounded compression ratio, no absolute or ``..`` names.
Members are read through :func:`read_member`, which stops at the declared cap
even when the central directory lies about the size.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import zipfile
import zlib

DTD_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.I)

MAX_XML_BYTES = 64 * 1024 * 1024
MAX_ZIP_ENTRIES = 5000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_ZIP_TOTAL = 256 * 1024 * 1024
MAX_RATIO = 200
MAX_INFLATE = 64 * 1024 * 1024


class UnsafeInput(ValueError):
    """The file was refused before or while being parsed."""


def parse_xml(data: bytes | str) -> ET.Element:
    """The root element, or :class:`UnsafeInput` / :class:`ET.ParseError`."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if len(raw) > MAX_XML_BYTES:
        raise UnsafeInput("XML larger than %d MiB" % (MAX_XML_BYTES // 1048576))
    if DTD_RE.search(raw):
        raise UnsafeInput("XML with a DOCTYPE or ENTITY declaration is refused")
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise UnsafeInput("not well-formed XML: %s" % exc) from None


def local(tag: str) -> str:
    """``{namespace}name`` -> ``name``."""
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def inflate_raw(data: bytes, limit: int = MAX_INFLATE) -> bytes:
    """Raw DEFLATE (draw.io's compressed diagrams) with an output cap."""
    d = zlib.decompressobj(-15)
    out = d.decompress(data, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise UnsafeInput("compressed content expands beyond %d MiB" % (limit // 1048576))
    return out


def open_zip(path_or_file) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(path_or_file)
    except (zipfile.BadZipFile, OSError) as exc:
        raise UnsafeInput("not a valid ZIP container: %s" % exc) from None
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise UnsafeInput("ZIP with %d entries; the limit is %d" % (len(infos), MAX_ZIP_ENTRIES))
    total = 0
    for i in infos:
        name = i.filename
        if name.startswith("/") or ".." in name.split("/") or "\\" in name:
            raise UnsafeInput("ZIP entry with an unsafe name: %r" % name[:80])
        total += i.file_size
        if i.file_size > MAX_MEMBER_BYTES:
            raise UnsafeInput("ZIP entry %r is larger than %d MiB" % (name[:80], MAX_MEMBER_BYTES // 1048576))
        if i.compress_size and i.file_size / max(1, i.compress_size) > MAX_RATIO and i.file_size > 1048576:
            raise UnsafeInput("ZIP entry %r has a compression ratio above %d" % (name[:80], MAX_RATIO))
    if total > MAX_ZIP_TOTAL:
        raise UnsafeInput("ZIP expands to more than %d MiB" % (MAX_ZIP_TOTAL // 1048576))
    return zf


def read_member(zf: zipfile.ZipFile, name: str, limit: int = MAX_MEMBER_BYTES) -> bytes:
    """A member's bytes, never more than *limit* whatever the header says."""
    try:
        with zf.open(name) as fh:
            data = fh.read(limit + 1)
    except KeyError:
        raise UnsafeInput("missing ZIP entry %r" % name[:80]) from None
    except (zipfile.BadZipFile, zlib.error, OSError) as exc:
        raise UnsafeInput("corrupt ZIP entry %r: %s" % (name[:80], exc)) from None
    if len(data) > limit:
        raise UnsafeInput("ZIP entry %r expands beyond %d MiB" % (name[:80], limit // 1048576))
    return data
