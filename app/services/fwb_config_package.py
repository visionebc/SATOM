"""FortiWeb configuration packages -- the only file format its restore takes.

A FortiWeb restores a configuration only through the endpoint its own GUI
posts (``system/maintenance.restoreconfiguration``), and only from the file
its own backup produces: a ZIP holding one text member,
``fwb_system_no_defaults.conf`` (``GET system/maintenance.backupconfiguration
?type=cli``). Measured on fortiweb20, FortiWeb-VM 7.6.8 build1128, 2026-11-08.

The member is a ``[header]`` block (magic, version, ``image_version`` of the
box that wrote it, ``file_number``, ``file_split``) and one ``[file]`` section
per configuration domain -- ``global`` and one per VDOM (``root`` on a box
without VDOMs). Each section is its meta lines, the split line, the domain's
CLI text with no outer wrapper, the split line again and ``[/file]``.

SATOM's vault also holds a different thing: the CLI dump a FortiWeb prints
over SSH (``show full-configuration``) when its REST API is licence-locked.
That text wraps the same content in ``config global`` / ``config vdom`` /
``edit <vdom>`` and is NOT restorable as is: posted raw, the box answers 200
and applies nothing. :func:`build_package` turns such a dump into a package,
taking the header and every section's meta from a package the TARGET box just
wrote (its own firmware string, its own split line), so the box never has to
accept a header SATOM made up.

Pure functions, no Flask, no device I/O: the callers in
:mod:`app.services.backup` do the REST calls.
"""
from __future__ import annotations

import io
import re
import zipfile

#: The ZIP member FortiWeb's CLI backup writes and its restore reads.
PACKAGE_MEMBER = "fwb_system_no_defaults.conf"

#: What :func:`classify` returns.
KIND_PACKAGE = "package"      # a FortiWeb backup ZIP -- restorable as is
KIND_CLI_DUMP = "cli_dump"    # ``show full-configuration`` text -- convert first
KIND_UNKNOWN = "unknown"      # neither (a password-encrypted backup, or junk)


class PackageError(ValueError):
    """The bytes are not what the caller needs; the message says why."""


# --------------------------------------------------------------------------- #
#  Recognising what the vault holds                                            #
# --------------------------------------------------------------------------- #
def _zip_member(data: bytes) -> tuple[str, str] | None:
    """``(member name, text)`` of a FortiWeb backup ZIP, else ``None``."""
    if not (data or b"").startswith(b"PK\x03\x04"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [i.filename for i in zf.infolist() if not i.is_dir()]
            if len(names) != 1 or not names[0].endswith(".conf"):
                return None
            text = zf.read(names[0]).decode("utf-8", errors="replace")
    except (zipfile.BadZipFile, OSError, RuntimeError):
        return None
    if not text.startswith("[header]"):
        return None
    return names[0], text


def _first_config_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip() and not line.startswith("#"):
            return line.rstrip()
    return ""


def classify(data: bytes) -> str:
    """:data:`KIND_PACKAGE`, :data:`KIND_CLI_DUMP` or :data:`KIND_UNKNOWN`."""
    if _zip_member(data) is not None:
        return KIND_PACKAGE
    head = (data or b"")[:4096].decode("utf-8", errors="replace")
    if _first_config_line(head) == "config global":
        return KIND_CLI_DUMP
    return KIND_UNKNOWN


# --------------------------------------------------------------------------- #
#  The CLI dump: one body per domain                                           #
# --------------------------------------------------------------------------- #
def _open_quotes(line: str) -> int:
    """Unescaped double quotes in ``line`` (``\\"`` and ``\\\\`` are escapes)."""
    n, esc = 0, False
    for ch in line:
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            n += 1
    return n


def _continuations(lines: list[str]) -> list[bool]:
    """``True`` for every line that continues a quoted value opened on an
    earlier line -- a PEM certificate, a script. Those lines are content: they
    are never indented and may read ``end`` or ``next`` (a Lua script), so the
    structure is read from the other lines only."""
    out, inside = [], False
    for line in lines:
        out.append(inside)
        if _open_quotes(line) % 2:
            inside = not inside
    return out


def _dedent(lines: list[str], cont: list[bool], width: int, where: str) -> list[str]:
    pad = " " * width
    out = []
    for n, (line, c) in enumerate(zip(lines, cont), 1):
        if c:
            out.append(line)
        elif not line.strip():
            out.append("")
        elif line.startswith(pad):
            out.append(line[width:])
        else:
            raise PackageError(
                f"CLI dump: line {n} of {where} is not indented under its block: {line[:60]!r}")
    return out


def _find(lines: list[str], cont: list[bool], value: str, start: int) -> int:
    """Index of the first structural line equal to ``value`` (ValueError if none)."""
    for k in range(start, len(lines)):
        if not cont[k] and lines[k] == value:
            return k
    raise ValueError(value)


def split_cli_dump(text: str) -> dict[str, list[str]]:
    """``{"global": [...], "<vdom>": [...]}`` -- each domain's CLI lines with
    the ``config global`` / ``config vdom`` + ``edit <vdom>`` wrapper removed
    and dedented to column 0, which is how a package section carries them."""
    lines = [l.rstrip("\r") for l in text.splitlines()]
    cont = _continuations(lines)
    if sum(_open_quotes(l) for l in lines) % 2:
        raise PackageError("CLI dump: a quoted value is never closed (truncated dump?)")
    i, n = 0, len(lines)
    while i < n and (not lines[i].strip() or lines[i].startswith("#")):
        i += 1
    if i >= n or lines[i] != "config global":
        raise PackageError("CLI dump does not start with 'config global'")
    try:
        end = _find(lines, cont, "end", i + 1)
    except ValueError:
        raise PackageError("CLI dump: 'config global' is never closed") from None
    out: dict[str, list[str]] = {
        "global": _dedent(lines[i + 1:end], cont[i + 1:end], 2, "config global")}
    i = end + 1
    while i < n and not lines[i].strip():
        i += 1
    if i >= n or lines[i] != "config vdom":
        raise PackageError("CLI dump: no 'config vdom' block after 'config global'")
    i += 1
    while i < n and lines[i] != "end":
        m = re.fullmatch(r'  edit "?([^"\s]+)"?', lines[i])
        if not m:
            raise PackageError(f"CLI dump: expected '  edit <vdom>', found {lines[i][:60]!r}")
        name = m.group(1)
        try:
            nxt = _find(lines, cont, "  next", i + 1)
        except ValueError:
            raise PackageError(f"CLI dump: VDOM {name!r} is never closed") from None
        if name in out:
            raise PackageError(f"CLI dump: VDOM {name!r} appears twice")
        out[name] = _dedent(lines[i + 1:nxt], cont[i + 1:nxt], 4, f"VDOM {name}")
        i = nxt + 1
    if i >= n:
        raise PackageError("CLI dump: 'config vdom' is never closed (truncated dump?)")
    if any(l.strip() for l in lines[i + 1:]):
        raise PackageError("CLI dump: text after the closing 'end' of 'config vdom'")
    return out


# --------------------------------------------------------------------------- #
#  The package: header + one section per domain                                #
# --------------------------------------------------------------------------- #
def parse_package_text(text: str) -> dict:
    """``{"header": [...lines...], "split": str, "sections": [{"meta": [...],
    "domain": str, "comments": [...], "body": [...]}]}``. Strict: anything
    this module would not write back byte for byte is refused."""
    lines = text.splitlines()
    try:
        hend = lines.index("[/header]")
    except ValueError:
        raise PackageError("package: no [/header]") from None
    if not lines or lines[0] != "[header]":
        raise PackageError("package: does not start with [header]")
    header = lines[:hend + 1]
    fields = dict(l.split("=", 1) for l in header[1:-1] if "=" in l)
    split = fields.get("file_split", "")
    if not split:
        raise PackageError("package: header has no file_split")
    sections = []
    i = hend + 1
    while i < len(lines):
        if not lines[i].strip():
            i += 1
            continue
        if lines[i] != "[file]":
            raise PackageError(f"package: expected [file], found {lines[i][:60]!r}")
        try:
            s1 = lines.index(split, i + 1)
            s2 = lines.index(split, s1 + 1)
        except ValueError:
            raise PackageError("package: a [file] section is missing its split line") from None
        if s2 + 1 >= len(lines) or lines[s2 + 1] != "[/file]":
            raise PackageError("package: a [file] section is not closed by [/file]")
        meta = lines[i + 1:s1]
        mfields = dict(l.split("=", 1) for l in meta if "=" in l)
        body = lines[s1 + 1:s2]
        k = 0
        while k < len(body) and body[k].startswith("#"):
            k += 1
        sections.append({"meta": meta, "fields": mfields,
                         "domain": mfields.get("domain", ""),
                         "comments": body[:k], "body": body[k:]})
        i = s2 + 2
    if str(len(sections)) != fields.get("file_number", ""):
        raise PackageError(f"package: header says file_number={fields.get('file_number')!r}, "
                           f"found {len(sections)} sections")
    return {"header": header, "fields": fields, "split": split, "sections": sections}


def package_text(data: bytes) -> str:
    """The text member of a FortiWeb backup ZIP (raises :class:`PackageError`)."""
    got = _zip_member(data)
    if got is None:
        raise PackageError("not a FortiWeb configuration backup (.zip with one .conf member)")
    return got[1]


def build_package(dump: bytes, template: bytes) -> bytes:
    """Turn a ``show full-configuration`` dump into a restorable package.

    ``template`` is a CLI backup the TARGET box just wrote: its header and the
    meta of each section are reused verbatim, the bodies come from ``dump``.
    The domains must match one to one -- a dump with a VDOM the target does
    not have (or the other way round) is refused, not guessed."""
    domains = split_cli_dump((dump or b"").decode("utf-8", errors="replace"))
    tpl_member, tpl_text = _zip_member(template) or (None, None)
    if tpl_member is None:
        raise PackageError("the target's own backup is not a FortiWeb CLI backup ZIP")
    tpl = parse_package_text(tpl_text)
    for s in tpl["sections"]:
        f = s["fields"]
        if (f.get("type"), f.get("encrypt"), f.get("compress")) != ("config", "no", "no"):
            raise PackageError(
                f"the target's backup section {f.get('name', '?')!r} is "
                f"type={f.get('type')}/encrypt={f.get('encrypt')}/compress={f.get('compress')}; "
                "only plain CLI sections are rebuilt")
    want = [s["domain"] for s in tpl["sections"]]
    if sorted(want) != sorted(domains):
        raise PackageError(
            f"domains differ: the dump has {sorted(domains)}, the target box has {sorted(want)}")
    out = list(tpl["header"])
    for s in tpl["sections"]:
        out += ["[file]", *s["meta"], tpl["split"], *s["comments"],
                *domains[s["domain"]], tpl["split"], "[/file]"]
    text = "\n".join(out) + "\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(tpl_member, text)
    return buf.getvalue()


# --------------------------------------------------------------------------- #
#  The post-check: what a restore must have put back                           #
# --------------------------------------------------------------------------- #
def config_profile(sections: dict[str, list[str]]) -> dict[str, int]:
    """``{"<domain>:<config block>": <entries>}`` -- the number of ``edit``
    rows directly under every top-level ``config`` block. Counting rows, not
    comparing text: a restore re-salts every ``ENC`` secret and a no-defaults
    backup drops default ``set`` lines, so text never matches; the objects
    do."""
    prof: dict[str, int] = {}
    for dom, body in sections.items():
        block = None
        for line, c in zip(body, _continuations(body)):
            if c:
                continue
            if line.startswith("config "):
                block = line[7:].strip()
                prof.setdefault(f"{dom}:{block}", 0)
            elif line == "end":
                block = None
            elif block and line.startswith("  edit "):
                prof[f"{dom}:{block}"] += 1
    return {k: v for k, v in prof.items() if v}


def package_sections(data: bytes) -> dict[str, list[str]]:
    """``{domain: body lines}`` of a package ZIP or a CLI dump."""
    kind = classify(data)
    if kind == KIND_CLI_DUMP:
        return split_cli_dump(data.decode("utf-8", errors="replace"))
    if kind == KIND_PACKAGE:
        pkg = parse_package_text(package_text(data))
        return {s["domain"]: s["body"] for s in pkg["sections"]}
    raise PackageError("not a FortiWeb backup ZIP or CLI dump")


def profile_diff(expected: dict[str, int], actual: dict[str, int]) -> list[str]:
    """Human lines for every block whose entry count differs."""
    out = []
    for key in sorted(set(expected) | set(actual)):
        e, a = expected.get(key, 0), actual.get(key, 0)
        if e != a:
            out.append(f"{key}: expected {e}, device has {a}")
    return out


__all__ = ["PACKAGE_MEMBER", "KIND_PACKAGE", "KIND_CLI_DUMP", "KIND_UNKNOWN",
           "PackageError", "classify", "split_cli_dump", "parse_package_text",
           "package_text", "build_package", "config_profile", "package_sections",
           "profile_diff"]
