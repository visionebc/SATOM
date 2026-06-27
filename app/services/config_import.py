"""Offline FortiWeb config-backup parser -> structured config snapshot.

Web port of the desktop ``config_import`` / ``backup_import`` services, kept
Qt-free and network-free. It parses a FortiWeb CLI configuration backup (the
``config ... end`` text a box exports) into a structured per-device snapshot:
every top-level ``config`` block is bucketed into its FortiWeb GUI section and
the objects are counted. No live appliance is ever contacted.

A backup arrives in one of three shapes, all handled here:

* **plaintext** -- a ``.conf`` / ``.txt`` export;
* **gzip** -- transparently decompressed;
* **zip** -- the largest member that looks like a FortiWeb config is used.

FortiWeb *encrypted* backups cannot be decrypted offline (no key without the
box), so they raise a clear :class:`ValueError` instead of producing a garbage
parse.

Self-contained on purpose: the generic CLI grammar parser
(``parse_config`` -> ``ConfigSection`` / ``ConfigEntry``) is ported here from
the desktop topology service, and section labelling reuses the shared
``registry.categories.category_for`` map. No Flask import -- file IO is confined
to the ``write_/load_/list_snapshot`` helpers, which all take an explicit root
directory, so the view layer owns the data-dir resolution.
"""
from __future__ import annotations

import glob
import gzip
import io
import json
import os
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..registry.categories import category_for

# Per-device artifacts, written under ``<root>/<device-slug>/``.
CONFIG_NAME = "_config.json"
CONFIG_TEXT_NAME = "_config.txt"

# Stamped on every snapshot this module produces.
SOURCE_IMPORT = "backup-import"

# A readable FortiWeb CLI config carries one of these markers; used to tell a
# real config apart from an encrypted/binary blob we cannot read offline.
_CONFIG_MARKER = re.compile(
    r"(?mi)^\s*config\s+\S|#\s*config-version|config-version\s*="
)


# --------------------------------------------------------------------------- #
#  Read a backup file's bytes -> CLI config text (plaintext / zip / gzip)      #
# --------------------------------------------------------------------------- #
def _decode(data: bytes) -> str:
    """Best-effort text decode (utf-8 -> latin-1 fallback, never raises)."""
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _has_config_markers(text: str) -> bool:
    return bool(_CONFIG_MARKER.search(text))


def parse_backup_bytes(data: bytes) -> tuple[str, str]:
    """Extract readable FortiWeb CLI config text from a backup file's bytes.

    Returns ``(config_text, note)`` where ``note`` records how it was read.
    Raises :class:`ValueError` when no readable config is found -- e.g. an
    encrypted backup, which cannot be decrypted offline.
    """
    if not data:
        raise ValueError("the file is empty.")

    # gzip -> decompress then re-dispatch (handles .gz and gzip'd configs).
    if data[:2] == b"\x1f\x8b":
        try:
            inner = gzip.decompress(data)
        except OSError as exc:
            raise ValueError(f"could not gunzip the file: {exc}") from exc
        text, note = parse_backup_bytes(inner)
        return text, f"gunzipped -> {note}"

    # zip -> pick the largest member that looks like a FortiWeb config.
    if data[:4] == b"PK\x03\x04":
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile as exc:
            raise ValueError(f"not a readable zip: {exc}") from exc
        best: tuple[int, str, str] | None = None  # (size, member, text)
        for info in zf.infolist():
            if info.is_dir():
                continue
            try:
                member = zf.read(info.filename)
            except Exception:  # noqa: BLE001 - a bad member never sinks the rest
                continue
            text = _decode(member)
            if _has_config_markers(text) and (best is None or len(text) > best[0]):
                best = (len(text), info.filename, text)
        if best is not None:
            return best[2], f"extracted from zip member '{best[1]}'"
        raise ValueError(
            "the zip contains no readable FortiWeb CLI config -- the backup may "
            "be encrypted (FortiWeb encrypted backups can't be decrypted offline)."
        )

    # plaintext
    text = _decode(data)
    if _has_config_markers(text):
        return text, "plaintext config"
    raise ValueError(
        "no FortiWeb CLI config found in the file -- it may be encrypted, binary, "
        "or not a config backup."
    )


# --------------------------------------------------------------------------- #
#  Generic FortiWeb CLI grammar parser (ported from the desktop topology svc)  #
# --------------------------------------------------------------------------- #
_TOKEN_RE = re.compile(r'"[^"]*"|\S+')


def _tokenize(line: str) -> list[str]:
    """Split a CLI line into tokens, keeping double-quoted strings whole."""
    return _TOKEN_RE.findall(line)


def _unquote(token: str) -> str:
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    return token


@dataclass
class ConfigEntry:
    """One ``edit "<name>" ... next`` block (or a singleton's settings)."""

    name: str
    settings: dict[str, str | list[str]] = field(default_factory=dict)
    children: list["ConfigSection"] = field(default_factory=list)

    def get(self, key: str, default: str = "") -> str:
        """A single-string setting (joins lists with spaces)."""
        val = self.settings.get(key, default)
        return " ".join(val) if isinstance(val, list) else val

    def get_list(self, key: str) -> list[str]:
        """A setting as a list of tokens (a lone string -> one-item list)."""
        val = self.settings.get(key)
        if val is None:
            return []
        return list(val) if isinstance(val, list) else [val]

    def child(self, path: str) -> "ConfigSection | None":
        return next((c for c in self.children if c.path == path), None)


@dataclass
class ConfigSection:
    """One ``config <path> ... end`` block holding its ``edit`` entries."""

    path: str
    entries: list[ConfigEntry] = field(default_factory=list)


def parse_config(text: str) -> list[ConfigSection]:
    """Parse FortiWeb CLI ``text`` into a list of top-level config sections."""
    sections: list[ConfigSection] = []
    stack: list[tuple[str, object]] = []  # ("section", sec) | ("entry", entry)

    def _singleton_entry(sec: ConfigSection) -> ConfigEntry:
        # ``config system global`` style blocks ``set`` without an ``edit``.
        if not sec.entries:
            sec.entries.append(ConfigEntry(name=""))
        return sec.entries[0]

    for raw in text.splitlines():
        tokens = _tokenize(raw.strip())
        if not tokens or tokens[0].startswith("#"):
            continue
        head = tokens[0]

        if head == "config":
            sec = ConfigSection(path=" ".join(_unquote(t) for t in tokens[1:]))
            if stack and stack[-1][0] == "entry":
                # nested config (e.g. vip-list inside a vserver entry)
                stack[-1][1].children.append(sec)  # type: ignore[union-attr]
            else:
                sections.append(sec)
            stack.append(("section", sec))

        elif head == "edit":
            entry = ConfigEntry(name=_unquote(" ".join(tokens[1:])))
            if stack and stack[-1][0] == "section":
                stack[-1][1].entries.append(entry)  # type: ignore[union-attr]
            stack.append(("entry", entry))

        elif head == "set" and len(tokens) >= 2:
            vals = [_unquote(t) for t in tokens[2:]]
            value: str | list[str] = vals[0] if len(vals) == 1 else vals
            if stack and stack[-1][0] == "entry":
                stack[-1][1].settings[tokens[1]] = value  # type: ignore[union-attr]
            elif stack and stack[-1][0] == "section":
                _singleton_entry(stack[-1][1]).settings[tokens[1]] = value  # type: ignore[union-attr]

        elif head == "next":
            if stack and stack[-1][0] == "entry":
                stack.pop()

        elif head == "end":
            if stack and stack[-1][0] == "entry":
                stack.pop()  # tolerate a missing ``next``
            if stack and stack[-1][0] == "section":
                stack.pop()

    return sections


# --------------------------------------------------------------------------- #
#  CLI block -> FortiWeb GUI section label                                     #
# --------------------------------------------------------------------------- #
def _section_for_path(cli_path: str) -> str:
    """Map a CLI ``config <path>`` to its FortiWeb GUI section label.

    Synthesises the REST URN the box exposes for this CLI path
    (``/api/v2.0/cmdb/<path>``) and runs it through the shared ``category_for``
    section map, so a new firmware path lands in the right bucket with no
    hardcoding here. Unknown paths fall back to ``Other``.
    """
    segs = [s for s in re.split(r"[\s/]+", cli_path.strip()) if s]
    urn = "/api/v2.0/cmdb/" + "/".join(segs)
    section, _strip = category_for(urn)
    return section[0] if section else "Other"


def _norm_segs(path: str) -> tuple[str, ...]:
    """Normalise a CLI ``config`` path into comparable lowercase segments."""
    p = path.strip().lstrip("/")
    if p.startswith("cmdb/"):
        p = p[len("cmdb/"):]
    parts = re.split(r"[\s/.]+", p)
    return tuple(s for s in (seg.strip().lower() for seg in parts) if s)


def _global_entry(parsed: list[ConfigSection]) -> ConfigEntry | None:
    for sec in parsed:
        if _norm_segs(sec.path) == ("system", "global") and sec.entries:
            return sec.entries[0]
    return None


def device_hostname(parsed: list[ConfigSection]) -> str:
    """The box hostname from ``config system global`` (``""`` if absent)."""
    e = _global_entry(parsed)
    return e.get("hostname") if e else ""


def device_firmware(parsed: list[ConfigSection]) -> str:
    """Firmware string from ``config system global`` (``""`` if absent)."""
    e = _global_entry(parsed)
    if e:
        for key in ("firmware-version", "version"):
            v = e.get(key)
            if v:
                return v
    return ""


# --------------------------------------------------------------------------- #
#  CLI entries -> JSON-friendly rows                                           #
# --------------------------------------------------------------------------- #
def _entry_to_row(entry: ConfigEntry) -> dict[str, Any]:
    """One ``edit "<name>" ... next`` block -> a plain dict (recursing into
    nested ``config`` children so vip-lists / members are preserved)."""
    row: dict[str, Any] = {}
    if entry.name:
        row["name"] = entry.name
    for key, val in entry.settings.items():
        row[key] = list(val) if isinstance(val, list) else val
    if entry.children:
        subs: dict[str, list[dict[str, Any]]] = {}
        for child in entry.children:
            subs[child.path] = [_entry_to_row(e) for e in child.entries]
        row["_subtables"] = subs
    return row


def _section_rows(sec: ConfigSection) -> list[dict[str, Any]]:
    """Rows for a ``config`` block (one per ``edit`` entry, or a singleton)."""
    return [_entry_to_row(e) for e in sec.entries]


# --------------------------------------------------------------------------- #
#  Snapshot assembly                                                           #
# --------------------------------------------------------------------------- #
def build_snapshot(
    parsed: list[ConfigSection],
    raw_text: str,
    *,
    device: str,
    origin: str = "",
    note: str = "",
    by: str = "",
) -> dict[str, Any]:
    """Bucket parsed sections by GUI section and wrap them with metadata.

    ``objects`` keeps the faithful ``{section -> {cli_path -> [rows]}}`` detail
    (nothing is lost), while ``sections`` is the flat ``{section -> count}`` the
    UI and the import summary use.
    """
    objects: dict[str, dict[str, list]] = {}
    for sec in parsed:
        label = _section_for_path(sec.path)
        rows = _section_rows(sec)
        bucket = objects.setdefault(label, {})
        # Same CLI path twice (shouldn't happen, but be safe) -> extend.
        bucket.setdefault(sec.path, []).extend(rows)

    by_section: dict[str, int] = {}
    total = 0
    type_count = 0
    for label, types in objects.items():
        section_total = 0
        for rows in types.values():
            section_total += len(rows)
            type_count += 1
        by_section[label] = section_total
        total += section_total

    return {
        "device": device,
        "source": SOURCE_IMPORT,
        "origin": origin or "",
        "note": note or "",
        "by": by or "",
        "firmware": device_firmware(parsed),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_objects": total,
        "section_count": len(by_section),
        "type_count": type_count,
        "sections": dict(sorted(by_section.items())),
        "objects": objects,
        "raw_bytes": len(raw_text or ""),
    }


# --------------------------------------------------------------------------- #
#  Persist / read / list (file IO into an explicit root directory)            #
# --------------------------------------------------------------------------- #
def _slug(s: Any) -> str:
    """Filesystem-safe token for a device name."""
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(s)) or "x"


def _device_dir(root: str, device: str) -> str:
    return os.path.join(str(root), _slug(device))


def config_path(root: str, device: str) -> str:
    """``<root>/<device-slug>/_config.json``."""
    return os.path.join(_device_dir(root, device), CONFIG_NAME)


def text_path(root: str, device: str) -> str:
    """``<root>/<device-slug>/_config.txt``."""
    return os.path.join(_device_dir(root, device), CONFIG_TEXT_NAME)


def write_snapshot(snapshot: dict, *, root: str) -> str:
    """Persist a snapshot dict to its per-device ``_config.json``; returns path."""
    device = snapshot.get("device") or "device"
    directory = _device_dir(root, str(device))
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, CONFIG_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=2, ensure_ascii=False, default=str)
    return path


def write_snapshot_text(raw_text: str, device: str, *, root: str) -> str:
    """Write the raw extracted CLI config to ``_config.txt``; returns path."""
    directory = _device_dir(root, device)
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, CONFIG_TEXT_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(raw_text or "")
    return path


def load_snapshot(device: str, *, root: str) -> dict | None:
    """Read a device's config snapshot (``None`` if absent or unreadable)."""
    try:
        with open(config_path(root, device), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def load_snapshot_text(device: str, *, root: str) -> str:
    """Read the raw CLI config companion (``""`` if absent)."""
    try:
        with open(text_path(root, device), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def list_snapshots(root: str) -> list[dict[str, Any]]:
    """Summaries of every imported snapshot under ``root`` (newest first).

    Scans ``<root>/*/_config.json``. A missing root or any unreadable file is
    skipped, so this is safe to call before the first import.
    """
    out: list[dict[str, Any]] = []
    for path in glob.glob(os.path.join(str(root), "*", CONFIG_NAME)):
        try:
            with open(path, encoding="utf-8") as fh:
                snap = json.load(fh)
        except (OSError, ValueError):
            continue
        out.append(
            {
                "device": snap.get("device") or os.path.basename(os.path.dirname(path)),
                "firmware": snap.get("firmware") or "",
                "origin": snap.get("origin") or "",
                "total_objects": int(snap.get("total_objects") or 0),
                "section_count": int(snap.get("section_count") or 0),
                "generated_at": snap.get("generated_at") or "",
            }
        )
    out.sort(key=lambda r: r.get("generated_at") or "", reverse=True)
    return out


# --------------------------------------------------------------------------- #
#  Orchestrator: bytes -> snapshot files -> result dict                        #
# --------------------------------------------------------------------------- #
def _origin_stem(origin: str) -> str:
    """Filename stem of an upload, peeling a ``.gz``/``.zip`` wrapper first
    (so ``fw.conf.gz`` -> ``fw``)."""
    base = os.path.basename(origin or "")
    for ext in (".gz", ".zip"):
        if base.lower().endswith(ext):
            base = base[: -len(ext)]
            break
    return os.path.splitext(base)[0]


def import_backup_bytes(
    data: bytes,
    *,
    root: str,
    device_name: str = "",
    origin: str = "",
    by: str = "",
) -> dict[str, Any]:
    """Read, parse and store a FortiWeb backup file's bytes as a snapshot.

    ``device_name`` overrides the device folder; otherwise it is taken from the
    config's ``system global`` hostname, else the uploaded file stem. Writes
    ``<root>/<device>/_config.{json,txt}`` and returns a summary dict::

        {device, firmware, total_objects, section_count,
         sections{label: count}, snapshot_path, text_path, note}

    Raises :class:`ValueError` if the file holds no readable CLI config
    (e.g. an encrypted backup).
    """
    text, note = parse_backup_bytes(data)
    parsed = parse_config(text)
    device = (
        (device_name or "").strip()
        or device_hostname(parsed)
        or _origin_stem(origin)
        or "device"
    )
    snapshot = build_snapshot(parsed, text, device=device, origin=origin, note=note, by=by)
    snap_path = write_snapshot(snapshot, root=root)
    txt_path = write_snapshot_text(text, device, root=root)
    return {
        "device": device,
        "firmware": snapshot["firmware"],
        "total_objects": snapshot["total_objects"],
        "section_count": snapshot["section_count"],
        "sections": snapshot["sections"],
        "snapshot_path": snap_path,
        "text_path": txt_path,
        "note": note,
    }


__all__ = [
    "CONFIG_NAME",
    "CONFIG_TEXT_NAME",
    "SOURCE_IMPORT",
    "ConfigEntry",
    "ConfigSection",
    "parse_config",
    "parse_backup_bytes",
    "device_hostname",
    "device_firmware",
    "build_snapshot",
    "config_path",
    "text_path",
    "write_snapshot",
    "write_snapshot_text",
    "load_snapshot",
    "load_snapshot_text",
    "list_snapshots",
    "import_backup_bytes",
]
