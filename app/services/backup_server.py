"""SFTP access to the external backup server (backup-server, LXC 251 @ hypervisor04).

The Fortinet appliances push their own scheduled config backups here
(``config system backup`` → SFTP, e.g. fw6 daily 02:00), and the firmware
``.out`` binaries referenced by the firmware SoT repo live here too. This
module is OFortMAut's read side: verify the box is reachable, inventory what
the devices have pushed, and pull a firmware image into the app's local
firmware store (``FirmwareImage``) so a restore/downgrade can be driven from
the console without re-uploading by hand.

Connection settings come from ``settings_store.backup_server()`` (Settings →
SoT & Backup); the password is Fernet-encrypted at rest. Paramiko is already
a dependency (``ssh_ops`` uses it for the FortiWeb CLI battery).
"""
from __future__ import annotations

import hashlib
import os
import posixpath
import stat as _stat
from datetime import datetime

from flask import current_app

from . import settings_store as store


def _connect(cfg: dict | None = None):
    """Open an SFTP session from the stored settings. Caller closes the
    returned transport. Raises on any failure — callers map to a friendly
    error."""
    import paramiko  # lazy, same convention as ssh_ops
    cfg = cfg or store.backup_server(reveal_secret=True)
    if not cfg.get("host") or not cfg.get("username"):
        raise RuntimeError("backup server not configured (Settings → SoT & Backup)")
    t = paramiko.Transport((cfg["host"], int(cfg.get("port") or 22)))
    t.connect(username=cfg["username"], password=cfg.get("password") or "")
    return t, paramiko.SFTPClient.from_transport(t)


def test_connection() -> dict:
    """Settings-page probe: connect, list both roots, report counts."""
    try:
        cfg = store.backup_server(reveal_secret=True)
        t, sftp = _connect(cfg)
        try:
            cdirs = sftp.listdir(cfg["config_path"])
            fw = sftp.listdir(cfg["firmware_path"])
        finally:
            t.close()
        return {"ok": True,
                "detail": (f"connected to {cfg['host']}:{cfg['port']} — "
                           f"{len(cdirs)} device folder(s) under {cfg['config_path']}, "
                           f"{len(fw)} file(s) under {cfg['firmware_path']}")}
    except Exception as exc:  # noqa: BLE001 — settings-page probe surfaces anything
        return {"ok": False, "detail": str(exc)}


def _listing(sftp, path: str) -> list[dict]:
    rows = []
    for att in sftp.listdir_attr(path):
        if _stat.S_ISDIR(att.st_mode or 0):
            continue
        rows.append({
            "name": att.filename,
            "size": int(att.st_size or 0),
            "mtime": datetime.utcfromtimestamp(att.st_mtime).strftime("%Y-%m-%d %H:%M")
            if att.st_mtime else "",
        })
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def inventory() -> dict:
    """What the backup server holds: device-pushed config backups (one folder
    per device under config_path) + firmware binaries. Never raises — the
    System Backup page renders the error state instead."""
    cfg = store.backup_server()
    out = {"configured": cfg["configured"], "reachable": False, "host": cfg["host"],
           "port": cfg["port"], "error": "", "devices": [], "firmware": []}
    if not cfg["configured"]:
        return out
    try:
        full = store.backup_server(reveal_secret=True)
        t, sftp = _connect(full)
        try:
            for entry in sorted(sftp.listdir_attr(full["config_path"]),
                                key=lambda a: a.filename):
                if not _stat.S_ISDIR(entry.st_mode or 0):
                    continue
                files = _listing(sftp, posixpath.join(full["config_path"], entry.filename))
                out["devices"].append({"device": entry.filename,
                                       "files": files[:10],
                                       "count": len(files),
                                       "latest": files[0]["mtime"] if files else ""})
            out["firmware"] = _listing(sftp, full["firmware_path"])
        finally:
            t.close()
        out["reachable"] = True
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    return out


# ── device-config backup browser (System Backup page modal) ─────────────────
#
# The appliances push their backups as a zip wrapping a Fortinet multi-file
# container (``fwb_system.conf``): a [header] with a ``file_split`` marker,
# then alternating [file] metadata / payload blocks. The plain-text config
# sections (encrypt=no) are extracted for diff & search; the encrypted
# extend-tar blob is listed but skipped.

_MAX_FETCH = 200 * 1024 * 1024  # refuse to pull anything bigger over SFTP

# tiny cache so an interactive diff+search session doesn't re-download the
# same multi-MB file on every request: (device, name, size) → extraction
_CACHE: dict = {}
_CACHE_MAX = 6


def _safe_names(device: str, filename: str) -> tuple[str, str]:
    dev = posixpath.basename((device or "").strip())
    fn = posixpath.basename((filename or "").strip())
    if not dev or not fn:
        raise RuntimeError("missing device or file name")
    return dev, fn


def device_files(device: str) -> dict:
    """Full listing of one device's folder on the backup server (the card
    itself only shows a summary)."""
    dev = posixpath.basename((device or "").strip())
    if not dev:
        return {"ok": False, "error": "missing device", "files": []}
    try:
        cfg = store.backup_server(reveal_secret=True)
        t, sftp = _connect(cfg)
        try:
            files = _listing(sftp, posixpath.join(cfg["config_path"], dev))
        finally:
            t.close()
        return {"ok": True, "device": dev, "files": files}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "files": []}


def _fetch_raw(device: str, filename: str) -> bytes:
    dev, fn = _safe_names(device, filename)
    cfg = store.backup_server(reveal_secret=True)
    t, sftp = _connect(cfg)
    try:
        remote = posixpath.join(cfg["config_path"], dev, fn)
        st = sftp.stat(remote)
        if (st.st_size or 0) > _MAX_FETCH:
            raise RuntimeError(f"{fn} is {st.st_size} bytes — too large to fetch")
        with sftp.open(remote, "rb") as fh:
            fh.prefetch()
            return fh.read()
    finally:
        t.close()


def _looks_text(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(sample) > 0.95


def _parse_container(blob: bytes) -> list[dict]:
    """Split a Fortinet multi-file backup container into its [file] entries.
    Returns [{name, encrypt, compress, payload}] in on-disk order."""
    import re
    m = re.search(rb"file_split=(.+?)\n", blob)
    if not m:
        return []
    parts = blob.split(m.group(1))
    out, pending = [], None
    for part in parts:
        if b"[file]" in part[:200]:
            meta = {}
            for line in part.split(b"[file]", 1)[1].splitlines():
                if b"=" in line:
                    k, v = line.split(b"=", 1)
                    meta[k.decode("ascii", "replace").strip()] = \
                        v.decode("utf-8", "replace").strip()
            pending = meta
        elif pending is not None:
            pending["payload"] = part.lstrip(b"\n")
            out.append(pending)
            pending = None
    return out


def _extract_texts(filename: str, data: bytes) -> dict:
    """Unwrap zip / gzip / Fortinet container down to the plain-text config
    sections. → {sections: [{name, text, lines}], skipped: [names]}."""
    import gzip
    import io
    import zipfile
    if data[:2] == b"PK":
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
            inner = [(i.filename, z.read(i)) for i in z.infolist()]
        except Exception:
            inner = [(filename, data)]
    else:
        inner = [(filename, data)]
    sections, skipped = [], []
    for name, blob in inner:
        if blob[:2] == b"\x1f\x8b":
            try:
                blob = gzip.decompress(blob)
            except Exception:
                skipped.append(name)
                continue
        if b"file_split=" in blob[:512] and blob[:8].startswith(b"[header]"):
            for ent in _parse_container(blob):
                ename = ent.get("name") or name
                payload = ent.get("payload") or b""
                if ent.get("encrypt") == "yes":
                    skipped.append(f"{ename} (encrypted)")
                    continue
                if payload[:2] == b"\x1f\x8b":
                    try:
                        payload = gzip.decompress(payload)
                    except Exception:
                        skipped.append(ename)
                        continue
                if not _looks_text(payload[:4096]):
                    skipped.append(ename)
                    continue
                text = payload.decode("utf-8", "replace")
                sections.append({"name": ename, "text": text,
                                 "lines": text.count("\n") + 1})
        elif _looks_text(blob[:4096]):
            text = blob.decode("utf-8", "replace")
            sections.append({"name": name, "text": text,
                             "lines": text.count("\n") + 1})
        else:
            skipped.append(name)
    return {"sections": sections, "skipped": skipped}


def _extraction(device: str, filename: str) -> dict:
    """Cached download+extract of one pushed backup."""
    dev, fn = _safe_names(device, filename)
    key = (dev, fn)
    if key in _CACHE:
        return _CACHE[key]
    data = _fetch_raw(dev, fn)
    res = _extract_texts(fn, data)
    res["size"] = len(data)
    while len(_CACHE) >= _CACHE_MAX:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[key] = res
    return res


def backup_outline(device: str, filename: str) -> dict:
    """What's inside one pushed backup — section names/sizes, no content."""
    try:
        res = _extraction(device, filename)
        return {"ok": True, "size": res["size"], "skipped": res["skipped"],
                "sections": [{"name": s["name"], "lines": s["lines"]}
                             for s in res["sections"]]}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}


def diff_device_backups(device: str, file_a: str, file_b: str) -> dict:
    """Unified diff of the plain-text config sections between two pushed
    backups of the same device (e.g. yesterday vs today)."""
    import difflib
    try:
        a = _extraction(device, file_a)
        b = _extraction(device, file_b)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    sa = {s["name"]: s for s in a["sections"]}
    sb = {s["name"]: s for s in b["sections"]}
    out, identical, truncated = [], True, False
    for name in sorted(set(sa) | set(sb)):
        ta = sa.get(name, {}).get("text", "")
        tb = sb.get(name, {}).get("text", "")
        if ta == tb:
            continue
        identical = False
        lines = list(difflib.unified_diff(
            ta.splitlines(), tb.splitlines(),
            fromfile=f"{file_a}:{name}", tofile=f"{file_b}:{name}", lineterm=""))
        if len(lines) > 3000:
            lines = lines[:3000]
            truncated = True
        out.append({"section": name, "diff": "\n".join(lines),
                    "changes": sum(1 for l in lines
                                   if l[:1] in "+-" and l[:3] not in ("+++", "---"))})
    return {"ok": True, "identical": identical, "sections": out,
            "truncated": truncated,
            "skipped": sorted(set(a["skipped"]) | set(b["skipped"]))}


def search_device_backup(device: str, filename: str, query: str,
                         context: int = 2, limit: int = 300) -> dict:
    """Case-insensitive substring search inside one pushed backup's text
    sections, with a little context around each hit."""
    q = (query or "").strip()
    if len(q) < 2:
        return {"ok": False, "error": "query too short (min 2 chars)"}
    try:
        res = _extraction(device, filename)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    ql = q.lower()
    hits, total = [], 0
    for sec in res["sections"]:
        lines = sec["text"].splitlines()
        for i, line in enumerate(lines):
            if ql in line.lower():
                total += 1
                if len(hits) < limit:
                    lo, hi = max(0, i - context), min(len(lines), i + context + 1)
                    hits.append({"section": sec["name"], "line": i + 1,
                                 "context": "\n".join(lines[lo:hi])})
    return {"ok": True, "query": q, "total": total, "hits": hits,
            "truncated": total > len(hits), "skipped": res["skipped"]}


def download_backup_stream(device: str, filename: str):
    """Raw bytes of one pushed backup, for the browser download button."""
    return _fetch_raw(device, filename)


def _firmware_root() -> str:
    """Same derivation as views/firmware.py: next to the data dir."""
    uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
    if uri.startswith("sqlite:///"):
        base = os.path.dirname(uri[len("sqlite:///"):])
    else:
        base = os.path.join(os.path.dirname(current_app.root_path), "data")
    d = os.path.join(base, "firmware")
    os.makedirs(d, exist_ok=True)
    return d


def _guess_product(filename: str) -> str:
    low = filename.lower()
    if low.startswith("fad") or "fortiadc" in low:
        return "fortiadc"
    return "fortiweb"


def pull_firmware(filename: str, by: str = "") -> dict:
    """Download one ``.out`` image from the backup server's firmware folder
    into the local firmware store and register it as a ``FirmwareImage`` so
    the existing Upgrade/Downgrade actions can use it. Idempotent on
    filename: an already-pulled image is reported, not duplicated."""
    from ..extensions import db
    from ..models_firmware import FirmwareImage

    safe = posixpath.basename(filename or "")
    if not safe or not safe.lower().endswith(".out"):
        return {"ok": False, "detail": "only .out firmware images can be pulled"}
    existing = FirmwareImage.query.filter_by(filename=safe).first()
    if existing is not None:
        return {"ok": True, "detail": f"{safe} already in the local firmware store",
                "image_id": existing.id, "already": True}

    cfg = store.backup_server(reveal_secret=True)
    t, sftp = _connect(cfg)
    try:
        remote = posixpath.join(cfg["firmware_path"], safe)
        fw = FirmwareImage(product=_guess_product(safe), version="?",
                           filename=safe, stored_path="", size_bytes=0,
                           sha256="", uploaded_by=by or "backup-server",
                           notes=f"pulled from backup server {cfg['host']}:{remote}")
        db.session.add(fw)
        db.session.flush()
        dest_dir = os.path.join(_firmware_root(), str(fw.id))
        os.makedirs(dest_dir, exist_ok=True)
        dest = os.path.join(dest_dir, safe)
        sftp.get(remote, dest)
        h = hashlib.sha256()
        with open(dest, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        fw.stored_path = dest
        fw.size_bytes = os.path.getsize(dest)
        fw.sha256 = h.hexdigest()
        db.session.commit()
        return {"ok": True, "image_id": fw.id,
                "detail": f"{safe} pulled — {fw.size_bytes // (1024*1024)} MB, sha256 {fw.sha256[:12]}…"}
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        return {"ok": False, "detail": str(exc)}
    finally:
        t.close()
