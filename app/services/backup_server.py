"""SFTP access to the external backup server (backup-server, LXC 251 @ hypervisor04).

The Fortinet appliances push their own scheduled config backups here
(``config system backup`` → SFTP, e.g. fw6 daily 02:00), and the firmware
``.out`` binaries referenced by the firmware SoT repo live here too. This
module is SATOM's read side: verify the box is reachable, inventory what
the devices have pushed, and pull a firmware image into the app's local
firmware store (``FirmwareImage``) so a restore/downgrade can be driven from
the console without re-uploading by hand.

Connection settings come from ``settings_store.backup_server()`` (Settings →
SoT & Backup); the password is Fernet-encrypted at rest. Paramiko is already
a dependency (``ssh_ops`` uses it for the FortiWeb CLI battery).
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
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


def backup_content(device: str, filename: str, section: str = "") -> dict:
    """Full plain-text of one pushed backup's config sections — the 'view
    live config' path. Reuses the cached extraction; returns every text
    section (or just the named one). Encrypted/binary parts are listed in
    'skipped', never inlined."""
    try:
        res = _extraction(device, filename)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    secs = res["sections"]
    if section:
        secs = [s for s in secs if s["name"] == section]
        if not secs:
            return {"ok": False, "error": f"no text section named {section!r}"}
    return {"ok": True, "size": res["size"],
            "sections": [{"name": s["name"], "text": s["text"],
                          "lines": s["lines"]} for s in secs],
            "skipped": res["skipped"]}


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


# Fortinet ``.out`` naming carries the version two ways in the wild:
#   * dotted, on the real backup-server images:  FWB_KVM-v7.6.8.M-build1128-FORTINET.out
#   * packed (older/short form):             FWB_KVM-v750-build0387-FORTINET.out
# and a ``build<n>`` token. All best-effort — a name that matches neither form
# yields ("", "") and the caller keeps its own fallback rather than storing a
# wrong version.
_FW_VER_DOTTED_RE = re.compile(r"v(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
_FW_VER_PACKED_RE = re.compile(r"v(\d)(\d)(\d)\b", re.IGNORECASE)
_FW_BUILD_RE = re.compile(r"build(\d+)", re.IGNORECASE)


def parse_fw_version(filename: str) -> tuple[str, str]:
    """Best-effort ``(version, build)`` from a Fortinet firmware filename.

    ``FWB_KVM-v7.6.8.M-build1128-FORTINET.out`` -> ``("7.6.8", "1128")``;
    ``FWB_KVM-v750-build0387-FORTINET.out``      -> ``("7.5.0", "0387")``.
    Returns ``("", "")`` when no recognisable ``v...`` token is present so the
    caller can keep its own fallback instead of storing a wrong version."""
    name = posixpath.basename(filename or "")
    ver = ""
    m = _FW_VER_DOTTED_RE.search(name) or _FW_VER_PACKED_RE.search(name)
    if m:
        ver = ".".join(m.groups())
    b = _FW_BUILD_RE.search(name)
    build = b.group(1) if b else ""
    return ver, build


def _manifest_path() -> str:
    return os.path.join(_firmware_root(), "manifest.json")


def write_manifest() -> dict:
    """Regenerate ``<firmware_root>/manifest.json`` from the FirmwareImage table
    (the local source of truth). Called after every pull/upload so the machine-
    readable inventory never drifts from the DB. Never raises — a failure is
    reported in the return dict, not propagated into the pull/upload flow."""
    from ..models_firmware import FirmwareImage
    try:
        rows = FirmwareImage.query.order_by(FirmwareImage.product,
                                            FirmwareImage.version).all()
        images = [{
            "product": r.product,
            "model": r.model or "",
            "platform": r.platform or "",
            "version": r.version or "",
            "build": r.build or "",
            "filename": r.filename,
            "size_bytes": r.size_bytes or 0,
            "sha256": r.sha256 or "",
            "created_at": (r.created_at.isoformat() + "Z") if r.created_at else "",
        } for r in rows]
        doc = {
            "schema": "satom.firmware-manifest/1",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "count": len(images),
            "images": images,
        }
        path = _manifest_path()
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=False)
        os.replace(tmp, path)
        return {"ok": True, "count": len(images), "path": path}
    except Exception as exc:  # noqa: BLE001 — manifest is best-effort
        return {"ok": False, "detail": str(exc)}


def read_manifest() -> dict:
    """Return the current manifest doc (regenerating it if the file is missing)."""
    path = _manifest_path()
    if not os.path.exists(path):
        write_manifest()
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return {"schema": "satom.firmware-manifest/1", "count": 0, "images": []}


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
        ver, build = parse_fw_version(safe)
        fw = FirmwareImage(product=_guess_product(safe), version=ver or "?",
                           build=build or None,
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
        write_manifest()  # keep the machine-readable inventory in step with the DB
        return {"ok": True, "image_id": fw.id,
                "detail": f"{safe} pulled — {fw.size_bytes // (1024*1024)} MB, sha256 {fw.sha256[:12]}…"}
    except Exception as exc:  # noqa: BLE001
        db.session.rollback()
        return {"ok": False, "detail": str(exc)}
    finally:
        t.close()


# ── system-bundle push (write side) ─────────────────────────────────────────
#
# The device configs live on backup-server because the appliances push them; the
# firmware ``.out`` images live there too. The one copy that was NOT off-boxed
# was SATOM's OWN backup (the Postgres pg_dump + reports/ bundle) — it only
# existed on the primary and its rsync mirror on the standby (same two racks).
# ``push_bundle`` closes that: it SFTP-puts a system bundle into the server's
# ``system_path`` so the DB backup lives in a third failure domain (hypervisor04),
# separate from the primary (hypervisor06) and the Gitea/standby pair (hypervisor03).

def push_bundle(local_path: str, remote_name: str | None = None,
                remote_dir: str | None = None) -> dict:
    """Upload one system backup bundle to the external server's ``system_path``.
    Best-effort and self-contained: returns ``{ok, detail, remote?, size?}`` and
    never raises (the caller records the detail line either way).

    The chroot root on backup-server is ``root:root`` (an sftp-chroot requirement),
    so the ``/system`` folder itself is created out-of-band as the sftp user;
    here we ``stat`` it, fall back to ``mkdir`` (works only if the folder is
    user-owned), then ``put`` and verify the size round-trips.

    ``remote_dir`` overrides the destination — used by ``git_backup`` to land
    the repo bundles in ``<system_path>/git``. That subfolder IS creatable here
    because ``system_path`` itself is owned by the sftp user; only the chroot
    root is not."""
    name = remote_name or os.path.basename(local_path)
    if not os.path.exists(local_path):
        return {"ok": False, "detail": f"local bundle missing: {local_path}"}
    try:
        cfg = store.backup_server(reveal_secret=True)
        if not cfg.get("configured"):
            return {"ok": False, "detail": "backup server not configured "
                                           "(Settings → SoT & Backup)"}
        sys_path = remote_dir or cfg.get("system_path") or "/system"
        local_size = os.path.getsize(local_path)
        t, sftp = _connect(cfg)
        try:
            try:
                sftp.stat(sys_path)
            except IOError:
                try:
                    sftp.mkdir(sys_path)
                except IOError as exc:  # root-owned chroot → must be pre-created
                    return {"ok": False,
                            "detail": f"{sys_path} does not exist and could not be "
                                      f"created ({exc}); create it on the server "
                                      f"owned by the sftp user."}
            remote = posixpath.join(sys_path, name)
            sftp.put(local_path, remote)
            st = sftp.stat(remote)
            if int(st.st_size or 0) != local_size:
                return {"ok": False,
                        "detail": f"size mismatch after upload "
                                  f"({st.st_size} != {local_size})"}
        finally:
            t.close()
        return {"ok": True, "remote": remote, "size": local_size,
                "detail": f"{name} ({local_size // 1024} KB) → "
                          f"{cfg['host']}:{remote}"}
    except Exception as exc:  # noqa: BLE001 — never raise into the backup flow
        return {"ok": False, "detail": str(exc)}


def dir_inventory(path: str) -> dict:
    """Generic listing of one folder on the backup server. Same shape as
    :func:`system_inventory` (which predates it and is kept for the DB-bundle
    card); used by ``git_backup`` for ``<system_path>/git``. Never raises — a
    folder that was never created reads as an empty, reachable listing."""
    cfg = store.backup_server()
    out = {"configured": cfg["configured"], "reachable": False,
           "host": cfg["host"], "path": path, "error": "", "files": []}
    if not cfg["configured"]:
        return out
    try:
        t, sftp = _connect(store.backup_server(reveal_secret=True))
        try:
            try:
                out["files"] = _listing(sftp, path)
            except IOError:
                out["files"] = []  # nothing pushed yet
        finally:
            t.close()
        out["reachable"] = True
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    return out


def fetch_file(path: str, filename: str) -> bytes:
    """Raw bytes of one file under *path* on the backup server, for a browser
    download. Caller validates *filename* — this refuses separators only."""
    if "/" in filename or ".." in filename:
        raise ValueError("invalid filename")
    t, sftp = _connect()
    try:
        with sftp.open(posixpath.join(path, filename), "rb") as fh:
            fh.prefetch()
            return fh.read()
    finally:
        t.close()


def system_inventory() -> dict:
    """What system bundles the app has pushed to the external server's
    ``system_path`` — the third off-box copy, rendered on the System Backup
    page next to the primary/standby ones. Never raises."""
    cfg = store.backup_server()
    out = {"configured": cfg["configured"], "reachable": False,
           "host": cfg["host"], "path": cfg.get("system_path") or "/system",
           "error": "", "files": []}
    if not cfg["configured"]:
        return out
    try:
        full = store.backup_server(reveal_secret=True)
        sys_path = full.get("system_path") or "/system"
        t, sftp = _connect(full)
        try:
            try:
                out["files"] = _listing(sftp, sys_path)
            except IOError:
                out["files"] = []  # folder not created / nothing pushed yet
        finally:
            t.close()
        out["reachable"] = True
        out["path"] = sys_path
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    return out


def infra_probe() -> dict:
    """Light health probe for the infra dashboard: reachable + filesystem usage
    (SFTP ``statvfs``) + top-level counts. Short-lived connection, never raises.
    Deliberately does NOT expose CPU/RAM — this box is SFTP-jailed (chroot +
    ForceCommand internal-sftp), a separate failure domain, and the web worker
    has no shell there by design."""
    cfg = store.backup_server()
    out = {"configured": cfg["configured"], "reachable": False,
           "host": cfg["host"], "port": cfg["port"], "error": "",
           "disk": None, "devices": None, "firmware": None}
    if not cfg["configured"]:
        return out
    try:
        full = store.backup_server(reveal_secret=True)
        t, sftp = _connect(full)
        try:
            try:  # OpenSSH statvfs@openssh.com (paramiko ships no wrapper)
                from paramiko.sftp import CMD_EXTENDED, CMD_EXTENDED_REPLY
                rt, msg = sftp._request(CMD_EXTENDED, "statvfs@openssh.com", ".")
                if rt == CMD_EXTENDED_REPLY:
                    f = [msg.get_int64() for _ in range(11)]
                    frsize, blocks, bavail = f[1], f[2], f[4]
                    total = frsize * blocks
                    free = frsize * bavail
                    if total:
                        out["disk"] = {"total_gb": round(total / 1e9, 1),
                                       "used_gb": round((total - free) / 1e9, 1),
                                       "free_gb": round(free / 1e9, 1),
                                       "pct": round(100.0 * (total - free) / total, 1)}
            except Exception:
                pass
            try:
                cp = full.get("config_path") or "/configs"
                out["devices"] = sum(1 for e in sftp.listdir_attr(cp)
                                     if _stat.S_ISDIR(e.st_mode or 0))
            except Exception:
                pass
            try:
                fp = full.get("firmware_path") or "/firmware"
                out["firmware"] = sum(1 for e in sftp.listdir_attr(fp)
                                      if not _stat.S_ISDIR(e.st_mode or 0))
            except Exception:
                pass
        finally:
            t.close()
        out["reachable"] = True
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)[:200]
    return out
