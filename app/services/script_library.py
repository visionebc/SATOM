"""Script Library: operator-facing Python scripts an administrator writes.

An administrator keeps a small multi-file project per script (``main.py`` plus
modules and data files), defines a FORM (the fields an operator fills in) and
publishes frozen versions. Every run -- an administrator's test run of the
draft or an operator's run of a published version -- executes in the sandbox
of ``app.services.sandbox`` through ``satom-scripts.service``, which has no
database and no ``.env``.

ON DISK (``data/scripts/``; replicated to the standby by the HA data sync,
except the queue and the claims, which are each node's own work)::

    library/<slug>/meta.json              name, form, network, timeout, audience,
                                          version list, published version
    library/<slug>/draft/<files>          what the editor shows and saves
    library/<slug>/versions/<n>/files/    frozen tree of version n
    library/<slug>/versions/<n>/meta.json frozen form/network/timeout/entry
    queue/<request_id>.json               a run waiting for the runner
    claimed/                              runs the runner took (at-most-once)
    status/<request_id>.json              live and finished run records

Disk and not the database ON PURPOSE: the runner that executes these scripts
must not hold a database connection or ``FERNET_KEY``. It reads frozen files
and writes status files, and nothing else.

WHAT A SCRIPT RECEIVES
    stdin   one JSON object: ``{"inputs": {...}, "script": ..., "version": ...}``.
            ``satom_script.inputs`` reads it. Never environment variables: an
            operator-chosen ``PYTHONPATH`` or ``LD_PRELOAD`` is an escape.
    fd      a result channel: ``satom_script.result(data)`` writes one JSON
            document the run record shows as structured output.
    stdout  the log, captured, redacted and capped.
"""
from __future__ import annotations

import io
import json
import keyword
import os
import re
import shutil
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
ROOT = APP_DIR / "data" / "scripts"
LIBRARY_DIR = ROOT / "library"
REQ_DIR = ROOT / "queue"
CLAIM_DIR = ROOT / "claimed"
STATUS_DIR = ROOT / "status"

ENTRY = "main.py"

# --- limits ----------------------------------------------------------------
MAX_FILES = 64
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 4
MAX_FIELDS = 40
MAX_INPUT_CHARS = 64 * 1024
MAX_OPTIONS = 100
MAX_VERSIONS = 50
TIMEOUT_MIN, TIMEOUT_MAX, TIMEOUT_DEFAULT = 5, 900, 60
OUTPUT_CAP = 64 * 1024
RESULT_CAP = 256 * 1024

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,47}$")
# Relative POSIX paths, letters/digits/_-. per segment, a known text suffix.
_PATH_SEG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
TEXT_SUFFIXES = (".py", ".txt", ".json", ".csv", ".yaml", ".yml", ".md",
                 ".cfg", ".ini", ".j2", ".tmpl", ".xml", ".sql")
_FIELD_RE = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
FIELD_TYPES = ("text", "textarea", "number", "select", "checkbox", "password")
NETWORK_MODES = ("none", "egress")
AUDIENCES = ("admins", "operators")
# Names the SDK and the runner own inside the work directory.
RESERVED_FILES = ("satom_script.py", "satom_sdk.py", "_satom_boot.py")


class ScriptError(ValueError):
    """A request the library refuses; the message is shown to the admin."""


def _utcnow() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ---------------------------------------------------------------------------
#  validation
# ---------------------------------------------------------------------------
def validate_slug(slug: str) -> str:
    slug = (slug or "").strip()
    if not _SLUG_RE.match(slug):
        raise ScriptError("the id must be 2-48 characters: lowercase letters, "
                          "digits, '-' or '_', starting with a letter or digit")
    return slug


def validate_path(path: str) -> str:
    """A relative file path inside the script's tree, or ScriptError."""
    if not isinstance(path, str):
        raise ScriptError("a file name must be text")
    p = path.strip().replace("\\", "/")
    if not p or p.startswith("/") or "//" in p:
        raise ScriptError("invalid file name %r" % path)
    segs = p.split("/")
    if len(segs) > MAX_DEPTH:
        raise ScriptError("%r is nested deeper than %d levels" % (path, MAX_DEPTH))
    for seg in segs:
        if seg in (".", "..") or not _PATH_SEG_RE.match(seg):
            raise ScriptError("invalid file name %r" % path)
    if not p.lower().endswith(TEXT_SUFFIXES):
        raise ScriptError("%r: only text files are kept (%s)"
                          % (path, ", ".join(TEXT_SUFFIXES)))
    if p in RESERVED_FILES or p.startswith("."):
        raise ScriptError("%r is reserved by SATOM" % path)
    return p


def validate_files(files: Any) -> dict[str, str]:
    if not isinstance(files, dict) or not files:
        raise ScriptError("a script needs at least %s" % ENTRY)
    if len(files) > MAX_FILES:
        raise ScriptError("at most %d files per script" % MAX_FILES)
    out: dict[str, str] = {}
    total = 0
    for raw, content in files.items():
        path = validate_path(raw)
        if path in out:
            raise ScriptError("%r appears twice" % path)
        if not isinstance(content, str):
            raise ScriptError("%r: content must be text" % path)
        size = len(content.encode("utf-8"))
        if size > MAX_FILE_BYTES:
            raise ScriptError("%r is larger than %d KiB" % (path, MAX_FILE_BYTES // 1024))
        total += size
        out[path] = content
    if total > MAX_TOTAL_BYTES:
        raise ScriptError("the script is larger than %d MiB in total"
                          % (MAX_TOTAL_BYTES // (1024 * 1024)))
    if ENTRY not in out:
        raise ScriptError("%s is required: it is what runs" % ENTRY)
    return out


def syntax_problems(files: dict[str, str]) -> list[dict]:
    """Every .py that does not compile, with file/line/message."""
    probs = []
    for path, src in sorted(files.items()):
        if not path.endswith(".py"):
            continue
        try:
            compile(src, path, "exec")
        except SyntaxError as exc:
            probs.append({"file": path, "line": exc.lineno or 0,
                          "col": exc.offset or 0, "message": exc.msg})
        except ValueError as exc:  # null bytes
            probs.append({"file": path, "line": 0, "col": 0, "message": str(exc)})
    return probs


def clean_fields(fields: Any) -> list[dict]:
    """The form definition, normalised. Raises ScriptError on a bad field."""
    if fields in (None, ""):
        return []
    if not isinstance(fields, list):
        raise ScriptError("the form must be a list of fields")
    if len(fields) > MAX_FIELDS:
        raise ScriptError("at most %d form fields" % MAX_FIELDS)
    out, seen = [], set()
    for i, f in enumerate(fields, 1):
        if not isinstance(f, dict):
            raise ScriptError("field %d is not an object" % i)
        name = str(f.get("name") or "").strip()
        if not _FIELD_RE.match(name) or keyword.iskeyword(name):
            raise ScriptError("field %d: %r is not a valid variable name "
                              "(lowercase, digits, _)" % (i, name))
        if name in seen:
            raise ScriptError("field %r is defined twice" % name)
        seen.add(name)
        ftype = str(f.get("type") or "text")
        if ftype not in FIELD_TYPES:
            raise ScriptError("field %r: unknown type %r" % (name, ftype))
        label = str(f.get("label") or name).strip()[:120]
        clean = {"name": name, "type": ftype, "label": label,
                 "required": bool(f.get("required")),
                 "help": str(f.get("help") or "").strip()[:300]}
        if ftype == "select":
            opts = f.get("options") or []
            if isinstance(opts, str):
                opts = [o for o in opts.splitlines()]
            opts = [str(o).strip()[:200] for o in opts if str(o).strip()]
            if not opts:
                raise ScriptError("field %r: a select needs options" % name)
            if len(opts) > MAX_OPTIONS or len(set(opts)) != len(opts):
                raise ScriptError("field %r: up to %d distinct options" % (name, MAX_OPTIONS))
            clean["options"] = opts
        default = f.get("default")
        if ftype == "password":
            default = None            # a default secret would be stored in clear
        elif ftype == "checkbox":
            default = bool(default) if default not in (None, "") else False
        elif default in (None, ""):
            default = None
        if default is not None:
            try:
                default = coerce_value(clean, default)
            except ScriptError as exc:
                raise ScriptError("field %r: default: %s" % (name, exc))
        clean["default"] = default
        out.append(clean)
    return out


def coerce_value(field: dict, value: Any) -> Any:
    ftype = field["type"]
    if ftype == "checkbox":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "on", "yes")
    if ftype == "number":
        if isinstance(value, bool):
            raise ScriptError("not a number")
        if isinstance(value, (int, float)):
            return value
        s = str(value).strip()
        try:
            return int(s)
        except ValueError:
            try:
                f = float(s)
            except ValueError:
                raise ScriptError("%r is not a number" % s)
            if f != f or f in (float("inf"), float("-inf")):
                raise ScriptError("not a finite number")
            return f
    s = "" if value is None else str(value)
    if len(s) > MAX_INPUT_CHARS:
        raise ScriptError("longer than %d characters" % MAX_INPUT_CHARS)
    if ftype == "select" and s not in field.get("options", []):
        raise ScriptError("%r is not one of the options" % s)
    return s


def resolve_inputs(fields: list[dict], raw: Any) -> dict[str, Any]:
    """Validate what a form submitted against ``fields``.

    Unknown names are dropped (only what the administrator defined reaches
    the script). Missing optional fields take their default."""
    raw = raw if isinstance(raw, dict) else {}
    out: dict[str, Any] = {}
    problems = []
    for f in fields:
        name = f["name"]
        val = raw.get(name)
        empty = val is None or (isinstance(val, str) and val.strip() == "")
        if f["type"] == "checkbox":
            out[name] = coerce_value(f, val) if val is not None else bool(f.get("default"))
            continue
        if empty:
            if f["required"]:
                problems.append("%s is required" % (f["label"] or name))
                continue
            out[name] = f.get("default")
            continue
        try:
            out[name] = coerce_value(f, val)
        except ScriptError as exc:
            problems.append("%s: %s" % (f["label"] or name, exc))
    if problems:
        raise ScriptError("; ".join(problems))
    return out


def secret_inputs(fields: list[dict], inputs: dict[str, Any]) -> dict[str, str]:
    """{field: value} of the password fields that were filled in."""
    return {f["name"]: str(inputs[f["name"]]) for f in fields
            if f["type"] == "password" and inputs.get(f["name"])}


def shown_inputs(fields: list[dict], inputs: dict[str, Any]) -> dict[str, Any]:
    """The inputs as a run record may show them: passwords masked."""
    out = {}
    for f in fields:
        if f["name"] not in inputs:
            continue
        v = inputs[f["name"]]
        out[f["name"]] = ("********" if v else "") if f["type"] == "password" else v
    return out


def clean_settings(meta: dict) -> dict:
    name = str(meta.get("name") or "").strip()[:120]
    if not name:
        raise ScriptError("a name is required")
    network = str(meta.get("network") or "none")
    if network not in NETWORK_MODES:
        raise ScriptError("network must be one of %s" % ", ".join(NETWORK_MODES))
    audience = str(meta.get("audience") or "admins")
    if audience not in AUDIENCES:
        raise ScriptError("audience must be one of %s" % ", ".join(AUDIENCES))
    try:
        timeout = int(meta.get("timeout") or TIMEOUT_DEFAULT)
    except (TypeError, ValueError):
        raise ScriptError("timeout must be a number of seconds")
    timeout = max(TIMEOUT_MIN, min(TIMEOUT_MAX, timeout))
    return {"name": name,
            "description": str(meta.get("description") or "").strip()[:2000],
            "network": network, "audience": audience, "timeout": timeout,
            "fields": clean_fields(meta.get("fields"))}


# ---------------------------------------------------------------------------
#  file helpers
# ---------------------------------------------------------------------------
def _atomic_write(path: Path, data: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / ("." + path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _write_json(path: Path, obj: Any, mode: int = 0o640) -> None:
    _atomic_write(path, json.dumps(obj, indent=2, sort_keys=True, default=str), mode)


def _read_json(path: Path) -> dict:
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _read_tree(base: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not base.is_dir():
        return out
    for p in sorted(base.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(base).as_posix()
        try:
            validate_path(rel)
        except ScriptError:
            continue
        out[rel] = p.read_text(encoding="utf-8", errors="replace")
    return out


def _write_tree(base: Path, files: dict[str, str]) -> None:
    """Replace ``base`` with exactly ``files`` (built aside, then swapped)."""
    tmp = base.parent / ("." + base.name + ".new-" + uuid.uuid4().hex[:6])
    tmp.mkdir(parents=True)
    for rel, content in files.items():
        dst = tmp / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(dst, content)
    old = None
    if base.exists():
        old = base.parent / ("." + base.name + ".old-" + uuid.uuid4().hex[:6])
        os.replace(base, old)
    os.replace(tmp, base)
    if old is not None:
        shutil.rmtree(old, ignore_errors=True)


def _dir(slug: str) -> Path:
    return LIBRARY_DIR / validate_slug(slug)


# ---------------------------------------------------------------------------
#  scripts
# ---------------------------------------------------------------------------
STARTER = '''"""Starter script. Fill in the form fields under the Form tab; their values
arrive in `inputs`, keyed by the field name."""
from satom_script import inputs, result, log

name = inputs.get("name") or "world"
log("hello, %s" % name)
result({"greeting": "hello, %s" % name})
'''

STARTER_FIELDS = [{"name": "name", "type": "text", "label": "Name",
                   "required": False, "help": "Who to greet", "default": None}]


def exists(slug: str) -> bool:
    try:
        return (_dir(slug) / "meta.json").is_file()
    except ScriptError:
        return False


def get(slug: str) -> dict | None:
    d = _dir(slug)
    meta = _read_json(d / "meta.json")
    if not meta:
        return None
    meta["files"] = _read_tree(d / "draft")
    meta["problems"] = syntax_problems(meta["files"])
    return meta


def list_scripts() -> list[dict]:
    out = []
    if not LIBRARY_DIR.is_dir():
        return out
    for d in sorted(LIBRARY_DIR.iterdir()):
        if not d.is_dir() or not _SLUG_RE.match(d.name):
            continue
        meta = _read_json(d / "meta.json")
        if meta:
            out.append({k: meta.get(k) for k in (
                "slug", "name", "description", "audience", "network", "published",
                "updated_at", "updated_by", "draft_changed")}
                | {"fields": len(meta.get("fields") or []),
                   "versions": len(meta.get("versions") or [])})
    return out


def create(slug: str, name: str, by: str) -> dict:
    slug = validate_slug(slug)
    d = _dir(slug)
    if (d / "meta.json").exists():
        raise ScriptError("a script with the id %r already exists" % slug)
    settings = clean_settings({"name": name or slug, "fields": STARTER_FIELDS})
    now = _utcnow()
    meta = {"slug": slug, **settings, "entry": ENTRY, "versions": [],
            "published": None, "draft_changed": True,
            "created_by": by, "created_at": now, "updated_by": by, "updated_at": now}
    _write_tree(d / "draft", {ENTRY: STARTER})
    _write_json(d / "meta.json", meta)
    return get(slug)


def save_draft(slug: str, files: Any, settings: dict, by: str) -> dict:
    """Save the editor's tree and the settings/form. Syntax errors do not
    block a draft (an editor that refuses to save half-written code loses
    work); they block publishing."""
    d = _dir(slug)
    meta = _read_json(d / "meta.json")
    if not meta:
        raise ScriptError("no script %r" % slug)
    files = validate_files(files)
    clean = clean_settings({**meta, **(settings or {})})
    _write_tree(d / "draft", files)
    meta.update(clean)
    meta.update({"updated_by": by, "updated_at": _utcnow(), "draft_changed": True})
    _write_json(d / "meta.json", meta)
    return get(slug)


def publish(slug: str, note: str, by: str) -> dict:
    d = _dir(slug)
    meta = _read_json(d / "meta.json")
    if not meta:
        raise ScriptError("no script %r" % slug)
    files = _read_tree(d / "draft")
    validate_files(files)
    probs = syntax_problems(files)
    if probs:
        p = probs[0]
        raise ScriptError("cannot publish: %s line %s: %s" % (p["file"], p["line"], p["message"]))
    versions = meta.get("versions") or []
    n = (max((v["n"] for v in versions), default=0)) + 1
    vdir = d / "versions" / str(n)
    _write_tree(vdir / "files", files)
    frozen = {k: meta[k] for k in ("name", "fields", "network", "timeout", "entry")}
    frozen.update({"n": n, "published_by": by, "published_at": _utcnow(),
                   "note": str(note or "").strip()[:500]})
    _write_json(vdir / "meta.json", frozen)
    versions.append({"n": n, "at": frozen["published_at"], "by": by,
                     "note": frozen["note"], "files": len(files)})
    meta.update({"versions": versions, "published": n, "draft_changed": False,
                 "updated_by": by, "updated_at": _utcnow()})
    _prune_versions(d, meta)
    _write_json(d / "meta.json", meta)
    return get(slug)


def _prune_versions(d: Path, meta: dict) -> None:
    versions = meta.get("versions") or []
    if len(versions) <= MAX_VERSIONS:
        return
    keep = versions[-MAX_VERSIONS:]
    if meta.get("published") and meta["published"] not in [v["n"] for v in keep]:
        keep = [v for v in versions if v["n"] == meta["published"]] + keep[1:]
    drop = {v["n"] for v in versions} - {v["n"] for v in keep}
    for n in drop:
        shutil.rmtree(d / "versions" / str(n), ignore_errors=True)
    meta["versions"] = keep


def version(slug: str, n: int) -> dict | None:
    vdir = _dir(slug) / "versions" / str(int(n))
    frozen = _read_json(vdir / "meta.json")
    if not frozen:
        return None
    frozen["files"] = _read_tree(vdir / "files")
    return frozen


def restore(slug: str, n: int, by: str) -> dict:
    v = version(slug, n)
    if v is None:
        raise ScriptError("no version %s" % n)
    meta = _read_json(_dir(slug) / "meta.json")
    return save_draft(slug, v["files"], {**meta, "fields": v["fields"],
                                         "network": v["network"],
                                         "timeout": v["timeout"]}, by)


def delete(slug: str) -> None:
    d = _dir(slug)
    if not d.is_dir():
        raise ScriptError("no script %r" % slug)
    trash = d.parent / (".deleted-" + d.name + "-" + uuid.uuid4().hex[:6])
    os.replace(d, trash)
    shutil.rmtree(trash, ignore_errors=True)


# ---------------------------------------------------------------------------
#  upload / download
# ---------------------------------------------------------------------------
MAX_UPLOAD_BYTES = 4 * 1024 * 1024


def files_from_upload(filename: str, data: bytes) -> dict[str, str]:
    """A .py file -> {name: text}; a .zip -> its text files.

    The zip is read member by member with a hard cap per member and in total
    (a zip bomb stops at the cap), every name goes through validate_path, and
    symlinks and directories are skipped, never followed."""
    if len(data) > MAX_UPLOAD_BYTES:
        raise ScriptError("upload larger than %d MiB" % (MAX_UPLOAD_BYTES // (1024 * 1024)))
    name = (filename or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if name.lower().endswith(".zip"):
        return _files_from_zip(data)
    path = validate_path(name)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ScriptError("%s is not UTF-8 text" % name)
    validate_files({path: text, **({} if path == ENTRY else {ENTRY: ""})})
    return {path: text}


def _files_from_zip(data: bytes) -> dict[str, str]:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise ScriptError("not a valid zip file")
    out: dict[str, str] = {}
    total = 0
    members = [m for m in zf.infolist() if not m.is_dir()]
    names = [m.filename for m in members]
    # A zip of a folder ("myscript/main.py") is unwrapped to its contents.
    prefix = ""
    tops = {n.split("/", 1)[0] for n in names}
    if len(tops) == 1 and all("/" in n for n in names):
        top = tops.pop()
        # Only a real folder name is unwrapped: "../x.py" or "/x.py" must be
        # refused by validate_path, not silently re-rooted.
        if top not in (".", "..") and _PATH_SEG_RE.match(top):
            prefix = top + "/"
    for m in members:
        mode = (m.external_attr >> 16) & 0o170000
        if mode == 0o120000:          # symlink
            continue
        rel = m.filename[len(prefix):] if prefix else m.filename
        if rel.startswith("__MACOSX/") or rel.split("/")[-1].startswith("."):
            continue
        if "__pycache__" in rel.split("/") or rel.endswith(".pyc"):
            continue
        path = validate_path(rel)
        if len(out) >= MAX_FILES:
            raise ScriptError("the zip has more than %d files" % MAX_FILES)
        with zf.open(m) as fh:
            raw = fh.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ScriptError("%s is larger than %d KiB" % (path, MAX_FILE_BYTES // 1024))
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ScriptError("the zip expands past %d MiB" % (MAX_TOTAL_BYTES // (1024 * 1024)))
        try:
            out[path] = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise ScriptError("%s is not UTF-8 text" % path)
    if not out:
        raise ScriptError("the zip contains no usable text files")
    return out


def zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in sorted(files.items()):
            zf.writestr(path, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
#  runs
# ---------------------------------------------------------------------------
_RID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[a-z0-9_-]{1,48}-[0-9a-f]{6}$")


def _new_request_id(slug: str) -> str:
    return "%s-%s-%s" % (datetime.utcnow().strftime("%Y%m%d-%H%M%S"), slug,
                         uuid.uuid4().hex[:6])


def enqueue_run(slug: str, *, version_ref: str | int, raw_inputs: Any, by: str,
                trigger: str = "test", node: str = "") -> dict:
    """Validate the inputs against the form OF THAT VERSION and queue a run.

    ``version_ref``: ``"draft"`` (administrators' test runs) or a published
    version number. The request carries the inputs, including password
    values, in a 0600 file the runner deletes as it claims it; the status
    record only ever holds the masked form."""
    slug = validate_slug(slug)
    if version_ref == "draft":
        meta = _read_json(_dir(slug) / "meta.json")
        if not meta:
            raise ScriptError("no script %r" % slug)
        files = _read_tree(_dir(slug) / "draft")
        validate_files(files)
        probs = syntax_problems(files)
        if probs:
            p = probs[0]
            raise ScriptError("%s line %s: %s" % (p["file"], p["line"], p["message"]))
        fields, network, timeout = meta["fields"], meta["network"], meta["timeout"]
    else:
        frozen = version(slug, int(version_ref))
        if frozen is None:
            raise ScriptError("no version %s of %r" % (version_ref, slug))
        fields, network, timeout = frozen["fields"], frozen["network"], frozen["timeout"]
        version_ref = int(version_ref)
    inputs = resolve_inputs(fields, raw_inputs)
    rid = _new_request_id(slug)
    now = _utcnow()
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    REQ_DIR.mkdir(parents=True, exist_ok=True)
    status = {"request_id": rid, "slug": slug, "version": version_ref,
              "trigger": trigger, "requested_by": by, "queued_at": now,
              "status": "queued", "network": network, "timeout": timeout,
              "inputs": shown_inputs(fields, inputs), "node": node}
    _write_json(STATUS_DIR / (rid + ".json"), status)
    req = {"request_id": rid, "slug": slug, "version": version_ref,
           "inputs": inputs, "requested_by": by, "trigger": trigger,
           "queued_at": now}
    _write_json(REQ_DIR / (rid + ".json"), req, mode=0o600)
    return status


def run_status(rid: str) -> dict | None:
    if not rid or not _RID_RE.match(rid):
        return None
    d = _read_json(STATUS_DIR / (rid + ".json"))
    return d or None


def recent_runs(slug: str | None = None, limit: int = 30) -> list[dict]:
    if not STATUS_DIR.is_dir():
        return []
    paths = sorted(STATUS_DIR.glob("*.json"), reverse=True)
    out = []
    for p in paths:
        if slug and ("-%s-" % slug) not in p.name:
            continue
        d = _read_json(p)
        if d and (not slug or d.get("slug") == slug):
            d.pop("output", None)
            d.pop("result", None)
            out.append(d)
        if len(out) >= limit:
            break
    return out
