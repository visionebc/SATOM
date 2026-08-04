"""Offline update packages — the app-side half (upload, preflight, enqueue).

The web worker NEVER applies a package. It stages the upload, tells the
operator what applying it would do, and drops a request for the privileged
runner. Every check made here is advisory: the runner re-verifies the
signature, the hashes and the version rules itself, as root, against a trust
store the worker cannot write. If the two ever disagree the runner wins, and
that is the point — this module runs in the process an attacker would already
have if they had anything at all.

What preflight is FOR: an update that cannot work should fail on a page that
explains why, not halfway through a privileged apply. Every check here answers
one question an operator would otherwise answer by reading a traceback.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
UPLOAD_DIR = APP_DIR / "data" / "update-uploads"
REQ_DIR = APP_DIR / "data" / "update-requests"
STATUS_DIR = APP_DIR / "data" / "update-status"
TRUST_DIR = os.environ.get("SATOM_TRUST_DIR", "/etc/satom/update-keys")

#: Refuse an upload larger than this before it can fill the disk. Generous
#: enough for code + every wheel (~80 MB today) with room to grow.
MAX_UPLOAD_BYTES = 400 * 1024 * 1024

#: Keep this many staged packages; the oldest are pruned on a new upload.
KEEP_UPLOADS = 5


def _load_update_package():
    """Load ``deploy/update_package.py`` BY PATH.

    Not an ``app.`` import: the same module is loaded by the root runner, which
    runs on the system interpreter with no venv and no ``app`` package. One
    file, three consumers (builder, worker, runner) — a second copy would be a
    second answer to "is this package trustworthy".
    """
    # Derived from this file's own location, NOT from FM_APP_DIR. That
    # variable names where the DATA lives and is settable at runtime; the
    # verifier is code and must be found beside the package loading it, or a
    # changed environment could silently swap which verifier is consulted.
    path = Path(__file__).resolve().parents[2] / "deploy" / "update_package.py"
    spec = importlib.util.spec_from_file_location("satom_update_package", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


up = _load_update_package()
PackageError = up.PackageError


# ---------------------------------------------------------------------------
# staging
# ---------------------------------------------------------------------------
def upload_dir() -> Path:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    return UPLOAD_DIR


def safe_name(filename: str) -> str:
    """A basename we are willing to store, or raise.

    Only the basename survives, and it must match the package pattern. The
    runner later joins this to the staging directory itself, so a name is the
    ONLY thing that crosses the privilege boundary — never a path.
    """
    base = os.path.basename((filename or "").strip().replace("\\", "/"))
    if not up.PKG_NAME_RE.match(base):
        raise PackageError(
            "%r is not an acceptable package name; expected something like "
            "satom-update-1.3.6.tar.gz (letters, digits, . _ - only)" % base)
    return base


def save_upload(stream, filename: str) -> dict:
    """Stream an upload into the staging directory.

    Written to a temporary name in the SAME directory and renamed on success,
    so a half-uploaded file is never visible under a real package name.
    """
    name = safe_name(filename)
    d = upload_dir()
    tmp = d / (".incoming-%s.tmp" % uuid.uuid4().hex[:10])
    total = 0
    try:
        with open(tmp, "wb") as fh:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise PackageError(
                        "upload exceeds the %d MB limit"
                        % (MAX_UPLOAD_BYTES // (1024 * 1024)))
                fh.write(chunk)
        if total == 0:
            raise PackageError("the uploaded file is empty")
        os.replace(tmp, d / name)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
    _prune_uploads(keep=KEEP_UPLOADS, protect=name)
    return {"name": name, "size": total}


def _prune_uploads(keep: int = KEEP_UPLOADS, protect: str = "") -> list:
    files = sorted((p for p in upload_dir().glob("*.tar.gz") if p.is_file()),
                   key=lambda p: p.stat().st_mtime, reverse=True)
    removed = []
    for p in files[keep:]:
        if p.name == protect:
            continue
        try:
            p.unlink()
            removed.append(p.name)
        except OSError:
            pass
    return removed


def list_uploads() -> list:
    out = []
    for p in sorted(upload_dir().glob("*.tar.gz"),
                    key=lambda p: p.stat().st_mtime, reverse=True):
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size,
                    "uploaded_at": datetime.utcfromtimestamp(st.st_mtime)
                                           .isoformat() + "Z"})
    return out


def delete_upload(name: str) -> None:
    p = upload_dir() / safe_name(name)
    if p.exists():
        p.unlink()
    sha = Path(str(p) + ".sha256")
    if sha.exists():
        sha.unlink()


# ---------------------------------------------------------------------------
# trust store (read-only view for the UI)
# ---------------------------------------------------------------------------
def trust_state() -> dict:
    """What this node will accept a package from.

    The operator needs to see this BEFORE uploading: "my package is refused"
    and "this node trusts nobody" look identical from the upload form.
    """
    problem = up.trust_store_problem(TRUST_DIR)
    keys = up.load_trust_store(TRUST_DIR)
    # The list is called "entries" and not "keys" ON PURPOSE. In Jinja,
    # ``trust.keys`` resolves to the dict's ``.keys`` METHOD before it resolves
    # the item, so a template iterating it gets a bound method and raises. The
    # name is the fix: a comment would not survive the next template.
    return {
        "dir": TRUST_DIR,
        "problem": problem,
        "usable": problem is None and bool(keys),
        "entries": [{"name": k["name"], "comment": k["comment"],
                     "fingerprint": k["fingerprint"]} for k in keys],
    }


# ---------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------
def _check(cid, label, status, detail):
    return {"id": cid, "label": label, "status": status, "detail": detail}


def _venv_python_tag() -> str:
    import sys
    return "cp%d%d" % sys.version_info[:2]


def _installed_versions() -> dict:
    import importlib.metadata as md
    out = {}
    for dist in md.distributions():
        try:
            name = dist.metadata["Name"]
            if name:
                out[name.lower().replace("_", "-")] = dist.version
        except Exception:
            continue
    return out


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")


def _parse_requirements(reqs) -> dict:
    out = {}
    for line in reqs or []:
        m = _REQ_RE.match(str(line))
        if m:
            out[m.group(1).lower().replace("_", "-")] = m.group(2)
    return out


def _wheel_index(pkg_dir: Path) -> dict:
    """{normalised distribution name: [versions]} from the wheel filenames."""
    idx = {}
    for w in (pkg_dir / "wheels").glob("*.whl"):
        parts = w.name.split("-")
        if len(parts) < 2:
            continue
        name = parts[0].lower().replace("_", "-")
        idx.setdefault(name, []).append(parts[1])
    return idx


def preflight(name: str) -> dict:
    """Everything applying this package would need, checked before applying it."""
    from ..version import app_version

    pkg_path = upload_dir() / safe_name(name)
    result = {
        "name": pkg_path.name,
        "checks": [],
        "manifest": {},
        "signed_by": None,
        "current_version": app_version(),
        "is_downgrade": False,
        "can_apply": False,
        "blocking": [],
    }
    if not pkg_path.is_file():
        result["checks"].append(_check("package", "Package file", "fail",
                                       "%s is not in the staging area" % pkg_path.name))
        result["blocking"] = ["package"]
        return result

    tmp = Path(tempfile.mkdtemp(prefix="satom-preflight-",
                                dir=str(upload_dir())))
    try:
        return _preflight_in(pkg_path, tmp, result)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _preflight_in(pkg_path: Path, tmp: Path, result: dict) -> dict:
    checks = result["checks"]

    # --- trust + signature -------------------------------------------------
    trust = trust_state()
    if trust["problem"]:
        checks.append(_check("trust", "Trust store", "fail", trust["problem"]))
    elif not trust["entries"]:
        checks.append(_check("trust", "Trust store", "fail",
                             "%s holds no public key, so no package can be "
                             "accepted. Install one with 'satom execute trust "
                             "add-key'." % trust["dir"]))
    else:
        checks.append(_check("trust", "Trust store", "ok",
                             "%d trusted key(s) in %s"
                             % (len(trust["entries"]), trust["dir"])))

    try:
        pkg_dir = up.extract_package(pkg_path, tmp)
    except Exception as exc:
        checks.append(_check("archive", "Archive", "fail", str(exc)))
        result["blocking"] = [c["id"] for c in checks if c["status"] == "fail"]
        return result
    checks.append(_check("archive", "Archive", "ok",
                         "extracted cleanly, no links or traversal"))

    try:
        verified = up.verify_package(pkg_dir, TRUST_DIR)
    except up.PackageError as exc:
        checks.append(_check("signature", "Signature & integrity", "fail", str(exc)))
        try:
            result["manifest"] = up.read_manifest(pkg_dir)
        except Exception:
            pass
        result["blocking"] = [c["id"] for c in checks if c["status"] == "fail"]
        if "signature" not in result["blocking"]:
            result["blocking"].append("signature")
        return result

    manifest = verified["manifest"]
    key = verified["key"]
    result["manifest"] = manifest
    result["signed_by"] = {"fingerprint": key["fingerprint"],
                           "comment": key["comment"], "name": key["name"]}
    checks.append(_check(
        "signature", "Signature & integrity", "ok",
        "signed by %s (%s); %d file(s) match the signed manifest"
        % (key["fingerprint"], key["comment"] or key["name"],
           len(manifest.get("files") or {}))))

    # --- version -----------------------------------------------------------
    cur = result["current_version"]
    new = str(manifest.get("version") or "")
    cmp_ = up.compare_versions(new, cur)
    if not up.VERSION_RE.match(new):
        checks.append(_check("version", "Version", "fail",
                             "%r is not a version this node can compare" % new))
    elif cmp_ > 0:
        checks.append(_check("version", "Version", "ok", "%s → %s" % (cur, new)))
    elif cmp_ == 0:
        checks.append(_check("version", "Version", "warn",
                             "already running %s — applying reinstalls the same "
                             "version" % cur))
    else:
        result["is_downgrade"] = True
        checks.append(_check(
            "version", "Version", "warn",
            "DOWNGRADE %s → %s. Allowed, but database migrations are NOT "
            "reversed: a schema created by %s stays in place. Take the database "
            "backup this apply offers, and be ready to restore it."
            % (cur, new, cur)))

    min_from = str(manifest.get("min_from_version") or "")
    if min_from and up.compare_versions(cur, min_from) < 0:
        checks.append(_check("min_from", "Upgrade path", "fail",
                             "this package requires %s or newer to apply; this "
                             "node runs %s" % (min_from, cur)))
    else:
        checks.append(_check("min_from", "Upgrade path", "ok",
                             "applies from %s" % (min_from or "any version")))

    # --- python ------------------------------------------------------------
    tags = list(manifest.get("python_tags") or [])
    mine = _venv_python_tag()
    if "*" in tags:
        checks.append(_check("python", "Python", "ok",
                             "all wheels are pure Python; this node runs %s" % mine))
    elif mine in tags:
        checks.append(_check("python", "Python", "ok",
                             "%s matches the package (%s)" % (mine, ", ".join(tags))))
    else:
        checks.append(_check(
            "python", "Python", "fail",
            "this node's venv is %s but the package carries wheels for %s. "
            "Applying it would fail inside pip with no network to fall back on."
            % (mine, ", ".join(tags) or "an unknown interpreter")))

    # --- dependencies ------------------------------------------------------
    wanted = _parse_requirements(manifest.get("requirements"))
    have = _installed_versions()
    wheels = _wheel_index(pkg_dir)
    missing, changing = [], []
    for dist, ver in sorted(wanted.items()):
        if have.get(dist) == ver:
            continue
        changing.append("%s %s→%s" % (dist, have.get(dist) or "absent", ver))
        if ver not in wheels.get(dist, []):
            missing.append("%s==%s" % (dist, ver))
    if missing:
        checks.append(_check(
            "deps", "Dependencies", "fail",
            "%d pinned dependency change(s) have no wheel in the package: %s. "
            "An offline node cannot download them."
            % (len(missing), ", ".join(missing[:6]))))
    elif changing:
        checks.append(_check("deps", "Dependencies", "ok",
                             "%d change(s), all present as wheels: %s"
                             % (len(changing), ", ".join(changing[:6]))))
    else:
        checks.append(_check("deps", "Dependencies", "ok",
                             "no pinned dependency changes"))

    # --- disk --------------------------------------------------------------
    size = pkg_path.stat().st_size
    free = shutil.disk_usage(str(APP_DIR)).free
    need = size * 3
    if free < need:
        checks.append(_check("disk", "Disk space", "fail",
                             "%s free, apply needs about %s (package, extraction "
                             "and a database backup)"
                             % (_h(free), _h(need))))
    elif free < need * 2:
        checks.append(_check("disk", "Disk space", "warn",
                             "%s free — tight but workable" % _h(free)))
    else:
        checks.append(_check("disk", "Disk space", "ok", "%s free" % _h(free)))

    # --- node role ---------------------------------------------------------
    from . import self_update as su
    role = su.node_role()
    if role == "standby":
        checks.append(_check(
            "node", "This node", "warn",
            "STANDBY. Apply here first — that is the staged order — but stage "
            "the upload on the PRIMARY: data/ is replicated to this node with "
            "rsync --delete, so a file uploaded here is removed on the next "
            "sync."))
    else:
        checks.append(_check("node", "This node", "ok",
                             "%s. The apply is node-local: each node applies "
                             "its own copy." % role))

    result["blocking"] = [c["id"] for c in checks if c["status"] == "fail"]
    result["can_apply"] = not result["blocking"]
    return result


def _h(n) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0
    return str(n)


# ---------------------------------------------------------------------------
# enqueue
# ---------------------------------------------------------------------------
def request_package_apply(name: str, by: str, *, allow_downgrade: bool = False,
                          do_backup: bool = True) -> str:
    """Enqueue an offline-package apply for the privileged runner.

    Only a validated BASENAME crosses to the runner. The runner resolves it
    against its own staging directory, so nothing in this request can direct it
    at a path of the caller's choosing.
    """
    from . import self_update as su

    pkg = safe_name(name)
    if not (upload_dir() / pkg).is_file():
        raise PackageError("%s is not staged on this node" % pkg)

    REQ_DIR.mkdir(parents=True, exist_ok=True)
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    req = {
        "id": uid,
        "kind": "package",
        "package": pkg,
        "allow_downgrade": bool(allow_downgrade),
        "do_backup": bool(do_backup),
        "requested_by": by,
        "requested_at": datetime.utcnow().isoformat() + "Z",
        "node": su.this_node_name(),
        "role": su.node_role(),
        "origin": "update-package",
    }
    (STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": "package",
        "package": pkg, "target": pkg, "requested_by": by,
        "node": req["node"], "role": req["role"], "origin": "update-package",
        "updated_at": datetime.utcnow().isoformat() + "Z"}))
    tmp = REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(REQ_DIR / (uid + ".json"))
    return uid
