"""Signed offline update packages — format, trust store and verification.

THIS MODULE IS THE TRUST BOUNDARY. Read the three rules before changing it.

1. **Standard library only.** No ``cryptography``, no ``flask``, no ``app``.
   The whole point of an offline update package is to repair a node whose venv
   or app tree is broken; a verifier that needs the venv cannot run exactly when
   it is needed. Ed25519 verification is therefore implemented here in pure
   Python (RFC 8032) on top of ``hashlib.sha512``.
   ``tests/test_update_package.py`` enforces this by AST.

2. **The public key is not a secret and the private key is not ours to hold.**
   A node trusts whatever public keys ``root`` placed in the trust store
   (``/etc/satom/update-keys``). The vendor key ships in the repo because a
   public key is publishable by definition — it can only VERIFY. Operators and
   forks add their own keys and sign their own packages; nothing in the product
   contains a secret.

3. **The trust store must live outside the app tree and be root-owned.**
   ``/opt/satom`` is owned by the service account. A trust store the web worker
   can write is not a trust store: the worker would add its own key and sign its
   own package. ``trust_store_problem()`` refuses in that case and the runner
   aborts. Same reasoning as the root-owned copy of the operator CLI.

Package layout (a gzip tarball with exactly one top-level directory)::

    satom-update-<version>/
        manifest.json      the signed document
        manifest.sig       base64 Ed25519 signature over manifest.json's BYTES
        app.tar.gz         the application tree at that revision
        wheels/*.whl       every pinned dependency, so apply needs no network

The signature covers the manifest's exact bytes (no canonicalisation, so there
is no re-serialisation ambiguity to exploit) and the manifest carries a sha256
for every other file, so signing one small document covers the whole package.

Format /2 (``SCHEMA_V2``) adds two smaller shapes. The outer file stays a gzip
tarball named ``satom-update-*.tar.gz``; what changes is the application
payload, named by the manifest's ``app_archive``:

* **full /2**: ``app.tar.xz``, the complete tree, xz-compressed.
* **delta /2**: ``app-delta.tar.xz``, only the files that differ from ONE
  earlier release (``from_version``). Every other file is read from the node's
  own tree and must hash to the value the signed manifest names
  (``app_tree``), so a delta can only produce the exact tree the full package
  would have. A node whose tree differs is refused before anything changes.
  Tarballs inside the tree whose members barely change (the API library pack)
  travel as a recipe (``app_rebuild``): the members that changed, plus the
  sha256 of every member taken from the copy the node already holds.

A runner that only speaks /1 refuses a /2 package at the schema check, before
anything is touched. See :func:`materialize_app`.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

SCHEMA = "satom.update-package/1"
SCHEMA_V2 = "satom.update-package/2"
#: Every schema this verifier applies. The release builder reads this tuple out
#: of an older release's payload to decide whether that release can take a /2
#: package -- keep the literal on one line.
SCHEMAS = ("satom.update-package/1", "satom.update-package/2")
PRODUCT = "satom"
KEY_TYPE = "satom-ed25519"
DEFAULT_TRUST_DIR = "/etc/satom/update-keys"

# A package filename we are willing to resolve. The runner takes only a
# BASENAME from the request and joins it to a fixed staging directory, so a
# forged request cannot point the runner at an arbitrary path.
PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.tar\.gz$")
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*([A-Za-z0-9.+_-]*)$")

# Ceiling on what one archive may unpack to (sum of the members' sizes).
# extract_package() runs as root BEFORE the signature is checked -- it has to,
# the signature is inside -- so an unsigned upload must not be able to fill
# the disk with a small, highly compressible tarball.
MAX_UNPACKED_BYTES = 2 * 1024 ** 3


class PackageError(Exception):
    """Any refusal to trust or read a package."""


# ---------------------------------------------------------------------------
# Ed25519 (RFC 8032) — pure Python, hashlib only.
# ---------------------------------------------------------------------------
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, _P - 2, _P)


_D = -121665 * _inv(121666) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
_G = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    out = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            out = _add(out, p)
        p = _add(p, p)
        s >>= 1
    return out


def _equal(p, q):
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    return (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(p):
    zi = _inv(p[2])
    x = p[0] * zi % _P
    y = p[1] * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _sha512_modq(b):
    return int.from_bytes(_sha512(b), "little") % _Q


def ed25519_public_from_seed(seed: bytes) -> bytes:
    """32-byte public key for a 32-byte private seed."""
    if len(seed) != 32:
        raise PackageError("an Ed25519 seed is 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(_mul(a, _G))


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    """Sign with a raw 32-byte seed. Present so tests and an emergency
    recovery can sign without any third-party package; the release signer
    (``deploy/sign_update_package.py``) keeps the key encrypted at rest."""
    if len(seed) != 32:
        raise PackageError("an Ed25519 seed is 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _compress(_mul(a, _G))
    r = _sha512_modq(prefix + msg)
    rs = _compress(_mul(r, _G))
    k = _sha512_modq(rs + pub + msg)
    s = (r + k * a) % _Q
    return rs + int.to_bytes(s, 32, "little")


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Verify a detached Ed25519 signature. Never raises on malformed input —
    a bad key or signature is simply not a valid signature."""
    try:
        if len(pub) != 32 or len(sig) != 64:
            return False
        a = _decompress(pub)
        if a is None:
            return False
        rs = sig[:32]
        s = int.from_bytes(sig[32:], "little")
        if s >= _Q:
            return False
        r = _decompress(rs)
        if r is None:
            return False
        k = _sha512_modq(rs + pub + msg)
        return _equal(_mul(s, _G), _add(r, _mul(k, a)))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# trust store
# ---------------------------------------------------------------------------
def format_public_key(pub: bytes, comment: str = "") -> str:
    """One line, deliberately shaped like ``authorized_keys``."""
    return "%s %s %s\n" % (KEY_TYPE, base64.b64encode(pub).decode("ascii"),
                           (comment or "").strip())


def parse_public_key(text: str):
    """(raw 32-byte key, comment) from a key file's text, or raise."""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2 or parts[0] != KEY_TYPE:
            raise PackageError("not a %s public key line" % KEY_TYPE)
        try:
            raw = base64.b64decode(parts[1], validate=True)
        except Exception:
            raise PackageError("public key is not valid base64")
        if len(raw) != 32:
            raise PackageError("an Ed25519 public key is 32 bytes, got %d" % len(raw))
        return raw, (parts[2].strip() if len(parts) > 2 else "")
    raise PackageError("no public key found in file")


def _one_path_problem(p: Path):
    try:
        info = p.lstat()
    except OSError as exc:
        return "cannot stat %s: %s" % (p, exc)
    if stat.S_ISLNK(info.st_mode):
        return "%s is a symlink; this path must not be redirectable" % p
    if info.st_uid != 0:
        return "%s is owned by uid %d, not root" % (p, info.st_uid)
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "%s is group/world writable (mode %o)" % (p, info.st_mode & 0o777)
    return None


def root_owned_problem(path, children_glob=None):
    """Why ``path`` is not safe for root to rely on, or ``None``.

    Walks the whole parent chain, because a root-owned file inside a directory
    someone else can write is a file someone else can replace. Used for the two
    places where root reads something it must be able to trust: the update
    trust store, and the runner's own code.
    """
    d = Path(path)
    if not d.exists():
        return "%s does not exist" % d
    for p in [d] + list(d.parents):
        problem = _one_path_problem(p)
        if problem:
            return problem
        if p == Path(p.root):
            break
    if children_glob and d.is_dir():
        for f in sorted(d.glob(children_glob)):
            problem = _one_path_problem(f)
            if problem:
                return problem
    return None


def trust_store_problem(trust_dir=DEFAULT_TRUST_DIR):
    """Why this trust store must not be trusted, or ``None`` when it is sound.

    A trust store any non-root account can write is equivalent to no signature
    checking at all: whoever can add a key can mint packages this node accepts.
    The runner treats a non-None result as fatal.
    """
    d = Path(trust_dir)
    if not d.is_dir():
        return "trust store %s does not exist" % d
    return root_owned_problem(d, "*.pub")


def load_trust_store(trust_dir=DEFAULT_TRUST_DIR) -> list:
    """[{name, key, comment}] for every readable ``*.pub``. Unreadable or
    malformed files are skipped rather than fatal: one corrupt file must not
    disable every other trusted key."""
    out = []
    d = Path(trust_dir)
    if not d.is_dir():
        return out
    for f in sorted(d.glob("*.pub")):
        try:
            raw, comment = parse_public_key(f.read_text())
        except Exception:
            continue
        out.append({"name": f.name, "key": raw, "comment": comment,
                    "fingerprint": key_fingerprint(raw)})
    return out


def key_fingerprint(pub: bytes) -> str:
    """SHA256:<base64> — the same shape ``ssh-keygen -l`` prints, so an
    operator can compare it against a published value by eye."""
    digest = hashlib.sha256(pub).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# manifest + package verification
# ---------------------------------------------------------------------------
def sha256_file(path, chunk=1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _safe_members(tf: tarfile.TarFile, root: str):
    """Yield members that stay inside ``root/`` and are plain files or dirs.

    Rejects absolute paths, ``..`` traversal, symlinks, hardlinks and device
    nodes. A link is rejected rather than resolved because a link that points
    inside the tree today can point outside it after a later member is
    extracted -- the ordering is attacker-chosen.
    """
    prefix = root.rstrip("/") + "/"
    for m in tf.getmembers():
        name = m.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise PackageError("unsafe path in archive: %s" % name)
        if not (name == root or name.startswith(prefix)):
            raise PackageError("archive member outside %s: %s" % (root, name))
        if m.issym() or m.islnk():
            raise PackageError("archive contains a link (%s); not allowed" % name)
        if m.ischr() or m.isblk() or m.isfifo() or m.isdev():
            raise PackageError("archive contains a device/fifo (%s)" % name)
        if not (m.isfile() or m.isdir()):
            raise PackageError("archive member %s has unsupported type" % name)
        m.mode = (m.mode & 0o755) | 0o600 if m.isfile() else 0o755
        yield m


def archive_root(path) -> str:
    """The single top-level directory of the package tarball."""
    with tarfile.open(path, "r:*") as tf:
        roots = {Path(m.name).parts[0] for m in tf.getmembers() if m.name.strip()}
    if len(roots) != 1:
        raise PackageError("package must contain exactly one top-level "
                           "directory, found %d" % len(roots))
    return roots.pop()


def _check_unpacked_size(members, what):
    total = sum(max(m.size, 0) for m in members if m.isfile())
    if total > MAX_UNPACKED_BYTES:
        raise PackageError("%s unpacks to %d bytes, over the %d-byte limit"
                           % (what, total, MAX_UNPACKED_BYTES))


def _refuse_links_on_disk(dest: Path, members):
    """Refuse when any EXISTING path a member lands on (or under) is a link.

    The member checks only look at the archive. Root extracting over a tree
    another account can write would follow a symlink that account planted
    there (``app -> /etc``) and write wherever it points. The ``data`` filter
    catches that on Pythons that have it; this check is what the nodes on
    3.11.2 (no filter) get, and it runs on every Python.
    """
    for m in members:
        cur = dest
        for part in Path(m.name).parts:
            cur = cur / part
            try:
                info = os.lstat(cur)
            except FileNotFoundError:
                break
            except OSError as exc:
                raise PackageError("cannot inspect %s: %s" % (cur, exc))
            if stat.S_ISLNK(info.st_mode):
                raise PackageError("refusing to extract %s: %s on disk is a "
                                   "symlink" % (m.name, cur))


def _extractall(tf, dest, members):
    if hasattr(tarfile, "data_filter"):
        tf.extractall(dest, members=members, filter="data")
    else:
        tf.extractall(dest, members=members)


# ---------------------------------------------------------------------------
# Root touching the service account's directories
# ---------------------------------------------------------------------------
# data/ and everything below it belong to the service account, which can swap
# any entry for a symlink at any moment -- including between a check and the
# write that follows it. So root never writes, chmods or chowns there BY PATH:
# every directory component is opened relative to its parent with O_NOFOLLOW,
# a new file is created O_EXCL|O_NOFOLLOW under a random name, its mode and
# owner are set on the open DESCRIPTOR, and an atomic rename replaces the
# final NAME (a link planted there is replaced, never followed). The runner,
# the operator CLI and every other root writer share these functions.

def open_dir_nofollow(base, parts, ids=None) -> int:
    """O_DIRECTORY fd of ``base/<parts...>``. ``base`` is opened normally (it is
    the app root, whose parent root owns); every component below it with
    O_NOFOLLOW, created 0750 and handed to ``ids`` = (uid, gid) when missing."""
    fd = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            if part in ("", ".", "..") or "/" in part:
                raise PackageError("refusing the path component %r" % (part,))
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            try:
                nfd = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o750, dir_fd=fd)
                nfd = os.open(part, flags, dir_fd=fd)
                if ids:
                    os.fchown(nfd, ids[0], ids[1])
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


_PLAIN_NAME_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,200}$")


def write_nofollow(dir_fd, name, chunks, mode=0o640, ids=None) -> int:
    """Write ``chunks`` (an iterable of bytes) to ``name`` in ``dir_fd`` without
    following any link; returns the byte count. The file appears under
    ``name`` only once it is complete."""
    if not isinstance(name, str) or not _PLAIN_NAME_RE.fullmatch(name):
        raise PackageError("refusing to write a file named %r" % (name,))
    tmp = ".%s.%s.tmp" % (name, os.urandom(6).hex())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                 dir_fd=dir_fd)
    total = 0
    try:
        with os.fdopen(fd, "wb") as fh:
            for chunk in chunks:
                fh.write(chunk)
                total += len(chunk)
            fh.flush()
            os.fchmod(fh.fileno(), mode)
            if ids:
                os.fchown(fh.fileno(), ids[0], ids[1])
        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    return total


def open_file_nofollow(dir_fd, name, owner_uid=None):
    """A binary file object for reading ``name`` in ``dir_fd``: a regular file,
    reached without following a link, owned by ``owner_uid`` when given."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PackageError("%s is not a regular file" % name)
        if owner_uid is not None and st.st_uid != owner_uid:
            raise PackageError("%s is owned by uid %d, expected %d"
                               % (name, st.st_uid, owner_uid))
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_small_nofollow(path, limit=64 * 1024):
    """Bytes of a small regular file reached WITHOUT following a link in its
    last component, or None. For files root reads in the service account's
    tree (VERSION, status JSON): a link there would otherwise make root read
    any file and repeat its content where that account can see it."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            return None
        data = fh.read(limit + 1)
    return data if len(data) <= limit else None


def read_version_file(path) -> str:
    """The VERSION file's version, or "" when it is not a plain version."""
    raw = read_small_nofollow(path, 128)
    text = (raw or b"").decode("ascii", "replace").strip()
    return text if VERSION_RE.match(text) and len(text) <= 64 else ""


def file_chunks(fh, size=1 << 20):
    """Iterate a binary file in ``size`` blocks."""
    return iter(lambda: fh.read(size), b"")


def extract_package(path, dest) -> Path:
    """Extract the package tarball under ``dest``; return the package dir."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = archive_root(path)
    with tarfile.open(path, "r:*") as tf:
        members = list(_safe_members(tf, root))
        _check_unpacked_size(members, "package")
        _refuse_links_on_disk(dest, members)
        _extractall(tf, dest, members)
    return dest / root


def extract_app_tree(app_tar, dest) -> list:
    """Extract ``app.tar.gz`` over the application tree.

    Returns the list of FILE paths it wrote, relative to ``dest``. The caller
    needs that list for two things it cannot do without it: staging exactly
    what this package changed (rather than sweeping up whatever else happened
    to be uncommitted in the tree) and removing files the new revision no
    longer has -- laying a tarball over a checkout adds and overwrites, but it
    never deletes.

    The application tarball is flat (no wrapper directory) because it is laid
    directly over an existing checkout, so it gets its own guard rather than
    reusing ``_safe_members``.
    """
    dest = Path(dest)
    with tarfile.open(app_tar, "r:*") as tf:
        members, written = _app_tree_members(tf)
        _refuse_links_on_disk(dest, members)
        _extractall(tf, dest, members)
    return written


def _app_tree_members(tf):
    members, written = [], []
    for m in tf.getmembers():
        name = m.name
        if name.startswith("/") or ".." in Path(name).parts:
            raise PackageError("unsafe path in app tree: %s" % name)
        if m.issym() or m.islnk():
            raise PackageError("app tree contains a link (%s); not allowed" % name)
        if m.ischr() or m.isblk() or m.isfifo() or m.isdev():
            raise PackageError("app tree contains a device/fifo (%s)" % name)
        if not (m.isfile() or m.isdir()):
            raise PackageError("app tree member %s has unsupported type" % name)
        members.append(m)
        if m.isfile():
            # Normalised (``./x`` -> ``x``): the caller compares this list
            # with ``git ls-files``, and a spelling difference would make
            # every tracked file look dropped.
            written.append(str(PurePosixPath(name)))
    _check_unpacked_size(members, "app tree")
    return members, written


def app_tree_files(app_tar) -> list:
    """Validate ``app.tar.gz`` exactly as :func:`extract_app_tree` does and
    return the FILE paths it holds, without extracting anything. The runner
    uses it when the tree is written by the service account, not by root."""
    with tarfile.open(app_tar, "r:*") as tf:
        return _app_tree_members(tf)[1]


def read_manifest(pkg_dir) -> dict:
    p = Path(pkg_dir) / "manifest.json"
    if not p.exists():
        raise PackageError("manifest.json is missing from the package")
    try:
        data = json.loads(p.read_bytes().decode("utf-8"))
    except Exception as exc:
        raise PackageError("manifest.json is not valid JSON: %s" % exc)
    if not isinstance(data, dict):
        raise PackageError("manifest.json must be a JSON object")
    return data


def verify_signature(pkg_dir, trust_dir=DEFAULT_TRUST_DIR) -> dict:
    """Verify ``manifest.sig`` over the exact bytes of ``manifest.json``.

    Returns the trusted key that matched. Raises ``PackageError`` otherwise —
    an unsigned package and a badly-signed one are the same refusal.

    This is the UPDATE verifier: it reads ``trust_dir`` and nothing else. The
    API-pack keys (:data:`PACK_KEY_DIR`) are a separate trust domain and never
    reach this function; a pack key cannot sign an update.
    """
    return verify_signature_keys(pkg_dir, load_trust_store(trust_dir), str(trust_dir))


#: Trust domains (one key, one use). ``update`` is the store above; the pack
#: lanes are verified only with their own keys (``app/services/api_pack.py``).
PACK_LANES = ("api_pack", "knowledge")
TRUST_PURPOSES = ("update",) + PACK_LANES
#: Operator-managed pack keys, one sub-directory per lane. The keys shipped
#: with the code live in ``deploy/pack-keys/<lane>/`` and are trusted because
#: the code tree itself arrived release-signed.
PACK_KEY_DIR = "/etc/satom/pack-keys"


def load_key_dirs(dirs) -> list:
    """Every usable key of several key directories, de-duplicated by
    fingerprint (first directory wins). Each entry also names its ``dir``."""
    out, seen = [], set()
    for d in dirs:
        for k in load_trust_store(d):
            if k["fingerprint"] in seen:
                continue
            seen.add(k["fingerprint"])
            out.append(dict(k, dir=str(d)))
    return out


def verify_signature_keys(pkg_dir, keys, store_label: str) -> dict:
    """``manifest.sig`` checked against an explicit key list (see
    :func:`verify_signature`). ``store_label`` names the key set in errors."""
    pkg_dir = Path(pkg_dir)
    mpath = pkg_dir / "manifest.json"
    spath = pkg_dir / "manifest.sig"
    if not mpath.exists():
        raise PackageError("manifest.json is missing from the package")
    if not spath.exists():
        raise PackageError("manifest.sig is missing — the package is unsigned")
    try:
        sig = base64.b64decode(spath.read_text().strip(), validate=True)
    except Exception:
        raise PackageError("manifest.sig is not valid base64")
    msg = mpath.read_bytes()
    if not keys:
        raise PackageError("the trust store %s holds no usable public key"
                           % store_label)
    for k in keys:
        if ed25519_verify(k["key"], msg, sig):
            return k
    raise PackageError("no key in the trust store signed this package "
                       "(%d key(s) tried)" % len(keys))


def verify_contents(pkg_dir, manifest) -> list:
    """Check every file the manifest claims. Returns the list of problems."""
    pkg_dir = Path(pkg_dir)
    files = manifest.get("files")
    problems = []
    if not isinstance(files, dict) or not files:
        return ["manifest lists no files"]
    for rel, meta in sorted(files.items()):
        if rel.startswith("/") or ".." in Path(rel).parts:
            problems.append("manifest names an unsafe path: %s" % rel)
            continue
        p = pkg_dir / rel
        if not p.is_file():
            problems.append("missing from package: %s" % rel)
            continue
        want = (meta or {}).get("sha256", "")
        got = sha256_file(p)
        if got != want:
            problems.append("sha256 mismatch: %s" % rel)
    listed = set(files)
    for p in sorted(pkg_dir.rglob("*")):
        if not p.is_file():
            continue
        rel = str(p.relative_to(pkg_dir))
        if rel in ("manifest.json", "manifest.sig") or rel in listed:
            continue
        problems.append("unlisted extra file in package: %s" % rel)
    return problems


def verify_package(pkg_dir, trust_dir=DEFAULT_TRUST_DIR) -> dict:
    """Full verification: trust store sanity, signature, then every hash.

    Order matters. The store is checked before the signature (a writable store
    makes any signature meaningless) and the signature before the hashes (the
    hashes are only trustworthy because the manifest is signed).
    """
    problem = trust_store_problem(trust_dir)
    if problem:
        raise PackageError("trust store is not safe to use: %s" % problem)
    key = verify_signature(pkg_dir, trust_dir)
    manifest = read_manifest(pkg_dir)
    if manifest.get("schema") not in SCHEMAS:
        raise PackageError("unsupported package schema %r (this node speaks %s)"
                           % (manifest.get("schema"), ", ".join(SCHEMAS)))
    if manifest.get("product") != PRODUCT:
        raise PackageError("package is for product %r, not %s"
                           % (manifest.get("product"), PRODUCT))
    problems = verify_contents(pkg_dir, manifest)
    if problems:
        raise PackageError("package contents do not match the signed "
                           "manifest: %s" % "; ".join(problems[:5]))
    if manifest.get("schema") == SCHEMA_V2:
        check_v2_manifest(manifest)
    return {"manifest": manifest, "key": key}


# ---------------------------------------------------------------------------
# Format /2: xz payload, per-file tree map, delta packages
# ---------------------------------------------------------------------------
FULL_ARCHIVES = ("app.tar.gz", "app.tar.xz")
DELTA_ARCHIVE = "app-delta.tar.xz"
KIND_FULL, KIND_DELTA = "full", "delta"
#: Inside a delta archive, the changed members of a rebuilt tarball live under
#: ``REBUILD_PREFIX + <tree path> + "/" + <member name>``.
REBUILD_PREFIX = ".satom-rebuild/"
_SHA_HEX = re.compile(r"^[0-9a-f]{64}$")
#: One tree file read back from the node: nothing in a SATOM tree is near this.
MAX_TREE_FILE_BYTES = 512 * 1024 ** 2
DELTA_MISMATCH = ("this node's application tree is not the one %s shipped: "
                  "%d file(s) differ or are missing (%s). Nothing was changed. "
                  "Apply the full package %s instead")


def _safe_rel(rel) -> bool:
    if not isinstance(rel, str) or not rel or rel.startswith("/") or "\\" in rel:
        return False
    parts = PurePosixPath(rel).parts
    return bool(parts) and ".." not in parts and "." not in parts \
        and str(PurePosixPath(rel)) == rel


def full_package_name(version) -> str:
    return "satom-update-%s.tar.gz" % version


def delta_package_name(version, from_version) -> str:
    return "satom-update-%s-from-%s.tar.gz" % (version, from_version)


def package_kind(manifest) -> str:
    """``full`` or ``delta``. Every /1 package is full."""
    if manifest.get("schema") == SCHEMA_V2 and manifest.get("package_kind") == KIND_DELTA:
        return KIND_DELTA
    return KIND_FULL


def tree_map(manifest) -> dict:
    """``app_tree`` validated: {path: (sha256, mode, size)}."""
    raw = manifest.get("app_tree")
    if not isinstance(raw, dict) or not raw:
        raise PackageError("a /2 manifest must list the complete application tree")
    out = {}
    for rel, meta in raw.items():
        if not _safe_rel(rel):
            raise PackageError("app_tree names an unsafe path: %r" % (rel,))
        if not (isinstance(meta, list) and len(meta) == 3
                and isinstance(meta[0], str) and _SHA_HEX.match(meta[0])
                and isinstance(meta[1], int) and 0 <= meta[1] <= 0o7777
                and isinstance(meta[2], int) and 0 <= meta[2] <= MAX_TREE_FILE_BYTES):
            raise PackageError("app_tree entry for %s is malformed" % rel)
        out[rel] = (meta[0], meta[1], meta[2])
    return out


def _rebuild_map(manifest, tree) -> dict:
    raw = manifest.get("app_rebuild") or {}
    if not isinstance(raw, dict):
        raise PackageError("app_rebuild must be an object")
    out = {}
    for rel, rec in raw.items():
        if rel not in tree:
            raise PackageError("app_rebuild names %s, which is not in the tree" % rel)
        if not isinstance(rec, dict) or not _safe_rel(rec.get("base")):
            raise PackageError("app_rebuild entry for %s has no safe base" % rel)
        members = rec.get("members")
        if not isinstance(members, list) or not members:
            raise PackageError("app_rebuild entry for %s lists no members" % rel)
        seen = set()
        for m in members:
            if not (isinstance(m, list) and len(m) == 5 and _safe_rel(m[0])
                    and (m[1] is None or (isinstance(m[1], str) and _SHA_HEX.match(m[1])))
                    and isinstance(m[2], int) and 0 <= m[2] <= MAX_TREE_FILE_BYTES
                    and isinstance(m[3], int) and 0 <= m[3] <= 0o7777
                    and isinstance(m[4], int) and m[4] >= 0):
                raise PackageError("app_rebuild member of %s is malformed" % rel)
            if m[0] in seen:
                raise PackageError("app_rebuild lists %s twice in %s" % (m[0], rel))
            seen.add(m[0])
        shipped = rec.get("shipped") or []
        if not isinstance(shipped, list) or not set(shipped) <= seen:
            raise PackageError("app_rebuild entry for %s ships members it does not list"
                               % rel)
        roots = rec.get("roots") or ["", ""]
        if not (isinstance(roots, list) and len(roots) == 2
                and all(r == "" or _safe_rel(r) for r in roots)):
            raise PackageError("app_rebuild entry for %s has malformed roots" % rel)
        out[rel] = {"base": rec["base"], "members": members, "shipped": list(shipped),
                    "roots": roots}
    return out


def check_v2_manifest(manifest) -> None:
    """Structural rules of a /2 manifest, checked right after the signature."""
    kind = manifest.get("package_kind")
    archive = manifest.get("app_archive")
    files = manifest.get("files") or {}
    if kind == KIND_FULL:
        if archive not in FULL_ARCHIVES:
            raise PackageError("a full /2 package names no usable app archive")
    elif kind == KIND_DELTA:
        if archive != DELTA_ARCHIVE:
            raise PackageError("a delta package must carry %s" % DELTA_ARCHIVE)
        if not VERSION_RE.match(str(manifest.get("from_version") or "")):
            raise PackageError("a delta package must name the version it applies to")
        shipped = manifest.get("app_delta_files")
        if not isinstance(shipped, list) or not all(_safe_rel(p) for p in shipped):
            raise PackageError("a delta package must list the files it carries")
    else:
        raise PackageError("unknown package kind %r" % (kind,))
    if archive not in files:
        raise PackageError("%s is not among the package's signed files" % archive)
    tree = tree_map(manifest)
    if kind == KIND_DELTA:
        rebuild = _rebuild_map(manifest, tree)
        for p in manifest["app_delta_files"]:
            if p not in tree or p in rebuild:
                raise PackageError("delta file %s is not a plain file of the tree" % p)


def needs_lzma(manifest) -> bool:
    return str(manifest.get("app_archive") or "").endswith(".xz")


def lzma_problem(manifest):
    """Why this Python cannot read the package's payload, or None."""
    if not needs_lzma(manifest):
        return None
    try:
        import lzma  # noqa: F401  -- optional in a CPython build
    except ImportError:
        return ("this node's Python (%s) was built without the lzma module, so it "
                "cannot read %s; apply the full .tar.gz package of an earlier "
                "release, or install the distribution's lzma support"
                % (sys.version.split()[0], manifest.get("app_archive")))
    return None


def _open_dir_ro(base, parts) -> int:
    """O_DIRECTORY fd of ``base/<parts>``, every component below ``base`` opened
    O_NOFOLLOW. Unlike :func:`open_dir_nofollow` it never creates anything."""
    fd = os.open(str(base), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            if part in ("", ".", "..") or "/" in part:
                raise PackageError("refusing the path component %r" % (part,))
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_tree_file(app_dir, rel, limit=MAX_TREE_FILE_BYTES):
    """Bytes of the regular file ``app_dir/rel``, reached without following any
    link and never through a FIFO or device, or None. Root reads the service
    account's tree with this; whatever it returns is only used after its
    sha256 matched the signed manifest."""
    if not _safe_rel(rel):
        return None
    parts = PurePosixPath(rel).parts
    try:
        dfd = _open_dir_ro(app_dir, parts[:-1])
    except (OSError, PackageError):
        return None
    try:
        with open_file_nofollow(dfd, parts[-1]) as fh:
            data = fh.read(limit + 1)
    except (OSError, PackageError):
        return None
    finally:
        os.close(dfd)
    return data if len(data) <= limit else None


def _sha(data) -> str:
    return hashlib.sha256(data).hexdigest()


def _plain_info(name, mode, size, mtime=0, isdir=False):
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE if isdir else tarfile.REGTYPE
    ti.mode = mode
    ti.size = 0 if isdir else size
    ti.mtime = mtime
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    return ti


def base_member_name(recipe, name) -> str:
    """The name ``name`` has in the BASE tarball: a pack's top directory carries
    its version (``satom-apipack-4.11.2/`` -> ``satom-apipack-4.11.3/``), so
    ``roots`` = [base root, target root] maps one onto the other."""
    broot, troot = (recipe.get("roots") or ["", ""])
    if troot and (name == troot or name.startswith(troot + "/")):
        return broot + name[len(troot):]
    return name


def rebuild_tarball(recipe, base_bytes, extra) -> bytes:
    """A .tar.gz whose members are ``recipe["members"]``, in that order.

    A member's bytes come from ``extra`` (the delta's copy) when present, else
    from the tarball ``base_bytes`` the node already holds; either way they
    must hash to the recipe's sha256. The rebuilt file's own bytes are not
    pinned (gzip output differs between zlib builds): its integrity is that of
    every member, and the API pack verifies its own signature on import."""
    have = {}
    if base_bytes is not None:
        try:
            with tarfile.open(fileobj=io.BytesIO(base_bytes), mode="r:*") as bt:
                for m in bt.getmembers():
                    if m.isfile():
                        have[str(PurePosixPath(m.name))] = m
                out = io.BytesIO()
                _write_rebuilt(out, recipe, extra,
                               lambda n: _member_bytes(bt, have, base_member_name(recipe, n)))
                return out.getvalue()
        except tarfile.TarError as exc:
            raise PackageError("cannot read %s: %s" % (recipe["base"], exc))
    out = io.BytesIO()
    _write_rebuilt(out, recipe, extra, lambda n: None)
    return out.getvalue()


def _member_bytes(bt, have, name):
    m = have.get(name)
    if m is None or m.size > MAX_TREE_FILE_BYTES:
        return None
    fh = bt.extractfile(m)
    return fh.read() if fh is not None else None


def _write_rebuilt(out, recipe, extra, from_base):
    with tarfile.open(fileobj=out, mode="w:gz", compresslevel=9,
                      format=tarfile.PAX_FORMAT) as dst:
        for name, sha, size, mode, mtime in recipe["members"]:
            if sha is None:
                dst.addfile(_plain_info(name, mode, 0, mtime, isdir=True))
                continue
            data = extra.get(name)
            if data is None:
                data = from_base(name)
            if data is None or len(data) != size or _sha(data) != sha:
                raise PackageError("member %s of %s does not match the signed recipe"
                                   % (name, recipe["base"]))
            dst.addfile(_plain_info(name, mode, size, mtime), io.BytesIO(data))


def delta_tree_problems(app_dir, manifest, limit=None) -> list:
    """Paths of the node's tree that a delta cannot build on, without writing
    anything: every file the delta does NOT carry must already be there with
    the sha256 the signed manifest names; every rebuilt tarball's base must
    hold the members the recipe takes from it. Read-only -- the web preflight
    and the runner share it."""
    tree = tree_map(manifest)
    rebuild = _rebuild_map(manifest, tree)
    shipped = set(manifest.get("app_delta_files") or [])
    bad = []
    for rel in sorted(tree):
        if rel in shipped or rel in rebuild:
            continue
        sha, _mode, size = tree[rel]
        data = read_tree_file(app_dir, rel, size)
        if data is None or len(data) != size or _sha(data) != sha:
            bad.append(rel)
            if limit and len(bad) >= limit:
                return bad
    for rel, rec in sorted(rebuild.items()):
        need = [m for m in rec["members"] if m[1] is not None]
        if not need:
            continue
        base = read_tree_file(app_dir, rec["base"])
        try:
            names = _base_members(base)
        except PackageError:
            names = None
        if names is None:
            bad.append(rec["base"])
            continue
        # Members the delta carries are not needed from the base.
        carried = set(rec["shipped"])
        for name, sha, size, _mode, _mt in need:
            if name in carried:
                continue
            if names.get(base_member_name(rec, name)) != (sha, size):
                bad.append("%s (%s)" % (rec["base"], name))
                break
        if limit and len(bad) >= limit:
            return bad
    return bad


def _base_members(base_bytes):
    """{member name: (sha256, size)} of a tarball's regular files, or None."""
    if base_bytes is None:
        return None
    out = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(base_bytes), mode="r:*") as bt:
            for m in bt.getmembers():
                if m.isfile() and m.size <= MAX_TREE_FILE_BYTES:
                    out[str(PurePosixPath(m.name))] = (_sha(bt.extractfile(m).read()), m.size)
    except tarfile.TarError:
        raise PackageError("unreadable tarball")
    return out


def _check_tree_size(tree):
    total = sum(meta[2] for meta in tree.values())
    if total > MAX_UNPACKED_BYTES:
        raise PackageError("the application tree is %d bytes, over the %d-byte limit"
                           % (total, MAX_UNPACKED_BYTES))


def materialize_app(pkg_dir, manifest, out_dir, app_dir=None, current_version=""):
    """Path of a tarball holding the COMPLETE application tree of this package.

    /1: the package's own ``app.tar.gz``, untouched. /2: a plain ``app.tar``
    written to ``out_dir`` (root-only staging) in which every file hashes to
    ``app_tree``. For a delta, files it does not carry are read from
    ``app_dir`` and must already match; a mismatch refuses the whole package
    (:data:`DELTA_MISMATCH`) before the caller changes anything.

    The result has the shape every later step already handles -- the member
    list is the complete target tree, so removing files the new revision
    dropped keeps working exactly as for a full package."""
    pkg_dir, out_dir = Path(pkg_dir), Path(out_dir)
    if manifest.get("schema") != SCHEMA_V2:
        app_tar = pkg_dir / "app.tar.gz"
        if not app_tar.is_file():
            raise PackageError("package has no app.tar.gz")
        return app_tar
    check_v2_manifest(manifest)
    problem = lzma_problem(manifest)
    if problem:
        raise PackageError(problem)
    tree = tree_map(manifest)
    _check_tree_size(tree)
    kind = manifest["package_kind"]
    src = pkg_dir / manifest["app_archive"]
    out = out_dir / "app.tar"
    if kind == KIND_FULL:
        _materialize_full(src, tree, out)
        return out
    from_v = str(manifest["from_version"])
    if compare_versions(current_version or "", from_v) != 0:
        raise PackageError(
            "this delta package applies to %s only; this node runs %s. Apply the "
            "full package %s instead"
            % (from_v, current_version or "an unknown version",
               full_package_name(manifest.get("version"))))
    if app_dir is None:
        raise PackageError("a delta package needs the application tree to build on")
    _materialize_delta(src, manifest, tree, Path(app_dir), out)
    return out


def _materialize_full(src, tree, out):
    seen = set()
    with tarfile.open(src, "r:*") as tf, tarfile.open(out, "w",
                                                       format=tarfile.PAX_FORMAT) as dst:
        members, _written = _app_tree_members(tf)
        for m in members:
            if not m.isfile():
                continue
            rel = str(PurePosixPath(m.name))
            meta = tree.get(rel)
            data = tf.extractfile(m).read()
            if meta is None or _sha(data) != meta[0] or len(data) != meta[2]:
                raise PackageError("%s in the app archive does not match the signed "
                                   "tree" % rel)
            seen.add(rel)
            dst.addfile(_plain_info(rel, meta[1], meta[2]), io.BytesIO(data))
    missing = sorted(set(tree) - seen)
    if missing:
        out.unlink()
        raise PackageError("the app archive lacks %d file(s) of the signed tree: %s"
                           % (len(missing), ", ".join(missing[:5])))


def _materialize_delta(src, manifest, tree, app_dir, out):
    rebuild = _rebuild_map(manifest, tree)
    listed = set(manifest["app_delta_files"])
    bad = []
    with tarfile.open(src, "r:*") as tf:
        members, _written = _app_tree_members(tf)
        carried, extra = {}, {}
        for m in members:
            if not m.isfile():
                continue
            rel = str(PurePosixPath(m.name))
            if rel.startswith(REBUILD_PREFIX):
                rest = rel[len(REBUILD_PREFIX):]
                owner = next((r for r in rebuild if rest.startswith(r + "/")), None)
                if owner is None:
                    raise PackageError("delta carries %s for no rebuilt file" % rel)
                extra.setdefault(owner, {})[rest[len(owner) + 1:]] = tf.extractfile(m).read()
            elif rel in listed:
                carried[rel] = m
            else:
                raise PackageError("delta carries %s, which its manifest does not list"
                                   % rel)
        for rel, rec in rebuild.items():
            if set(extra.get(rel, {})) != set(rec["shipped"]):
                raise PackageError("delta does not carry exactly the members it lists "
                                   "for %s" % rel)
        if set(carried) != listed:
            raise PackageError("delta lacks %d listed file(s): %s" % (
                len(listed - set(carried)), ", ".join(sorted(listed - set(carried))[:5])))
        with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as dst:
            for rel in sorted(tree):
                sha, mode, size = tree[rel]
                if rel in rebuild:
                    rec = rebuild[rel]
                    try:
                        data = rebuild_tarball(rec, read_tree_file(app_dir, rec["base"]),
                                               extra.get(rel, {}))
                    except PackageError:
                        bad.append(rec["base"])
                        continue
                    dst.addfile(_plain_info(rel, mode, len(data)), io.BytesIO(data))
                    continue
                if rel in carried:
                    data = tf.extractfile(carried[rel]).read()
                    if len(data) != size or _sha(data) != sha:
                        raise PackageError("%s in the delta does not match the signed "
                                           "tree" % rel)
                else:
                    data = read_tree_file(app_dir, rel, size)
                    if data is None or len(data) != size or _sha(data) != sha:
                        bad.append(rel)
                        continue
                dst.addfile(_plain_info(rel, mode, size), io.BytesIO(data))
    if bad:
        out.unlink()
        raise PackageError(DELTA_MISMATCH % (
            manifest["from_version"], len(bad), ", ".join(bad[:5]),
            full_package_name(manifest.get("version"))))


# ---------------------------------------------------------------------------
# version comparison (PEP 440 subset: dotted numeric release + optional suffix)
# ---------------------------------------------------------------------------
def version_tuple(v: str):
    nums = []
    for part in re.split(r"[._-]", (v or "").strip()):
        if part.isdigit():
            nums.append(int(part))
        else:
            m = re.match(r"^(\d+)", part)
            if m:
                nums.append(int(m.group(1)))
            break
    return tuple(nums) or (0,)


def compare_versions(a: str, b: str) -> int:
    ta, tb = version_tuple(a), version_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def build_manifest(*, version, commit, built_at, python_tags, requirements,
                   files, min_from_version="", notes="", wheelset=None,
                   wheels_mode="", wheels_baseline=None, schema=SCHEMA,
                   payload=None) -> dict:
    """Assemble a manifest. Deliberately carries NO hostname, path or operator
    identity: the package is published, and a published artifact must not
    describe the estate that built it. ``payload`` holds the /2 keys
    (:func:`plan_full_payload` / :func:`plan_delta`)."""
    if schema not in SCHEMAS:
        raise PackageError("unknown package schema %r" % (schema,))
    if (schema == SCHEMA_V2) != bool(payload):
        raise PackageError("a /2 manifest needs its payload keys, and only a /2 one")
    m = {
        "schema": schema,
        "product": PRODUCT,
        "version": str(version),
        "commit": str(commit),
        "built_at": str(built_at),
        "python_tags": list(python_tags),
        "min_from_version": str(min_from_version or ""),
        "requirements": list(requirements),
        "files": files,
        "notes": str(notes or ""),
    }
    # Optional, additive keys: a node that predates them ignores them.
    if wheelset is not None:
        m["wheelset"] = sorted(wheelset)
    if wheels_mode:
        m["wheels_mode"] = str(wheels_mode)
    if wheels_baseline is not None:
        m["wheels_baseline"] = sorted(wheels_baseline, key=version_tuple)
    for k, v in (payload or {}).items():
        if k in m:
            raise PackageError("payload key %s collides with the manifest" % k)
        m[k] = v
    if schema == SCHEMA_V2:
        check_v2_manifest(m)
    return m


# ---------------------------------------------------------------------------
# Build side of format /2 (the release builder; never runs on a node)
# ---------------------------------------------------------------------------
#: Tarballs in the tree that travel as a recipe when most members are unchanged.
REBUILDABLE = re.compile(r"^api-packs/[^/]+\.tar\.gz$")
#: A recipe is used only when what it still has to ship is at most this share
#: of the file: below that the plain file is simpler and about as small.
REBUILD_MAX_SHARE = 0.5


def read_tree_tar(path) -> dict:
    """{path: (bytes, mode, mtime)} of every regular file of an app tarball,
    validated with the same rules as an install (:func:`_app_tree_members`)."""
    out = {}
    with tarfile.open(path, "r:*") as tf:
        members, _w = _app_tree_members(tf)
        for m in members:
            if m.isfile():
                rel = str(PurePosixPath(m.name))
                out[rel] = (tf.extractfile(m).read(), m.mode & 0o7777, int(m.mtime))
    return out


def tree_of(files) -> dict:
    """``app_tree`` for :func:`read_tree_tar` output."""
    return {rel: [_sha(data), mode, len(data)] for rel, (data, mode, _mt)
            in sorted(files.items())}


def plan_full_payload(files, archive="app.tar.xz") -> dict:
    return {"package_kind": KIND_FULL, "app_archive": archive, "app_tree": tree_of(files)}


def _tar_members(data):
    """[(name, sha|None, size, mode, mtime, bytes|None)] in archive order."""
    out = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
        for m in t.getmembers():
            name = str(PurePosixPath(m.name))
            if m.isdir():
                out.append((name, None, 0, m.mode & 0o7777, int(m.mtime), None))
            elif m.isfile():
                b = t.extractfile(m).read()
                out.append((name, _sha(b), len(b), m.mode & 0o7777, int(m.mtime), b))
            else:
                raise PackageError("%s holds a member that is neither file nor dir" % name)
    return out


def _recipe(rel, data, base_rel, base_data):
    """(recipe, {member: bytes} to ship) or None when a recipe does not pay."""
    try:
        target = _tar_members(data)
        based = _tar_members(base_data)
    except (tarfile.TarError, PackageError):
        return None
    roots = [_single_root(based), _single_root(target)]
    if not (roots[0] and roots[1]):
        roots = ["", ""]
    rec = {"roots": roots}
    have = {(n, s) for n, s, _sz, _md, _mt, _b in based if s is not None}
    ship = {n: b for n, s, _sz, _md, _mt, b in target
            if s is not None and (base_member_name(rec, n), s) not in have}
    if not all(_safe_rel(n) for n, *_r in target):
        return None
    if sum(len(b) for b in ship.values()) > REBUILD_MAX_SHARE * len(data):
        return None
    recipe = {"base": base_rel, "shipped": sorted(ship), "roots": roots,
              "members": [[n, s, sz, md, mt] for n, s, sz, md, mt, _b in target]}
    return recipe, ship


def _single_root(members) -> str:
    roots = {PurePosixPath(m[0]).parts[0] for m in members if m[0]}
    return roots.pop() if len(roots) == 1 else ""


def plan_delta(from_files, to_files, from_version, from_commit=""):
    """(payload keys, {archive path: bytes}) of a delta from ``from_files`` to
    ``to_files`` (both :func:`read_tree_tar` output, the REDACTED payloads the
    two releases shipped -- a node holds exactly those bytes)."""
    rebuild, archive = {}, {}
    for rel, (data, _mode, _mt) in sorted(to_files.items()):
        old = from_files.get(rel)
        if REBUILDABLE.match(rel):
            bases = ([rel] if old else []) + sorted(
                p for p in from_files if p != rel and REBUILDABLE.match(p)
                and PurePosixPath(p).parent == PurePosixPath(rel).parent)
            for b in bases:
                got = _recipe(rel, data, b, from_files[b][0])
                if got:
                    rebuild[rel] = got[0]
                    for name, b_ in got[1].items():
                        archive[REBUILD_PREFIX + rel + "/" + name] = b_
                    break
            if rel in rebuild:
                continue
            # No recipe: ship it whole even when unchanged -- a node that got
            # it by recipe holds other bytes, and the byte check would refuse.
            archive[rel] = data
            continue
        if old is None or old[0] != data:
            archive[rel] = data
    shipped = sorted(p for p in archive if not p.startswith(REBUILD_PREFIX))
    payload = {"package_kind": KIND_DELTA, "app_archive": DELTA_ARCHIVE,
               "from_version": str(from_version), "from_commit": str(from_commit or ""),
               "app_tree": tree_of(to_files), "app_delta_files": shipped,
               "app_rebuild": rebuild}
    return payload, archive


def write_payload_tar(path, entries, modes=None, compression="xz"):
    """Write ``entries`` ({path: bytes}) as a tarball, sorted, root-owned,
    mtime 0 -- deterministic input to the compressor."""
    mode = {"xz": "w:xz", "gz": "w:gz", "": "w"}[compression]
    kw = {"preset": 9} if compression == "xz" else (
        {"compresslevel": 9} if compression == "gz" else {})
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT, **kw) as t:
        for rel in sorted(entries):
            data = entries[rel]
            t.addfile(_plain_info(rel, (modes or {}).get(rel, 0o644), len(data)),
                      io.BytesIO(data))


def verify_delta_against(from_files, manifest, delta_archive_path, work_dir) -> list:
    """Builder self-check: apply the delta to a tree holding ``from_files`` (a
    stand-in for a node on ``from_version``) and compare the result with the
    signed tree. Returns problems; empty means the delta reproduces it."""
    work = Path(work_dir)
    node, pkg, out = work / "node", work / "pkg", work / "out"
    for d in (node, pkg, out):
        d.mkdir(parents=True, exist_ok=True)
    for rel, (data, mode, _mt) in from_files.items():
        p = node / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        os.chmod(p, mode or 0o644)
    import shutil
    shutil.copyfile(str(delta_archive_path), str(pkg / DELTA_ARCHIVE))
    try:
        built = materialize_app(pkg, manifest, out, app_dir=node,
                                current_version=manifest["from_version"])
    except PackageError as exc:
        return [str(exc)]
    got = read_tree_tar(built)
    tree = tree_map(manifest)
    problems = []
    rebuild = manifest.get("app_rebuild") or {}
    if set(got) != set(tree):
        problems.append("file set differs: +%s -%s" % (
            sorted(set(got) - set(tree))[:3], sorted(set(tree) - set(got))[:3]))
    for rel, (sha, mode, size) in tree.items():
        if rel not in got:
            continue
        data, gmode, _mt = got[rel]
        if rel in rebuild:
            want = [(m[0], m[1]) for m in rebuild[rel]["members"]]
            have = [(n, s) for n, s, *_r in _tar_members(data)]
            if want != have:
                problems.append("rebuilt %s differs from its recipe" % rel)
        elif _sha(data) != sha or gmode != mode:
            problems.append("%s differs" % rel)
    return problems


# ---------------------------------------------------------------------------
# Which wheels an update package has to carry
# ---------------------------------------------------------------------------
# A package used to carry EVERY pinned wheel (~55 MB) although most releases
# change none of them. It now carries only the wheels some supported node could
# be missing. "Supported" is defined by what we can actually KNOW: a node runs
# the venv of the package it applied, and a package records its full resolved
# wheel set in the manifest (`wheelset`). Packages built before that field
# existed say nothing reliable about their venv, and their runners have no
# dependency preflight -- so they never count as a baseline, and a delta
# package raises min_from_version to the oldest release that does. A node older
# than that is refused by the version rules (before anything is touched) and
# applies an earlier full package first. Fresh installs (offline bundles,
# image) are not affected: they always carry every wheel.
WHEEL_NAME_RE = re.compile(r"^([A-Za-z0-9_.]+)-([A-Za-z0-9_.!+]+)(-\d[^-]*)?-[^-]+-[^-]+-[^-]+\.whl$")


def wheel_key(filename) -> str:
    """``Flask_SQLAlchemy-3.1.1-py3-none-any.whl`` -> ``flask-sqlalchemy==3.1.1``.

    Name normalised per PEP 503, so a key from a filename and a key from a
    requirement line compare equal."""
    m = WHEEL_NAME_RE.match(os.path.basename(str(filename)))
    if not m:
        raise PackageError("not a wheel filename: %s" % filename)
    return "%s==%s" % (re.sub(r"[-_.]+", "-", m.group(1)).lower(), m.group(2))


def select_wheels(wheel_names, baseline=None, min_from_version="", version=""):
    """Decide which of ``wheel_names`` (the full resolved set) the package ships.

    ``baseline`` maps a released version to that release's ``wheelset``. Only
    entries older than ``version`` count. Returns a dict:

    * ``keep``: filenames to ship,
    * ``mode``: ``"full"`` (no usable baseline) or ``"delta"``,
    * ``min_from_version``: raised to the oldest baseline release in delta mode,
    * ``baseline``: the releases the delta was computed against.

    A wheel is left out only when EVERY baseline release already has that exact
    ``name==version``: any node at or above min_from_version then has it.
    """
    names = sorted(os.path.basename(str(n)) for n in wheel_names)
    usable = {}
    for v, keys in (baseline or {}).items():
        if not keys or not VERSION_RE.match(str(v)):
            continue
        if version and compare_versions(str(v), str(version)) >= 0:
            continue
        usable[str(v)] = set(keys)
    if min_from_version:
        usable = {v: k for v, k in usable.items()
                  if compare_versions(v, min_from_version) >= 0}
    if not usable:
        return {"keep": names, "mode": "full",
                "min_from_version": str(min_from_version or ""), "baseline": []}
    floor = min(usable, key=version_tuple)
    eff = str(min_from_version or "")
    if not eff or compare_versions(floor, eff) > 0:
        eff = floor
    common = set.intersection(*usable.values())
    keep = [n for n in names if wheel_key(n) not in common]
    return {"keep": keep, "mode": "delta", "min_from_version": eff,
            "baseline": sorted(usable, key=version_tuple)}


def read_package_wheelset(path):
    """(version, wheelset or None) of a package tarball, from its manifest only.

    None means the package predates ``wheelset`` and cannot serve as a
    baseline. Reads one member; never extracts anything."""
    root = archive_root(path)
    with tarfile.open(path, "r:*") as tf:
        try:
            mem = tf.getmember(root + "/manifest.json")
        except KeyError:
            raise PackageError("%s has no manifest.json" % path)
        if not mem.isfile() or mem.size > 16 * 1024 ** 2:
            raise PackageError("%s: manifest.json is not a sane regular file" % path)
        data = json.loads(tf.extractfile(mem).read().decode("utf-8"))
    ws = data.get("wheelset")
    return str(data.get("version") or ""), (list(ws) if isinstance(ws, list) else None)


def dump_manifest(manifest: dict) -> bytes:
    """The exact bytes that get signed."""
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
