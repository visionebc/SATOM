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
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tarfile
from pathlib import Path

SCHEMA = "satom.update-package/1"
PRODUCT = "satom"
KEY_TYPE = "satom-ed25519"
DEFAULT_TRUST_DIR = "/etc/satom/update-keys"

# A package filename we are willing to resolve. The runner takes only a
# BASENAME from the request and joins it to a fixed staging directory, so a
# forged request cannot point the runner at an arbitrary path.
PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.tar\.gz$")
VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*([A-Za-z0-9.+_-]*)$")


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
    with tarfile.open(path, "r:gz") as tf:
        roots = {Path(m.name).parts[0] for m in tf.getmembers() if m.name.strip()}
    if len(roots) != 1:
        raise PackageError("package must contain exactly one top-level "
                           "directory, found %d" % len(roots))
    return roots.pop()


def extract_package(path, dest) -> Path:
    """Extract the package tarball under ``dest``; return the package dir."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = archive_root(path)
    with tarfile.open(path, "r:gz") as tf:
        tf.extractall(dest, members=_safe_members(tf, root))
    return dest / root


def extract_app_tree(app_tar, dest) -> int:
    """Extract ``app.tar.gz`` over the application tree. Returns the file count.

    The application tarball is flat (no wrapper directory) because it is laid
    directly over an existing checkout, so it gets its own guard rather than
    reusing ``_safe_members``.
    """
    dest = Path(dest)
    count = 0
    with tarfile.open(app_tar, "r:gz") as tf:
        members = []
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
                count += 1
        tf.extractall(dest, members=members)
    return count


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
    """
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
    keys = load_trust_store(trust_dir)
    if not keys:
        raise PackageError("the trust store %s holds no usable public key"
                           % trust_dir)
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
    if manifest.get("schema") != SCHEMA:
        raise PackageError("unsupported package schema %r (this node speaks %s)"
                           % (manifest.get("schema"), SCHEMA))
    if manifest.get("product") != PRODUCT:
        raise PackageError("package is for product %r, not %s"
                           % (manifest.get("product"), PRODUCT))
    problems = verify_contents(pkg_dir, manifest)
    if problems:
        raise PackageError("package contents do not match the signed "
                           "manifest: %s" % "; ".join(problems[:5]))
    return {"manifest": manifest, "key": key}


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
                   files, min_from_version="", notes="") -> dict:
    """Assemble a manifest. Deliberately carries NO hostname, path or operator
    identity: the package is published, and a published artifact must not
    describe the estate that built it."""
    return {
        "schema": SCHEMA,
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


def dump_manifest(manifest: dict) -> bytes:
    """The exact bytes that get signed."""
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
