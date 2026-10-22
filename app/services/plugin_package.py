"""Plugin packages (``satom.plugin/1``) -- import and export of Plugin Studio plugins.

A package is how a plugin travels between SATOM servers WITHOUT an update
package: Plugin Studio's Export writes one (unsigned), the internal generator
(satom-dev/satom-plugins) builds and signs them, and Import reads them back.

A package is a zip holding exactly:

    plugin.json   manifest: format, slug, name, version, kind, icon,
                  description, datasets, params, min_satom, entry (code only),
                  built_at, files {member: sha256}
    plugin.sig    optional: {"alg": "ed25519", "key_id": <sha256 hex of the raw
                  public key>, "sig": <base64 Ed25519 over plugin.json's bytes>}
    body.jinja, style.css, script.js     kind view | widget
    code/<entry>/...                     kind code (see plugin_code)

Every rule is checked BEFORE anything is written: member names (no traversal,
nothing unlisted), sizes, the sha256 of each member against the manifest, and
the signature when there is one. A signature by a key that is not in
``TRUSTED_KEYS`` -- or one that does not match -- is an error, never "unsigned".
"""
from __future__ import annotations

import ast
import base64
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone

FORMAT = "satom.plugin/1"
EXT = ".satomplugin"
KINDS = ("view", "widget", "code", "app")
#: A Plugin Studio app: its form, diagram and actions, the data stores, HTTP
#: connections (never their secrets) and API Catalog versions it uses
#: (``services.studio_app_package``).
APP_FILE = "app.json"
CONTENT_FILES = ("body.jinja", "style.css", "script.js")
CODE_SUFFIXES = (".py", ".html", ".jinja", ".css", ".js", ".json", ".txt",
                 ".md", ".svg")
MAX_PACKAGE = 10 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 10 * 1024 * 1024
MAX_FILES = 200

SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
VERSION_RE = re.compile(r"^\d{1,4}\.\d{1,4}\.\d{1,4}$")
ICON_RE = re.compile(r"^bi-[a-z0-9-]{1,28}$")
ENTRY_RE = re.compile(r"^[a-z_][a-z0-9_]{0,40}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

#: key_id (sha256 hex of the raw Ed25519 public key) -> base64 raw public key.
#: The Vision EBC plugin signing key; its private half never leaves the
#: generator host. Replacing it = a new key there + a new entry here.
TRUSTED_KEYS: dict[str, str] = {
    "69ddf5c8b5b295cbd1efb628187dbe4936975708312c7c6f9fb8f83df5c94c6e":
        "BDuBTuJ12PR510M0DTXA+aCihA33q66w512ifE/gxBQ=",
}


class PackageError(ValueError):
    """The package is refused; the message says why, in plain English."""


@dataclass
class Package:
    manifest: dict
    files: dict[str, bytes] = field(default_factory=dict)
    signer: str | None = None          # trusted key_id, or None when unsigned
    manifest_bytes: bytes = b""        # exact bytes the signature covers
    sig_bytes: bytes = b""

    @property
    def slug(self) -> str:
        return self.manifest["slug"]

    @property
    def version(self) -> str:
        return self.manifest["version"]

    @property
    def kind(self) -> str:
        return self.manifest["kind"]

    def text(self, name: str) -> str:
        return self.files.get(name, b"").decode("utf-8")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def version_tuple(v: str | None) -> tuple:
    try:
        return tuple(int(x) for x in str(v).split("."))
    except (TypeError, ValueError):
        return (0,)


def _member_ok(name: str, kind: str, entry: str) -> bool:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    if kind in ("view", "widget"):
        return name in CONTENT_FILES
    if kind == "app":
        return name == APP_FILE
    return (len(parts) >= 3 and parts[0] == "code" and parts[1] == entry
            and name.endswith(CODE_SUFFIXES) and "__pycache__" not in parts)


def validate_manifest(m) -> dict:
    if not isinstance(m, dict):
        raise PackageError("plugin.json is not an object.")
    if m.get("format") != FORMAT:
        raise PackageError(f"Unknown package format {m.get('format')!r} "
                           f"(this server reads {FORMAT}).")
    if not SLUG_RE.match(str(m.get("slug") or "")):
        raise PackageError("The slug must be lowercase letters, digits and dashes.")
    name = m.get("name")
    if not (isinstance(name, str) and name.strip() and len(name) <= 200):
        raise PackageError("The plugin has no name.")
    if not VERSION_RE.match(str(m.get("version") or "")):
        raise PackageError("The version must be X.Y.Z.")
    kind = m.get("kind")
    if kind not in KINDS:
        raise PackageError(f"Unknown plugin kind {kind!r}.")
    if not ICON_RE.match(str(m.get("icon") or "")):
        raise PackageError("The icon must be a Bootstrap icon class (bi-...).")
    entry = str(m.get("entry") or "")
    if kind == "code" and not ENTRY_RE.match(entry):
        raise PackageError("A code plugin needs a Python package name in 'entry'.")
    if kind != "code" and entry:
        raise PackageError("'entry' is only for code plugins.")
    for k in ("datasets", "params"):
        if not isinstance(m.get(k, []), list):
            raise PackageError(f"'{k}' must be a list.")
    if kind in ("code", "app") and (m.get("datasets") or m.get("params")):
        raise PackageError(f"A {kind} plugin carries no datasets or params.")
    if m.get("min_satom") and not VERSION_RE.match(str(m["min_satom"])):
        raise PackageError("min_satom must be X.Y.Z.")
    files = m.get("files")
    if not isinstance(files, dict) or not files:
        raise PackageError("plugin.json lists no files.")
    if len(files) > MAX_FILES:
        raise PackageError(f"Too many files ({len(files)} > {MAX_FILES}).")
    for fname, digest in files.items():
        if not _member_ok(fname, kind, entry):
            raise PackageError(f"{fname!r} is not allowed in a {kind} plugin.")
        if not _SHA_RE.match(str(digest)):
            raise PackageError(f"{fname!r} has no sha256 in plugin.json.")
    if kind in ("view", "widget") and set(files) != set(CONTENT_FILES):
        raise PackageError(f"A {kind} plugin carries exactly "
                           f"{', '.join(CONTENT_FILES)}.")
    if kind == "code" and f"code/{entry}/__init__.py" not in files:
        raise PackageError(f"code/{entry}/__init__.py is missing.")
    return m


def check_code_entry(src: bytes, label: str) -> None:
    """The entry module must compile and assign ``bp`` at top level."""
    try:
        tree = ast.parse(src.decode("utf-8"), label)
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise PackageError(f"{label} does not compile: {exc}")
    for node in tree.body:
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        if any(isinstance(t, ast.Name) and t.id == "bp" for t in targets):
            return
    raise PackageError(f"{label} must define a Flask Blueprint named 'bp'.")


def trusted_keys() -> dict[str, bytes]:
    return {k: base64.b64decode(v) for k, v in TRUSTED_KEYS.items()}


def verify_signature(manifest_bytes: bytes, sig_bytes: bytes,
                     keys: dict[str, bytes] | None = None) -> str:
    """-> the signer's key_id. Raises on a malformed, untrusted or bad signature."""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    keys = trusted_keys() if keys is None else keys
    try:
        s = json.loads(sig_bytes.decode("utf-8"))
        if s.get("alg") != "ed25519":
            raise ValueError
        kid, sig = str(s["key_id"]), base64.b64decode(s["sig"])
    except Exception:
        raise PackageError("plugin.sig is malformed.")
    if kid not in keys:
        raise PackageError(f"The package is signed by a key this server does not "
                           f"trust ({kid[:16]}).")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(keys[kid]).verify(
            sig, manifest_bytes)
    except Exception:
        raise PackageError("The signature does not match plugin.json -- the "
                           "package was altered after it was signed.")
    return kid


def read_package(data: bytes, keys: dict[str, bytes] | None = None) -> Package:
    if not data:
        raise PackageError("The file is empty.")
    if len(data) > MAX_PACKAGE:
        raise PackageError(f"The file is larger than {MAX_PACKAGE // 1048576} MB.")
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise PackageError("This is not a SATOM plugin package.")
    infos = z.infolist()
    names = [i.filename for i in infos]
    if len(names) != len(set(names)):
        raise PackageError("The package has a duplicate member.")
    if "plugin.json" not in names:
        raise PackageError("plugin.json is missing -- not a SATOM plugin package.")
    if sum(i.file_size for i in infos) > MAX_TOTAL:
        raise PackageError("The package expands to more than 10 MB.")
    if any(i.file_size > MAX_FILE for i in infos):
        raise PackageError("A member is larger than 2 MB.")
    mbytes = z.read("plugin.json")
    try:
        manifest = json.loads(mbytes.decode("utf-8"))
    except Exception:
        raise PackageError("plugin.json is not valid JSON.")
    validate_manifest(manifest)
    allowed = set(manifest["files"]) | {"plugin.json", "plugin.sig"}
    extra = sorted(n for n in names if n not in allowed)
    if extra:
        raise PackageError("Members not listed in plugin.json: "
                           + ", ".join(extra[:5]))
    files: dict[str, bytes] = {}
    for fname, digest in manifest["files"].items():
        if fname not in names:
            raise PackageError(f"{fname} is listed but missing.")
        b = z.read(fname)
        if sha256(b) != digest:
            raise PackageError(f"{fname} does not match its sha256 in plugin.json.")
        files[fname] = b
    if manifest["kind"] == "code":
        entry = manifest["entry"]
        check_code_entry(files[f"code/{entry}/__init__.py"],
                         f"code/{entry}/__init__.py")
    elif manifest["kind"] == "app":
        try:
            body = json.loads(files[APP_FILE].decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise PackageError(f"{APP_FILE} is not valid JSON.")
        if not isinstance(body, dict) or not isinstance(body.get("app"), dict):
            raise PackageError(f"{APP_FILE} has no 'app' object.")
    else:
        for n in CONTENT_FILES:
            try:
                files[n].decode("utf-8")
            except UnicodeDecodeError:
                raise PackageError(f"{n} is not UTF-8 text.")
    signer, sig_bytes = None, b""
    if "plugin.sig" in names:
        sig_bytes = z.read("plugin.sig")
        signer = verify_signature(mbytes, sig_bytes, keys)
    return Package(manifest=manifest, files=files, signer=signer,
                   manifest_bytes=mbytes, sig_bytes=sig_bytes)


def write_package(manifest: dict, files: dict[str, bytes]) -> bytes:
    """An UNSIGNED package (export). Signing happens only on the generator host."""
    m = dict(manifest)
    m["format"] = FORMAT
    m["files"] = {n: sha256(b) for n, b in sorted(files.items())}
    validate_manifest(m)
    mbytes = json.dumps(m, indent=1, sort_keys=True,
                        ensure_ascii=False).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in [("plugin.json", mbytes)] + sorted(files.items()):
            zi = zipfile.ZipInfo(name, _ZIP_EPOCH)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            z.writestr(zi, data)
    return buf.getvalue()


def export_plugin(plugin, satom_version: str = "") -> tuple[str, bytes]:
    """-> (filename, bytes) of an unsigned package for a Plugin Studio row."""
    version = plugin.pkg_version or "1.0.0"
    manifest = {
        "slug": plugin.slug, "name": plugin.name, "version": version,
        "kind": plugin.kind if plugin.kind in ("view", "widget") else "view",
        "icon": plugin.icon if ICON_RE.match(plugin.icon or "") else "bi-puzzle",
        "description": "",
        "datasets": list(plugin.datasets),
        "params": list(plugin.param_defs),
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if VERSION_RE.match(satom_version or ""):
        manifest["min_satom"] = satom_version
    files = {"body.jinja": (plugin.jinja or "").encode("utf-8"),
             "style.css": (plugin.css or "").encode("utf-8"),
             "script.js": (plugin.js or "").encode("utf-8")}
    return f"{plugin.slug}-{version}{EXT}", write_package(manifest, files)
