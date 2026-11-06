"""Plugin bundles -- several plugin packages installed in one go (2026-11-06).

A bundle (``.satombundle``) is a zip of ``.satomplugin`` files plus an
optional ``bundle.json``::

    {"format": "satom.plugin-bundle/1", "name": "Troubleshooting",
     "description": "...", "folder": "Troubleshooting",
     "plugins": ["backend-reachability.satomplugin", ...]}

``plugins`` is the install order (default: by file name) and, when given,
must list every member. A plain ``.zip`` of ``.satomplugin`` files with no
``bundle.json`` is a bundle too: zip a folder of packages and import it.

The bundle itself is NOT signed and carries no trust: every member is a
complete plugin package that goes through the same import as on its own
(``plugin_import.import_package``: its own signature, policy and rules).
``bundle.json`` only suggests a name and the folder the apps it creates are
filed under -- the operator sees both on the preview and confirms. Members
other than ``.satomplugin`` files and ``bundle.json`` refuse the bundle, so
nothing travels unseen.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from dataclasses import dataclass, field

from . import plugin_package as P

FORMAT = "satom.plugin-bundle/1"
EXT = ".satombundle"
MANIFEST = "bundle.json"
MAX_MEMBERS = 50
#: The largest bundle file, and what it may expand to.
MAX_BUNDLE = 64 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
_MEMBER_RE = re.compile(r"^(?:[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]{1,120}\.satomplugin$")
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


class BundleError(ValueError):
    pass


@dataclass
class Bundle:
    name: str
    description: str = ""
    folder: str = ""
    #: ``[(member file name, package bytes)]`` in install order.
    members: list = field(default_factory=list)


def _zip(data: bytes):
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        return None


def is_bundle(data: bytes) -> bool:
    """A zip with no ``plugin.json`` (not a package) that holds a
    ``bundle.json`` or at least one ``.satomplugin``. Decides nothing about
    its validity: :func:`read_bundle` does."""
    if not data or data[:2] != b"PK":
        return False
    z = _zip(data)
    if z is None:
        return False
    names = [i.filename for i in z.infolist() if not i.is_dir()]
    if "plugin.json" in names:
        return False
    return MANIFEST in names or any(n.endswith(".satomplugin") for n in names)


def read_bundle(data: bytes, fallback_name: str = "") -> Bundle:
    if not data:
        raise BundleError("The file is empty.")
    if len(data) > MAX_BUNDLE:
        raise BundleError("The bundle is larger than %d MB." % (MAX_BUNDLE // 1048576))
    z = _zip(data)
    if z is None:
        raise BundleError("This is not a SATOM plugin bundle (not a zip).")
    infos = [i for i in z.infolist() if not i.is_dir()]
    names = [i.filename for i in infos]
    if len(names) != len(set(names)):
        raise BundleError("The bundle has a duplicate member.")
    if sum(i.file_size for i in infos) > MAX_EXPANDED:
        raise BundleError("The bundle expands to more than %d MB." % (MAX_EXPANDED // 1048576))
    big = [i.filename for i in infos if i.file_size > P.MAX_PACKAGE]
    if big:
        raise BundleError("A member is larger than one package may be (%d MB): %s"
                          % (P.MAX_PACKAGE // 1048576, big[0]))
    plugins = [n for n in names if n != MANIFEST]
    stray = [n for n in plugins if not _MEMBER_RE.match(n)]
    if stray:
        raise BundleError("A bundle holds only .satomplugin files and bundle.json; it also has: "
                          + ", ".join(stray[:5]))
    if not plugins:
        raise BundleError("The bundle has no .satomplugin file.")
    if len(plugins) > MAX_MEMBERS:
        raise BundleError("A bundle holds at most %d plugins (this one has %d)."
                          % (MAX_MEMBERS, len(plugins)))
    meta = {}
    if MANIFEST in names:
        try:
            meta = json.loads(z.read(MANIFEST).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise BundleError("bundle.json is not valid JSON.") from None
        if not isinstance(meta, dict):
            raise BundleError("bundle.json is not an object.")
        if meta.get("format", FORMAT) != FORMAT:
            raise BundleError("bundle.json: format %r is not %s." % (meta.get("format"), FORMAT))
    order = meta.get("plugins")
    if order is not None:
        if not isinstance(order, list) or not all(isinstance(x, str) for x in order) \
                or len(order) != len(set(order)) or set(order) != set(plugins):
            raise BundleError("bundle.json: 'plugins' must list every .satomplugin of the "
                              "bundle once, in install order.")
    else:
        order = sorted(plugins, key=str.lower)
    name = _text(meta.get("name"), 120) or _text(fallback_name, 120) or "bundle"
    return Bundle(name=name, description=_text(meta.get("description"), 2000),
                  folder=_text(meta.get("folder"), 48),
                  members=[(n, z.read(n)) for n in order])


def _text(v, n: int) -> str:
    return " ".join(v.split())[:n] if isinstance(v, str) else ""


def write_bundle(name: str, members: list, *, description: str = "", folder: str = "") -> bytes:
    """A bundle of *members* (``[(file name, package bytes)]``, in install
    order). Deterministic: the same input gives the same bytes."""
    if not members:
        raise BundleError("A bundle needs at least one plugin.")
    if len(members) > MAX_MEMBERS:
        raise BundleError("A bundle holds at most %d plugins." % MAX_MEMBERS)
    files = [n for n, _ in members]
    if len(files) != len(set(files)) or not all(_MEMBER_RE.match(n) for n in files):
        raise BundleError("Member names are unique .satomplugin file names.")
    manifest = {"format": FORMAT, "name": name, "description": description,
                "folder": folder, "plugins": files}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname, blob in [(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True).encode())] \
                + list(members):
            info = zipfile.ZipInfo(fname, _ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            z.writestr(info, blob)
    out = buf.getvalue()
    if len(out) > MAX_BUNDLE:
        raise BundleError("The bundle would be larger than %d MB." % (MAX_BUNDLE // 1048576))
    return out
