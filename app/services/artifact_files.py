"""Read, edit, version and compare artifact CONTENT in the browser.

FortiWeb cannot do this. Its GUI offers *Create New | Delete* for the three
unreadable kinds and no view at all — the file you uploaded last year is a name
on a list. SATOM already keeps the bytes (:mod:`services.waf_artifacts`), so it
can offer the thing the appliance structurally cannot: open the schema, read
it, change one line, keep both copies, and diff them.

The versioning is not new machinery. ``waf_artifact`` rows have always been
versions keyed by content hash, so *saving an edit* is exactly *putting a
blob* — an edit that changes nothing writes nothing and mints no row, the same
rule the SoT store runs on. What this module adds is the surface: decoding,
the editability verdict, the diff, and a deletion that cannot strand a blob or
orphan one.

**One refusal is load-bearing:** content that is not valid UTF-8 is shown but
NOT editable. A textarea round-trip would silently replace every undecodable
byte with U+FFFD and save that as the new version — the file would still look
fine, still push, and no longer be the file. Better to say "binary, download
it" than to hand back a corrupted schema that passes every check.
"""
from __future__ import annotations

import difflib

from . import waf_artifacts as wa

#: Same cap the upload form enforces. These objects are schemas, not archives;
#: the cap exists so a mis-picked ISO cannot fill the partition the SoT store
#: shares.
MAX_BYTES = 4 * 1024 * 1024

#: Beyond this the browser gets the download, not a textarea: a 2 MB schema in
#: a <textarea> is a hung tab, and a hung tab reads as a broken page.
INLINE_LIMIT = 512 * 1024


def decode(blob: bytes) -> tuple[str, bool]:
    """``(text, is_clean_utf8)``. Never raises — a viewer that 500s on a weird
    byte is worse than one that shows the replacement character."""
    if blob is None:
        return "", False
    try:
        return blob.decode("utf-8"), True
    except UnicodeDecodeError:
        return blob.decode("utf-8", "replace"), False


def editability(blob: bytes | None) -> tuple[bool, str]:
    """May this content be edited in the browser, and if not, why not."""
    if blob is None:
        return False, "the stored blob is missing from data/artifacts"
    if b"\x00" in blob:
        return False, ("the content contains NUL bytes — it is not text, and a "
                       "textarea round-trip would not give it back unchanged")
    _text, clean = decode(blob)
    if not clean:
        return False, ("the content is not valid UTF-8 — editing it here would "
                       "save the replacement characters as the new version")
    if len(blob) > INLINE_LIMIT:
        return False, ("the content is %d KB, past the %d KB inline limit — "
                       "download it, edit it locally and upload the result"
                       % (len(blob) // 1024, INLINE_LIMIT // 1024))
    return True, ""


def object_key(row) -> tuple[str, str, int | None]:
    return (row.kind, row.name, row.appliance_id)


def versions(kind: str, name: str, appliance_id: int | None = None,
             *, any_scope: bool = False) -> list:
    """Every stored version of one object, newest first.

    ``any_scope=True`` crosses the appliance boundary on purpose: the object
    page is where an operator compares *this box's copy* against *the library
    copy*, and that comparison is the reason drift between two boxes under one
    name is visible at all.
    """
    from ..models_artifacts import WafArtifact

    q = WafArtifact.query.filter_by(kind=kind, name=name)
    if not any_scope:
        q = q.filter_by(appliance_id=appliance_id)
    return q.order_by(WafArtifact.created_at.desc(),
                      WafArtifact.id.desc()).all()


def object_index() -> list[dict]:
    """One entry per distinct ``(kind, name, appliance_id)``, newest first.

    The inventory renders OBJECTS, not versions. Listing versions there makes a
    single much-edited schema look like ten separate files, and the count that
    matters for a migration is how many distinct objects must travel.
    """
    from ..models_artifacts import WafArtifact

    groups: dict[tuple, dict] = {}
    for row in WafArtifact.query.order_by(WafArtifact.created_at.desc(),
                                          WafArtifact.id.desc()).all():
        key = object_key(row)
        g = groups.get(key)
        if g is None:
            groups[key] = {
                "kind": row.kind, "label": wa.label(row.kind), "name": row.name,
                "appliance_id": row.appliance_id, "latest": row.to_dict(),
                "versions": 1, "bytes": row.size or 0,
                "sources": {row.source}, "readable": wa.is_readable(row.kind),
                "created_at": row.created_at, "last_seen_at": row.last_seen_at,
            }
        else:
            g["versions"] += 1
            g["bytes"] += row.size or 0
            g["sources"].add(row.source)
            if row.last_seen_at and (not g["last_seen_at"]
                                     or row.last_seen_at > g["last_seen_at"]):
                g["last_seen_at"] = row.last_seen_at
    out = []
    for g in groups.values():
        g["sources"] = sorted(g["sources"])
        out.append(g)
    out.sort(key=lambda g: (g["kind"], g["name"], g["appliance_id"] or 0))
    return out


def save_text(kind: str, name: str, text: str, *, appliance_id: int | None = None,
              by: str = "", note: str = "") -> tuple[object | None, bool, str]:
    """Store an edited/authored body. ``(row, created, error)``.

    Rejects the empty body for the reason the upload form does: an empty
    artifact satisfies every "SATOM has a copy" check and pushes an object the
    referencing rule answers ``-7694`` for. A stored emptiness is worse than a
    known absence.
    """
    if kind not in wa.KINDS:
        return None, False, "unknown artifact type %r" % kind
    if not (name or "").strip():
        return None, False, ("an object name is required — it is the mkey the "
                             "device will store this under")
    blob = (text or "").encode("utf-8")
    if not blob.strip():
        return None, False, ("the content is empty. Storing it would let a "
                             "clone report success while pushing an object "
                             "with no content")
    if len(blob) > MAX_BYTES:
        return None, False, ("content is larger than %d KB — these objects are "
                             "schemas, not archives" % (MAX_BYTES // 1024))
    row, created = wa.put(kind, name.strip(), blob, appliance_id=appliance_id,
                          source="uploaded", by=by, note=note)
    return row, created, ""


def delete_version(row_id: int) -> tuple[bool, str, bool]:
    """Drop one stored version. ``(ok, message, blob_removed)``.

    The blob is removed ONLY when no other row still names its hash. Two
    objects legitimately share content (the same schema uploaded for two
    devices is one blob), and deleting the file out from under the surviving
    row would leave an index entry pointing at nothing — the exact corruption
    :func:`waf_artifacts.resolve` reports as ``store_error`` and which an
    operator would then chase as a missing upload.
    """
    from ..models import db
    from ..models_artifacts import WafArtifact

    row = WafArtifact.query.get(row_id)
    if row is None:
        return False, "no such version", False
    sha, name, kind = row.sha256, row.name, row.kind
    db.session.delete(row)
    db.session.commit()
    others = WafArtifact.query.filter_by(sha256=sha).count()
    removed = False
    if not others:
        p = wa.blob_path(sha)
        try:
            if p.exists():
                p.unlink()
                removed = True
        except OSError:
            # The index row is already gone and that is the state that matters;
            # a blob nothing points at is dead weight, not a fault to abort on.
            pass
    return True, ("deleted version %s of %s \"%s\"%s"
                  % (sha[:12], wa.label(kind), name,
                     "" if removed else " (blob kept — another version still "
                                        "carries the same content)")), removed


def diff_lines(old: bytes | None, new: bytes | None, *,
               old_label: str = "a", new_label: str = "b") -> list[dict]:
    """Unified diff as rows the template can colour without parsing prose.

    Returns ``[{"cls": "add|del|hunk|meta|ctx", "text": …}]``. The classes are
    resolved HERE rather than by a regex in Jinja: a diff whose ``---`` header
    is coloured as a deletion is a diff that lies about the first line.
    """
    a, _ = decode(old or b"")
    b, _ = decode(new or b"")
    out: list[dict] = []
    for line in difflib.unified_diff(a.splitlines(), b.splitlines(),
                                     fromfile=old_label, tofile=new_label,
                                     lineterm="", n=3):
        if line.startswith("+++") or line.startswith("---"):
            cls = "meta"
        elif line.startswith("@@"):
            cls = "hunk"
        elif line.startswith("+"):
            cls = "add"
        elif line.startswith("-"):
            cls = "del"
        else:
            cls = "ctx"
        out.append({"cls": cls, "text": line})
    return out


def diff_stat(rows: list[dict]) -> dict:
    return {"added": sum(1 for r in rows if r["cls"] == "add"),
            "removed": sum(1 for r in rows if r["cls"] == "del"),
            "identical": not any(r["cls"] in ("add", "del") for r in rows)}
