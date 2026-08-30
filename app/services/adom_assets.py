"""What one ADOM actually HAS: config backups, SoT history, firmware, identity.

The four things an operator asks about a device live in four different places —
the backup server's per-device folder, the ``sot_version`` index, the firmware
store, and the appliance row — and until now the only page that joined any two
of them was System Backup, which joins them for the whole console at once. At
one ADOM you could see what SATOM *does* to a device and never what it *holds*
for it.

Three rules this module exists to enforce:

* **An empty folder is an event, not a silence.** ``days_since_push`` and the
  state it grades are the entire point: a device with no backup for eleven days
  looks exactly like a device that has never been configured to push, and only
  one of those is normal. Both are reported by name.
* **Nothing is dropped for having no owner.** A backup folder whose device was
  de-registered still appears — under the identity record if there is one, in
  an explicit *unclaimed* bucket if there is not. Four FortiWebs' worth of
  history was invisible precisely because no page had a row to hang it on.
* **The row is the CHASSIS, because the artefact is the chassis's** (2026-08-30).
  A FortiWeb in ADOM mode is one appliance row per ADOM and one ``execute
  backup`` for the whole box. Listing the ADOM rows beside it printed three
  permanent *never pushed* lines per device — six of this fleet's twelve — for
  boxes that were pushing correctly. They are folded onto the chassis by
  ``device_identity.chassis_groups`` and their numbers are ADDED, never
  discarded: a fold that loses a version count is a different lie.

* **One card per ARTEFACT, not one table with everything in it** (2026-08-30).
  Config backups, the SoT history, firmware images and SATOM's own bundles are
  four different things, kept in four different places, with four different
  retention policies and four different failure modes — a single row that
  carried "21 backups" beside "11 versions" invited the reading that one is a
  copy of the other. The device sections survive INSIDE the first two cards,
  built by the same ``_sections`` call over the same rows, so a device sits
  under the same family heading in both.
* **SATOM's own bundle is console-wide, so it appears in Global only.** It is a
  dump of every ADOM at once; filing it under one family would claim it
  belongs to that family.

The assembly is here, not in the view, so it can be exercised against a
database without a request and without SFTP (an unreachable server degrades to
``reachable=False`` and every device reads "unknown", never "no backups").
"""
from __future__ import annotations

from datetime import datetime

#: Days since the last config push, graded. Deliberately generous at the top —
#: the appliances' own schedules are typically daily or weekly, so a red at 3
#: days would cry wolf on a correctly configured weekly job.
FRESH_DAYS = 8
STALE_DAYS = 31

#: The section a device with no established family lands in. Its own key, not
#: a bucket shared with a real ADOM: "we could not tell" and "FortiWeb" are
#: different answers and only one of them is actionable.
UNASSIGNED = "unassigned"

#: What the ``state`` filter accepts, and which graded states each one means.
#: ``stale`` deliberately spans warn AND crit: an operator filtering for stale
#: wants every device that stopped pushing, not the ones inside one threshold.
STATE_FILTERS = {
    "ok": ("ok",),
    "stale": ("warn", "crit"),
    "never": ("never",),
    "unknown": ("unknown",),
}


def _parse_mtime(text: str):
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(str(text)[:19], fmt)
        except (TypeError, ValueError):
            continue
    return None


def grade(days: float | None, has_files: bool) -> tuple[str, str]:
    """(state, label). ``never`` is its own state: "this device has never
    pushed" and "this device stopped pushing" need different actions, and one
    orange badge for both hides which one you are looking at."""
    if not has_files:
        return "never", "never pushed"
    if days is None:
        return "unknown", "date unreadable"
    if days <= FRESH_DAYS:
        return "ok", "%d day(s) ago" % int(days)
    if days <= STALE_DAYS:
        return "warn", "%d day(s) ago" % int(days)
    return "crit", "%d day(s) ago" % int(days)


def _haystack(row: dict) -> str:
    """Everything the free-text filter searches, lower-cased.

    Includes every name the device has EVER been known by: an operator who
    types the name a box was renamed away from is looking for that box, and
    the identity table is the only thing that still remembers the old one.
    """
    ident = row.get("identity")
    parts = [row.get("name") or "", row.get("slug") or "", row.get("serial") or "",
             getattr(ident, "host", "") or "", getattr(ident, "model", "") or "",
             getattr(ident, "firmware", "") or ""]
    parts.extend(getattr(ident, "name_history", None) or [])
    parts.extend(m.slug for m in row.get("members") or [])
    return " ".join(str(p) for p in parts).lower()


def matches(row: dict, *, device_type: str = "", state: str = "",
            q: str = "", hide_retired: bool = False) -> bool:
    """Whether one assembled row survives the filter. Pure, so the guards can
    exercise every clause without a request or a database."""
    if device_type:
        want = "" if device_type == UNASSIGNED else device_type
        if (row.get("product") or "") != want:
            return False
    if state:
        if row.get("state") not in STATE_FILTERS.get(state, ()):
            return False
    if hide_retired and row.get("retired"):
        return False
    if q:
        if q.strip().lower() not in _haystack(row):
            return False
    return True


def _folder_view(slug: str, folder: dict, now: datetime) -> dict:
    last = _parse_mtime((folder or {}).get("latest") or "")
    days = ((now - last).total_seconds() / 86400.0) if last else None
    state, label = grade(days, bool(folder and folder.get("count")))
    return {"slug": slug, "backups": int((folder or {}).get("count") or 0),
            "latest": (folder or {}).get("latest") or "",
            "files": (folder or {}).get("files") or [],
            "days": days, "state": state, "state_label": label}


#: Graded states from best to worst. A chassis that pushes under two folder
#: names is as healthy as its FRESHEST folder — grading it by the worst would
#: paint a device red for a folder it deliberately stopped using.
_STATE_RANK = ("ok", "warn", "crit", "unknown", "never")


# ---------------------------------------------------------------------------
# Where a device SITS — the reader's OWN classification, not a second one
# ---------------------------------------------------------------------------
#: The family heading already IS the ``kind`` dimension, so ``kind`` is
#: dropped from the nested lens. Nesting a dimension under itself gives every
#: family exactly one child named after the family — the chain of single-child
#: folders ``bookmarks.parse_lens`` REFUSES on the profile form. Refusing it
#: there and producing it here would be one tree drawn two different ways.
FAMILY_DIMENSION = "kind"


def lens_below_family(stack) -> list:
    """The nesting dimensions, with the family's own dimension removed.

    Repeats are dropped for the same reason ``bookmarks.parse_lens`` refuses
    them: below a dimension's first level every device already shares one
    value, so a second occurrence adds depth and no information.
    """
    out: list = []
    for dim in stack or []:
        if dim == FAMILY_DIMENSION or dim in out:
            continue
        out.append(dim)
    return out


def _lens_title(stack) -> str:
    """The arrangement, written out. Delegated to the bookmarks service so the
    page and the panel cannot spell the same order two ways."""
    from .bookmarks import lens_title
    return lens_title(stack)


def _appliances_of(row, appliances: dict) -> list:
    """Every appliance row this chassis folds, primary first.

    ``device_identity.chassis_groups`` already elected the row that speaks for
    the box and sorts the rest deterministically; reusing that order is what
    keeps a device in the same bucket between two renders.
    """
    out = []
    for member in row.get("members") or []:
        appl = appliances.get(getattr(member, "appliance_id", None))
        if appl is not None:
            out.append(appl)
    return out


def _dim_value(row, dim: str, segments, appliances: dict) -> str:
    """One classification value for a CHASSIS.

    Read off the APPLIANCE row, because that is where ``zone``, ``line`` and
    ``department`` live — a :class:`DeviceIdentity` has no such column, and
    reading the identity would silently answer "(unclassified)" for the whole
    fleet.

    The primary row answers. An unclassified primary falls back to the first
    sibling that carries a real value: a sibling ADOM row nobody filled in
    does not un-classify a box that IS in the DMZ.

    A chassis with no appliance row left at all — a de-registered device only
    the identity table still remembers — reads ``(unclassified)``. That is the
    honest answer: the record that held the classification is gone, and
    deriving one from the name would be a guess.
    """
    from .bookmarks import UNCLASSIFIED, dimension_value
    for appl in _appliances_of(row, appliances):
        try:
            value = dimension_value(appl, dim, segments)
        except ValueError:          # a dimension this build does not know
            return UNCLASSIFIED
        if value != UNCLASSIFIED:
            return value
    return UNCLASSIFIED


def bucket_path(row, lens, segments=(), appliances=None) -> list:
    """The ``(dim, value)`` chain a chassis falls under.

    Truncated exactly the way the bookmarks panel truncates it: the chain
    stops at the first level whose WHOLE TAIL is unclassified. Without that, a
    device classified nowhere sinks three levels of
    ``(unclassified) → (unclassified) → (unclassified)`` — depth with no
    information in it, on the half of a real fleet that most needs noticing.
    A device with no line but a real zone still gets
    ``(unclassified) → dmz``, because that zone is a fact.

    Reproduced in BEHAVIOUR and pinned by a guard rather than imported: the
    panel walks appliances and this walks folded chassis, but a device filed
    under ``dmz`` on the panel and under ``(unclassified)`` here would make
    one of the two pages wrong without either of them failing.
    """
    from .bookmarks import UNCLASSIFIED
    appliances = appliances or {}
    values = [_dim_value(row, d, segments, appliances) for d in lens]
    for i, value in enumerate(values):
        if all(v == UNCLASSIFIED for v in values[i:]):
            values = values[:i + 1]
            break
    return list(zip(lens, values))


def _synthetic() -> tuple:
    from .bookmarks import NO_SEGMENT, UNCLASSIFIED
    return (UNCLASSIFIED, NO_SEGMENT)


#: Row fields a group header adds up. Named once: a bucket that reported a
#: number its own rows do not add to is a fold that lost devices.
_ROW_SUMS = ("backups", "sot_versions", "sot_evacuated", "sot_bytes")


def _totals(rows: list) -> dict:
    """The counters every grouping level carries, from ONE author.

    The family header and every classification level below it are summed by
    this function, so the two can never disagree about the same rows.
    """
    out = {k: sum(int(r.get(k) or 0) for r in rows) for k in _ROW_SUMS}
    out["count"] = len(rows)
    out["no_backup"] = sum(1 for r in rows if r.get("state") == "never")
    out["sot_none"] = sum(1 for r in rows if not r.get("sot_versions"))
    return out


def _nodes(rows: list, lens, segments, appliances: dict, prefix: str) -> list:
    """Pre-order flattening of the classification tree under ONE family.

    Flat, not nested, because the table is flat. Each node carries its DEPTH
    and the ancestors that must all be open for it to be visible; nesting the
    structure and re-flattening it in Jinja would move the open/closed rule
    into the template, where the browser's copy of it could not be compared
    against anything.

    A node may carry BOTH rows of its own and children — that is exactly what
    the truncation in :func:`bucket_path` produces, and dropping either half
    would lose devices off the page.

    ``count`` and the sums describe the whole SUBTREE; ``rows``/``own_count``
    describe only what this node draws directly. Folding a node must never
    take a number off the page, so the header counts everything under it.

    The node KEY is built from the raw stored value and only the NAME is the
    displayed one. Keying on the label would move every node the day a value
    is re-spelled, and the browser's open set is keyed on exactly that string
    — a cosmetic rename would fold shut every tree every reader had open.
    """
    from .bookmarks import DIMENSION_LABELS, dimension_label
    nodes: dict = {}
    for row in rows:
        key: tuple = ()
        chain = bucket_path(row, lens, segments, appliances)
        for step in chain:
            key = key + (step,)
            nodes.setdefault(key, {"sub": [], "own": []})["sub"].append(row)
        if chain:
            nodes[key]["own"].append(row)

    synth = _synthetic()
    out: list = []

    def path_of(key) -> str:
        return prefix + "".join("/%s=%s" % (d, v) for d, v in key)

    def emit(parent) -> None:
        n = len(parent) + 1
        level = [k for k in nodes if len(k) == n and k[:len(parent)] == parent]
        # Real buckets first, alphabetically; the synthetic ones last. A
        # bracket sorts before every letter, so plain sorting would open each
        # family with the bucket that says nothing about the fleet and push
        # the real estate underneath it.
        level.sort(key=lambda k: (k[-1][1] in synth, str(k[-1][1]).lower()))
        for key in level:
            dim, value = key[-1]
            node = nodes[key]
            out.append({
                "path": path_of(key),
                "anc": [path_of(key[:i + 1]) for i in range(len(key) - 1)],
                "chain": [path_of(key[:i + 1]) for i in range(len(key))],
                "depth": len(key) - 1,
                "dim": dim, "value": value,
                "label": dimension_label(dim, value),
                "dim_label": DIMENSION_LABELS.get(dim, dim),
                "rows": node["own"], "own_count": len(node["own"]),
            } | _totals(node["sub"]))
            emit(key)

    emit(())
    return out


def _sections(rows: list, lens=(), segments=(),
              appliances: dict | None = None) -> list:
    """One section per device family, in the order the ADOM registry declares
    — so the page and the ADOM switcher agree — each nested by the READER'S
    OWN classification lens.

    The nesting is the same one the bookmarks panel uses (``line › zone ›
    department`` until the reader changes it on their profile), because this
    console must not have two ideas about how the fleet is arranged. It is
    read per-reader and never stored on the row: re-classifying a device
    needs no migration here, exactly as it needs none there.

    An empty *lens* is the degenerate case, not an error — the family
    headings alone, which is what this page did before. It happens for real
    whenever a reader's whole lens is ``kind``.
    """
    from ..branding import all_adoms
    order, labels = [], {}
    for adom in all_adoms():
        key = adom.get("key") or ""
        if key in ("", "global"):
            continue
        order.append(key)
        labels[key] = adom.get("name") or key
    buckets: dict = {}
    for row in rows:
        buckets.setdefault(row.get("product") or UNASSIGNED, []).append(row)
    out = []
    for key in order + [k for k in sorted(buckets) if k not in order]:
        if key not in buckets:
            continue
        group = buckets[key]
        # Counters from the SAME function every level below uses, over the
        # SAME row set the backup and SoT cards share. Two summing sites over
        # one set of rows is how a device ends up under FortiWeb in one card
        # and under unassigned in the next.
        out.append({"key": key, "label": labels.get(key, key),
                    "rows": group,
                    "nodes": _nodes(group, lens, segments,
                                    appliances or {}, key)} | _totals(group))
    return out


def _firmware_sections(images: list, device_type: str = "") -> list:
    """Firmware images grouped by the family they are FOR, registry order.

    Grouped the same way and in the same order as the device sections: an
    operator reading "FortiWeb" in one card and "FortiWeb" in the next must be
    reading about the same family, and two orderings on one page is how a
    version gets attributed to the wrong appliance line.
    """
    from ..branding import all_adoms
    order, labels = [], {}
    for adom in all_adoms():
        key = adom.get("key") or ""
        if key in ("", "global"):
            continue
        order.append(key)
        labels[key] = adom.get("name") or key
    buckets: dict = {}
    for img in images:
        key = (getattr(img, "product", "") or "") or UNASSIGNED
        if device_type and key != device_type:
            continue
        buckets.setdefault(key, []).append(img)
    out = []
    for key in order + [k for k in sorted(buckets) if k not in order]:
        if key not in buckets:
            continue
        group = buckets[key]
        out.append({"key": key, "label": labels.get(key, key),
                    "rows": group, "count": len(group),
                    "bytes": sum(int(getattr(i, "size_bytes", 0) or 0)
                                 for i in group)})
    return out


def bundles_view(product: str = "") -> dict:
    """SATOM's OWN backup bundles — console-wide, so Global only.

    ``shown`` is false inside any ADOM and the caller renders nothing. This is
    not cosmetic: a bundle is a dump of the whole console (every ADOM's
    devices, every credential, the SoT index) and listing it under one family
    would say it belongs to that family. There is exactly one such set of
    files no matter which ADOM you are standing in.

    Degrades rather than raises: ``all_bundles`` already answers ``{}`` for an
    unreachable server, so a network blip renders "we cannot see the off-box
    copy", never "there are no backups".
    """
    if product:
        return {"shown": False, "rows": [], "count": 0, "bytes": 0,
                "local": 0, "off_box": 0, "mismatch": [], "error": "",
                "only_off_box": False, "only_local": False}
    try:
        rows = list(_system_backup().all_bundles())
        error = ""
    except Exception as exc:  # noqa: BLE001 — the card renders the error state
        rows, error = [], str(exc)
    local = sum(1 for b in rows if b.get("local"))
    off_box = sum(1 for b in rows if b.get("off_box"))
    return {
        "shown": True, "rows": rows, "count": len(rows), "error": error,
        "bytes": sum(int(b.get("size") or 0) for b in rows),
        "local": local, "off_box": off_box,
        # A bundle held in exactly one place is a bundle with no redundancy,
        # and the two ways of getting there fail differently: only-local dies
        # with the node it is backing up, only-off-box dies with the backup
        # server. Both are worth naming; neither is an error.
        "only_local": bool(rows) and off_box == 0,
        "only_off_box": bool(rows) and local == 0,
        # Present in both places under one name with two sizes: a truncated
        # upload. Reported by name because the size is the only thing that
        # tells the two apart.
        "mismatch": [b["name"] for b in rows
                     if b.get("local") and b.get("off_box")
                     and not b.get("size_match")],
    }


def _system_backup():
    from . import system_backup
    return system_backup


def collect(product: str = "", *, now: datetime | None = None,
            device_type: str = "", state: str = "", q: str = "",
            hide_retired: bool = False, lens=(), segments=None) -> dict:
    """Everything one ADOM holds. Empty *product* means the whole console.

    One SFTP round trip for the entire fleet listing (``inventory``), never one
    per device: at 100 appliances a per-device call is 100 connections to
    render one page.

    The filter arguments narrow ``rows``/``sections`` only. ``totals`` always
    describes the WHOLE ADOM: a tile that shrinks with the filter reads as
    "this ADOM has 2 devices" when what happened is that you typed something.

    *lens* is the reader's bookmark-panel classification order, passed in
    rather than read here so the guards can drive every arrangement without a
    logged-in user. It is filtered through :func:`lens_below_family`, so a
    caller may hand over the raw stored stack.
    """
    from . import backup_server, device_identity, sot_store

    now = now or datetime.utcnow()
    lens = lens_below_family(lens)

    # Only fetched when a dimension actually needs it: `segment` is derived
    # from the declared CIDRs and the other five are plain columns, so a
    # settings read on every render would buy nothing.
    if segments is None:
        if "segment" in lens:
            from . import settings_store
            try:
                segments = settings_store.segments()
            except Exception:  # noqa: BLE001 — no segment beats no page
                segments = ()
        else:
            segments = ()

    # The classification lives on the APPLIANCE row. One query for the whole
    # console, never one per device: the page already folds ~100 identities
    # and a per-row lookup would be ~100 statements to draw one table. A
    # failure here degrades to "(unclassified)", never to a 500.
    appliances: dict = {}
    if lens:
        try:
            from ..models import Appliance
            appliances = {a.id: a for a in Appliance.query.all()}
        except Exception:  # noqa: BLE001
            appliances = {}

    try:
        inv = backup_server.inventory()
    except Exception as exc:  # noqa: BLE001 — the page renders the error state
        inv = {"configured": False, "reachable": False, "error": str(exc),
               "devices": [], "firmware": []}
    folders = {str(d.get("device") or ""): d for d in (inv.get("devices") or [])}

    sot = {row["device"]: row for row in sot_store.devices_detail(product)}

    rows = []
    claimed = set()
    for group in device_identity.chassis_groups(product):
        ident = group["primary"]
        members = group["rows"]
        claimed.update(m.slug for m in members)

        # Every member's folder, not just the chassis's. A sibling normally
        # has none — but if one IS pushing under its own name that folder is
        # real, and folding it out of sight is how an estate goes missing.
        views = [_folder_view(m.slug, folders[m.slug], now)
                 for m in members if m.slug in folders]
        backups = sum(v["backups"] for v in views)
        latest = max((v["latest"] for v in views), default="")
        newest = _parse_mtime(latest)
        days = ((now - newest).total_seconds() / 86400.0) if newest else None
        if views:
            state_key = min((v["state"] for v in views),
                            key=_STATE_RANK.index)
            label = next(v["state_label"] for v in views
                         if v["state"] == state_key)
        else:
            state_key, label = grade(None, False)

        detail = [sot.get(m.slug, {}) for m in members]
        rows.append({
            "identity": ident,
            "members": members,
            "slug": ident.slug,
            "name": ident.name,
            "product": ident.product or "",
            "serial": next((m.serial for m in members if m.serial), ""),
            # Retired only when EVERY row of the chassis is: a box with one
            # live ADOM row is a live box, and greying it out would say the
            # opposite about hardware that is still in service.
            "retired": all(m.retired for m in members),
            "backups": backups,
            "backup_latest": latest,
            "backup_files": [f for v in views for f in v["files"]],
            "folders": views,
            "days_since_push": days,
            "state": state_key,
            "state_label": label,
            "sot_versions": sum(int(d.get("versions") or 0) for d in detail),
            "sot_local": sum(int(d.get("local") or 0) for d in detail),
            "sot_evacuated": sum(int(d.get("evacuated") or 0) for d in detail),
            "sot_last_change": max((d.get("last_change") or ""
                                    for d in detail), default=""),
            "sot_bytes": sum(int(d.get("bytes_gz") or 0) for d in detail),
        })

    # Folders on the server that no identity claims. Never hidden: this bucket
    # is where a device renamed on the appliance but not in SATOM shows up, and
    # it is the only place a totally forgotten estate is visible at all.
    unclaimed = []
    if not product:
        for slug, folder in sorted(folders.items()):
            if slug in claimed:
                continue
            unclaimed.append(_folder_view(slug, folder, now) | {
                "backups": int(folder.get("count") or 0),
                "backup_latest": folder.get("latest") or "",
                "backup_files": folder.get("files") or []})

    # SoT devices with no identity row at all — should be empty once
    # device_identity.reconcile() has run, and says so loudly if it is not.
    orphan_sot = sorted(set(sot) - claimed) if not product else []

    firmware = []
    try:
        from ..models_firmware import FirmwareImage
        fq = FirmwareImage.query
        if product:
            fq = fq.filter_by(product=product)
        firmware = fq.order_by(FirmwareImage.id.desc()).all()
    except Exception:  # noqa: BLE001
        firmware = []

    shown = [r for r in rows
             if matches(r, device_type=device_type, state=state, q=q,
                        hide_retired=hide_retired)]

    # The SoT card is a table about a DIFFERENT artefact, so the backup-state
    # filter must not narrow it: "never pushed" grades the backup server, and
    # a device that has never pushed a config file can still have a hundred
    # recorded configuration versions. Applying it here would hide exactly the
    # rows an operator went looking for. The identity filters (family, name,
    # de-registered) DO apply — those describe the device, not the artefact.
    shown_sot = [r for r in rows
                 if matches(r, device_type=device_type, q=q,
                            hide_retired=hide_retired)]

    return {
        "product": product,
        "server": {"configured": bool(inv.get("configured")),
                   "reachable": bool(inv.get("reachable")),
                   "host": inv.get("host") or "",
                   "error": inv.get("error") or ""},
        "rows": shown,
        "sections": _sections(shown, lens, segments, appliances),
        "sot_sections": _sections(shown_sot, lens, segments, appliances),
        # The heading NAMES the arrangement. A control can only tell you how a
        # tree is grouped once you open it; the heading says it while you are
        # reading the tree it produced. Same reason the bookmarks panel put
        # its lens order in the root's name instead of a dropdown.
        "lens": list(lens),
        "lens_title": _lens_title([FAMILY_DIMENSION] + list(lens)),
        "unclaimed": unclaimed,
        "orphan_sot": orphan_sot,
        "firmware": firmware,
        "firmware_sections": _firmware_sections(firmware, device_type),
        "bundles": bundles_view(product),
        "filters": {"type": device_type, "state": state, "q": q,
                    "hide_retired": bool(hide_retired),
                    "active": bool(device_type or state or q or hide_retired),
                    "shown": len(shown), "of": len(rows),
                    "shown_sot": len(shown_sot)},
        "types": sorted({r["product"] or UNASSIGNED for r in rows}),
        # Unfiltered, always. See the docstring.
        "totals": {
            "devices": len(rows),
            "retired": sum(1 for r in rows if r["retired"]),
            "backups": sum(r["backups"] for r in rows),
            "no_backup": sum(1 for r in rows if r["state"] == "never"),
            "stale": sum(1 for r in rows if r["state"] in ("warn", "crit")),
            "sot_versions": sum(r["sot_versions"] for r in rows),
            "sot_evacuated": sum(r["sot_evacuated"] for r in rows),
            "sot_none": sum(1 for r in rows if not r["sot_versions"]),
            # Unfiltered like the rest: `firmware` above is already scoped to
            # the ADOM, and the type filter only ever narrows what is DRAWN.
            "firmware": len(firmware),
            "firmware_bytes": sum(int(getattr(i, "size_bytes", 0) or 0)
                                  for i in firmware),
        },
    }
