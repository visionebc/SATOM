"""Maintain :class:`app.models_identity.DeviceIdentity` — the record of who a
device is, and who it was.

Three writers, and only three:

* :func:`observe` — called from ``firmware_probe.refresh`` on the ONE status
  call that already runs. No extra device I/O is introduced anywhere: the
  serial was already being read off that payload and thrown away (it was used
  to guess ``hw_type`` and then discarded).
* :func:`retire` — called when an appliance is de-registered. Sets a timestamp;
  never deletes.
* :func:`reconcile` — idempotent, boot- and page-safe: makes sure every
  appliance and every device the SoT store has ever recorded HAS a row, so the
  history is reachable from a page instead of only from psql.

The product of a device that no longer has an appliance row is established by
:func:`fingerprint_product`, which matches the snapshot's own endpoint keys
against the four shipped endpoint catalogs. That is a measurement of the
snapshot, not a guess from the name: a device called ``fw7`` and a device called
``fortiweb11`` are identified the same way, and a name that lies is ignored.
A snapshot that matches nothing leaves the product EMPTY rather than picking the
most popular family — an unassigned device is visible and askable; one filed
under the wrong ADOM is neither.
"""
from __future__ import annotations

import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path

#: product key -> endpoint catalog filename at the repo root.
CATALOGS = {
    "fortiweb": "endpoints.yaml",
    "fortiadc": "endpoints_fortiadc.yaml",
    "fortianalyzer": "endpoints_fortianalyzer.yaml",
    "fortiauthenticator": "endpoints_fortiauthenticator.yaml",
}

#: A fingerprint is accepted only when the best family explains this fraction of
#: the snapshot's endpoint keys. The four catalogs overlap on generic names
#: (``system_global``, ``system_interface`` …), so a bare "highest score wins"
#: would confidently file a 3-endpoint snapshot under whichever family happens
#: to list those three.
MIN_COVERAGE = 0.55
#: …and only when it beats the runner-up by this much. Two families that
#: explain a snapshot equally well have not identified it.
MIN_MARGIN = 0.15


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def slug_for(name: str) -> str:
    from .device_sync import slugify
    return slugify(name or "")


@lru_cache(maxsize=1)
def _catalog_keys() -> dict:
    """product -> frozenset of endpoint keys, read from the shipped YAML."""
    import yaml
    out = {}
    for product, fname in CATALOGS.items():
        path = _repo_root() / fname
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except (OSError, ValueError):
            data = {}
        out[product] = frozenset(data) if isinstance(data, dict) else frozenset()
    return out


def snapshot_endpoint_keys(snapshot: dict) -> set:
    """The endpoint keys a harvested snapshot actually contains."""
    keys = set()
    for endpoints in ((snapshot or {}).get("sections") or {}).values():
        if isinstance(endpoints, dict):
            keys.update(str(k) for k in endpoints)
    return keys


def fingerprint_product(snapshot: dict) -> str:
    """Which family this snapshot came from, or "" when it cannot be told."""
    keys = snapshot_endpoint_keys(snapshot)
    if not keys:
        return ""
    scores = sorted(
        ((len(keys & cat) / len(keys), product)
         for product, cat in _catalog_keys().items()),
        reverse=True)
    best, runner = scores[0], (scores[1] if len(scores) > 1 else (0.0, ""))
    if best[0] < MIN_COVERAGE or (best[0] - runner[0]) < MIN_MARGIN:
        return ""
    return best[1]


#: Where a harvested FortiWeb snapshot carries the name of the CHASSIS.
#: Section, endpoint, field — measured on the live store 2026-08-30: all four
#: snapshots of fortiweb12 (the box and its three ADOM rows) answer
#: ``fortiweb12`` here, and all four of fortiweb09 answer ``fortiweb09``.
CHASSIS_HOSTNAME_PATH = ("System", "global", "hostname")


def chassis_from_snapshot(snapshot: dict) -> str:
    """The hostname the BOX answered with, or "".

    This is a measurement, not a reading of the row's name. Operators name a
    per-ADOM row ``<device>@<adom>`` BY HAND and nothing enforces it, which is
    why :func:`models.appliance_name_parts` refuses to trust the text after
    '@' on its own. The snapshot does not have that problem — and it is the
    ONLY authority left for a de-registered device, whose appliance row (and
    with it the ``vdom`` that proved the suffix) no longer exists.
    """
    sec, endpoint, field = CHASSIS_HOSTNAME_PATH
    section = ((snapshot or {}).get("sections") or {}).get(sec)
    rows = section.get(endpoint) if isinstance(section, dict) else None
    if isinstance(rows, dict):
        rows = rows.get("results", rows)
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return ""
    for entry in rows:
        if isinstance(entry, dict) and str(entry.get(field) or "").strip():
            return str(entry[field]).strip()
    return ""


def chassis_from_appliance(appl) -> tuple:
    """``(chassis slug, adom)`` for an appliance row, or ``("", "")``.

    Delegates the split to :func:`models.appliance_name_parts` — the product's
    ONE answer to "what is this row called" — and accepts it only when it
    actually stripped something. ``vdom`` is ``root`` on every FortiWeb,
    whether or not ADOM mode is on (measured on fortiweb12/13, 2026-08-27), so
    a non-empty ``vdom`` proves nothing by itself.
    """
    from ..models import appliance_name_parts
    stem, adom = appliance_name_parts(appl)
    name = (getattr(appl, "name", "") or "").strip()
    if not adom or not stem or stem == name:
        return "", ""
    return slug_for(stem), adom


# --------------------------------------------------------------------------- #
#  Writers                                                                     #
# --------------------------------------------------------------------------- #

def _row(slug: str):
    from ..models_identity import DeviceIdentity
    return DeviceIdentity.query.filter_by(slug=slug).first()


def observe(appliance, *, serial: str = "", firmware: str = "",
            model: str = "", hw_type: str = "") -> dict:
    """Record what a live status call just told us about this appliance.

    A blank field never erases a known one: the four kinds answer with
    different payloads (FortiAuthenticator carries no hostname at all), so an
    absent field means "this payload did not say", not "the value is now
    empty". That is the same attestation rule ``firmware_probe`` applies to
    ``firmware_checked_at``.
    """
    from ..extensions import db
    from ..models_identity import DeviceIdentity

    name = getattr(appliance, "name", "") or ""
    slug = slug_for(name)
    if not slug:
        return {"ok": False, "detail": "unnamed appliance"}
    now = datetime.utcnow()
    row = _row(slug)
    created = row is None
    if created:
        row = DeviceIdentity(slug=slug, name=name, first_seen_at=now,
                             names=json.dumps([name]))
        db.session.add(row)

    history = row.name_history
    if name and name not in history:
        history.append(name)
        row.names = json.dumps(history)
    if name:
        row.name = name

    serial_changed = bool(serial) and (row.serial or "") != serial
    if serial:
        row.serial = serial
    if firmware:
        row.firmware = firmware
    if model:
        row.model = model
    if hw_type:
        row.hw_type = hw_type
    if getattr(appliance, "host", ""):
        row.host = appliance.host
    if getattr(appliance, "kind", ""):
        row.product = appliance.kind
    # Assigned, not or-ed with what is already stored: a LIVE appliance row is
    # the authority on which box it administers, so a row renamed out of its
    # ADOM must stop claiming the old chassis on the very next observation.
    chassis, adom = chassis_from_appliance(appliance)
    row.chassis_slug = chassis or slug
    row.adom = adom
    row.appliance_id = getattr(appliance, "id", None)
    # Seeing a device again un-retires it: a box that answers a status call is
    # not retired, whatever a stale timestamp says.
    row.retired_at = None
    row.last_seen_at = now
    db.session.commit()
    return {"ok": True, "created": created, "slug": slug,
            "serial": row.serial or "", "serial_changed": serial_changed}


def retire(name_or_slug: str, note: str = "") -> dict:
    """Mark a device retired. Never deletes: its backups and SoT versions stay
    on the server and this row is the only thing that can still name them."""
    from ..extensions import db
    slug = slug_for(name_or_slug) or name_or_slug
    row = _row(slug)
    if row is None:
        return {"ok": False, "detail": "no identity for %s" % slug}
    row.retired_at = row.retired_at or datetime.utcnow()
    row.appliance_id = None
    if note:
        row.note = ((row.note + "\n") if row.note else "") + note
    db.session.commit()
    return {"ok": True, "slug": slug,
            "retired_at": row.retired_at.isoformat(timespec="seconds")}


def reconcile() -> dict:
    """Give every appliance and every SoT device a row. Idempotent.

    Two passes, in this order on purpose: a LIVE appliance is authoritative
    about its own family, so it must win over a fingerprint of an old snapshot.
    """
    from ..extensions import db
    from ..models import Appliance
    from ..models_identity import DeviceIdentity
    from ..models_sot import SotVersion

    now = datetime.utcnow()
    created = adopted = 0

    live_slugs = set()
    for app_row in Appliance.query.order_by(Appliance.id).all():
        slug = slug_for(app_row.name or "")
        if not slug:
            continue
        live_slugs.add(slug)
        row = _row(slug)
        if row is None:
            row = DeviceIdentity(slug=slug, name=app_row.name or "",
                                 names=json.dumps([app_row.name or ""]),
                                 first_seen_at=now)
            db.session.add(row)
            created += 1
        row.name = app_row.name or row.name
        row.product = app_row.kind or row.product or ""
        row.host = app_row.host or row.host
        row.model = app_row.model or row.model
        row.firmware = app_row.firmware or row.firmware
        row.hw_type = app_row.hw_type or row.hw_type
        chassis, adom = chassis_from_appliance(app_row)
        row.chassis_slug = chassis or slug
        row.adom = adom
        row.appliance_id = app_row.id
        row.retired_at = None
        if getattr(app_row, "serial", "") and not row.serial:
            row.serial = app_row.serial
        row.last_seen_at = row.last_seen_at or now
    db.session.commit()

    # Devices the SoT remembers but no appliance row claims — the four
    # FortiWebs whose history is currently unreachable from any page.
    seen = {d for (d,) in db.session.query(SotVersion.device).distinct()}
    for slug in sorted(seen - live_slugs):
        if _row(slug) is not None:
            continue
        newest = (SotVersion.query.filter_by(device=slug)
                  .order_by(SotVersion.taken_at.desc()).first())
        product = ""
        try:
            from . import sot_store
            snap = sot_store.load(newest.id) if newest else None
            product = fingerprint_product(snap or {})
        except Exception:  # noqa: BLE001 — an unreadable blob must not block
            product = ""
        row = DeviceIdentity(
            slug=slug, name=slug, names=json.dumps([slug]),
            product=product,
            first_seen_at=(newest.taken_at if newest else now),
            last_seen_at=(newest.last_seen_at if newest else now),
            retired_at=now,
            note="adopted from SoT history: no appliance row exists")
        db.session.add(row)
        adopted += 1
    db.session.commit()

    # Pass three: rows with no chassis yet — everything written before the
    # column existed, plus the ones just adopted. Deliberately its OWN pass
    # rather than a line inside the two above, so it cannot depend on the
    # order in which peers happen to be created: the guard below asks whether
    # the chassis names a device THIS store already knows, and in pass two
    # half of them do not exist yet.
    filled = _resolve_chassis()
    return {"created": created, "adopted": adopted, "chassis": filled}


def _resolve_chassis() -> int:
    """Fill ``chassis_slug`` wherever it is still blank. Returns how many.

    Order of authority: the appliance row (free, and the operator authored
    it), then the device's own newest snapshot. A snapshot may cost an SFTP
    round trip for an evacuated payload — acceptable here because this only
    ever runs behind the *Reconcile identity* button, never in a page render.
    """
    from ..extensions import db
    from ..models import Appliance
    from ..models_identity import DeviceIdentity
    from ..models_sot import SotVersion

    pending = DeviceIdentity.query.filter(
        db.or_(DeviceIdentity.chassis_slug == "",
               DeviceIdentity.chassis_slug.is_(None))).all()
    known = {r.slug: r for r in DeviceIdentity.query.all()}
    filled = 0
    for row in pending:
        chassis = ""
        if row.appliance_id:
            appl = db.session.get(Appliance, row.appliance_id)
            if appl is not None:
                chassis, adom = chassis_from_appliance(appl)
                if adom:
                    row.adom = adom
        if not chassis:
            newest = (SotVersion.query.filter_by(device=row.slug)
                      .order_by(SotVersion.taken_at.desc()).first())
            if newest is not None:
                try:
                    from . import sot_store
                    chassis = slug_for(
                        chassis_from_snapshot(sot_store.load(newest.id) or {}))
                except Exception:  # noqa: BLE001 — an unreadable blob must
                    chassis = ""   # not block the rest of the reconciliation
        # A hostname that names no device of this family identifies NOTHING,
        # and adopting it anyway would file one box's backups under another
        # box's row. Two chassis with one hostname is a real configuration;
        # silently merging them is not a real answer.
        if chassis and chassis != row.slug:
            peer = known.get(chassis)
            if peer is None or (peer.product or "") != (row.product or ""):
                chassis = ""
        row.chassis_slug = chassis or row.slug
        filled += 1
    db.session.commit()
    return filled


# --------------------------------------------------------------------------- #
#  Readers                                                                     #
# --------------------------------------------------------------------------- #

def product_for_slug(slug: str) -> str:
    row = _row(slug)
    return (row.product or "") if row else ""


def for_slug(slug: str):
    return _row(slug)


def by_product(product: str = "", include_retired: bool = True) -> list:
    from ..models_identity import DeviceIdentity
    q = DeviceIdentity.query
    if product:
        q = q.filter_by(product=product)
    if not include_retired:
        q = q.filter(DeviceIdentity.retired_at.is_(None))
    return q.order_by(DeviceIdentity.retired_at.isnot(None),
                      DeviceIdentity.name).all()


def chassis_groups(product: str = "") -> list:
    """Identities folded onto the chassis whose stored artefacts they share.

    One entry per DEVICE, which is the unit the backup server stores. Sibling
    ADOM rows never carry a folder of their own — the box pushes one file
    under one name — so listing them beside the chassis prints N-1 permanent
    "never pushed" lines for a device that is pushing perfectly well.

    Rows whose chassis could not be established group as themselves. Nothing
    is dropped and nothing is merged on a guess.
    """
    groups = {}
    for row in by_product(product):
        g = groups.setdefault(row.chassis, {"chassis": row.chassis, "rows": []})
        g["rows"].append(row)
    out = []
    for key, g in groups.items():
        # The row that speaks for the box first: no ADOM, then the one whose
        # slug IS the chassis, then still-live over retired. Deterministic, so
        # the same device does not change identity between two renders.
        g["rows"].sort(key=lambda r: (bool(r.adom), r.slug != key,
                                      r.retired_at is not None, r.name))
        g["primary"] = g["rows"][0]
        g["folded"] = len(g["rows"]) - 1
        out.append(g)
    out.sort(key=lambda g: (g["primary"].retired_at is not None,
                            g["primary"].name))
    return out


def serial_groups(product: str = "") -> list:
    """Identities grouped by serial — one entry per physical/virtual chassis.

    The grouping is what makes a FortiWeb backup legible: the chassis and its
    per-ADOM rows share one serial, so the file belongs to the GROUP, never to
    one of its members.
    """
    groups: dict[str, dict] = {}
    for row in by_product(product):
        key = row.serial or ("?" + row.slug)
        g = groups.setdefault(key, {"serial": row.serial or "",
                                    "known": bool(row.serial), "rows": []})
        g["rows"].append(row)
    out = list(groups.values())
    for g in out:
        g["rows"].sort(key=lambda r: (r.retired_at is not None, r.name))
        g["primary"] = g["rows"][0]
    out.sort(key=lambda g: (not g["known"], g["primary"].name))
    return out
