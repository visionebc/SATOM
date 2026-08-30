"""Who a managed device IS — and who it *was*.

Everything else SATOM knows about an appliance hangs off ``appliances.id`` with
``ON DELETE CASCADE``: hardware, certificates, probes, snapshots. De-registering
a device therefore destroys its record along with it, which is exactly backwards
for the question an operator asks about a file sitting on the backup server —
*whose is this?* The four FortiWebs whose 24 SoT versions are unreachable from
any page today are that defect in production.

So identity does not live in a column on ``appliances`` and has **no foreign
key**: a row here outlives the appliance it describes, the same way
``sot_version`` outlives it by indexing on the device NAME rather than its id.
Retiring a device sets :attr:`DeviceIdentity.retired_at`; nothing is deleted.

The identity is the **serial number**, not the name. A name is a label an
operator typed and can change; the serial is what the chassis answers with. One
serial with three names is one box that was renamed twice — and, on FortiWeb,
one chassis whose per-ADOM rows (``fortiweb12@adom_prod`` …) all report the
SAME serial, which is precisely why a backup taken from that chassis covers
every one of them and must never be presented as belonging to a single ADOM.

Rows are keyed by :attr:`slug` (``slugify(name)``) because that is how the SoT
store, ``data/reports/`` and the backup server's per-device folders all key the
same device; the display name is carried alongside. A serial that has not been
observed yet is stored as the empty string, never as a fabricated placeholder:
"we have not asked this box" and "this box has no serial" are different facts.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


class DeviceIdentity(db.Model):
    __tablename__ = "device_identity"

    id = db.Column(db.Integer, primary_key=True)

    #: ``slugify(name)`` — the key the SoT store, ``data/reports/`` and the
    #: backup server folders all agree on. Unique: SATOM device names are.
    slug = db.Column(db.String(128), unique=True, nullable=False, index=True)
    #: The display name as SATOM last knew it.
    name = db.Column(db.String(128), nullable=False, default="")
    #: What the chassis calls itself. "" = never observed (not "none").
    serial = db.Column(db.String(64), nullable=False, default="", index=True)
    #: ADOM / device family: fortiweb | fortiadc | fortianalyzer |
    #: fortiauthenticator. "" only when it could not be established.
    product = db.Column(db.String(32), nullable=False, default="", index=True)

    #: The slug of the CHASSIS whose stored artefacts this row shares.
    #:
    #: A FortiWeb in ADOM mode is one appliance row per ADOM, but it has ONE
    #: flash partition and ONE ``execute backup`` that contains every ADOM
    #: (models.chassis_device_row says the same thing about firmware). So the
    #: file on the backup server belongs to the BOX, and three ADOM rows are
    #: three views of one artefact rather than three artefacts. Equal to
    #: :attr:`slug` for a plain device, and for an unresolved row — an
    #: unresolved row is its own chassis, never somebody else's.
    #:
    #: Recorded rather than derived on read for two reasons: the appliance row
    #: that carries ``vdom`` is GONE by the time anybody asks about a
    #: de-registered device, and the other authority is the device's own
    #: snapshot, whose payload may be off-box (one SFTP round trip is fine on
    #: a button press and is not fine per row of a page render).
    chassis_slug = db.Column(db.String(128), nullable=False, default="",
                             index=True)
    #: The ADOM this row administers; "" when it administers the box itself.
    adom = db.Column(db.String(64), nullable=False, default="")

    model = db.Column(db.String(128), nullable=True)
    firmware = db.Column(db.String(64), nullable=True)
    hw_type = db.Column(db.String(16), nullable=True)
    host = db.Column(db.String(253), nullable=True)

    #: The appliance row this described when last seen. Deliberately a plain
    #: integer: a ForeignKey would cascade this row away with the device, which
    #: is the whole failure this table exists to prevent.
    appliance_id = db.Column(db.Integer, nullable=True)

    #: Every name this slug has been known by, JSON list, oldest first.
    names = db.Column(db.Text, nullable=False, default="[]")

    first_seen_at = db.Column(db.DateTime, nullable=False,
                              default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime, nullable=False,
                             default=datetime.utcnow, index=True)
    #: Set when the appliance is de-registered. NULL = still managed. The row
    #: is never deleted — a retired device is the one whose old backups need a
    #: name most.
    retired_at = db.Column(db.DateTime, nullable=True, index=True)
    note = db.Column(db.Text, nullable=False, default="")

    @property
    def name_history(self) -> list:
        try:
            out = json.loads(self.names or "[]")
            return [str(n) for n in out] if isinstance(out, list) else []
        except (TypeError, ValueError):
            return []

    @property
    def chassis(self) -> str:
        """The slug this row's stored artefacts are filed under.

        Falls back to its own slug, never to a blank: a row whose chassis was
        never established has to group as ITSELF, because the alternative —
        every unresolved row sharing one empty key — merges unrelated devices
        into a single line and reports one device's backups as another's.
        """
        return self.chassis_slug or self.slug

    @property
    def retired(self) -> bool:
        return self.retired_at is not None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "slug": self.slug, "name": self.name,
            "serial": self.serial or "", "product": self.product or "",
            "chassis": self.chassis, "adom": self.adom or "",
            "model": self.model or "", "firmware": self.firmware or "",
            "hw_type": self.hw_type or "", "host": self.host or "",
            "appliance_id": self.appliance_id,
            "names": self.name_history,
            "retired": self.retired,
            "first_seen": self.first_seen_at.isoformat(timespec="seconds")
                          if self.first_seen_at else "",
            "last_seen": self.last_seen_at.isoformat(timespec="seconds")
                         if self.last_seen_at else "",
            "retired_at": self.retired_at.isoformat(timespec="seconds")
                          if self.retired_at else "",
            "note": self.note or "",
        }
