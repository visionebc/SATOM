"""``flask not-in-gui inventory`` — "Not in GUI, but in CLI" from the console.

Backend of ``satom get device not-in-gui``. The inventory is the one the
per-device page draws (:func:`app.services.not_in_gui.device_inventory`): the
API library's channels for the device's exact build plus the measured GUI
layouts. It never contacts the device — only the field VALUES are live, and
those stay on the page ("Read values over CLI"). Output is one JSON document.
"""
from __future__ import annotations

import json

import click
from flask.cli import AppGroup

not_in_gui_cli = AppGroup("not-in-gui", help='"Not in GUI, but in CLI": what each device has outside its GUI.')


def _print(obj) -> None:
    click.echo(json.dumps(obj, indent=1, sort_keys=True, default=str))


def _fields(rows) -> list:
    return [{"key": f["key"], "type": f.get("cli_type") or "",
             "lib_channel": f.get("lib_channel") or ""} for f in rows or []]


@not_in_gui_cli.command("inventory")
@click.argument("device")
@click.option("--endpoint", default="", help="Only this object (library key or CLI path).")
def inventory_cmd(device, endpoint):
    """Every object and field DEVICE's build has outside the Fortinet GUI."""
    from .extensions import db
    from .models import Appliance
    from .services import not_in_gui as nig

    a = (Appliance.query.filter_by(name=device).first()
         or (db.session.get(Appliance, int(device)) if device.isdigit() else None))
    if a is None:
        _print({"error": "no appliance named %r" % device,
                "appliances": sorted(x.name for x in Appliance.query.all())})
        raise SystemExit(1)
    inv = nig.device_inventory(a)
    doc = {
        "device": a.name, "id": a.id, "product": inv.get("product") or a.kind,
        "version": inv.get("version") or "", "complete": inv.get("complete"),
        "tree_measured": inv.get("tree_measured"), "note": inv.get("note") or "",
        "objects": [{"endpoint": o["endpoint"], "cli_path": o.get("cli_path") or "",
                     "kind": o.get("kind") or "", "fields": _fields(o.get("fields"))}
                    for o in inv.get("objects") or []],
        "fields": [{"endpoint": o["endpoint"], "cli_path": o.get("cli_path") or "",
                    "fields": _fields(o.get("fields"))}
                   for o in inv.get("fields") or []],
        "layout_pages": [{"endpoint": p["endpoint"], "page": p.get("page"),
                          "rest_not_in_gui": list(p.get("rest_not_in_gui") or [])}
                         for p in inv.get("layout_pages") or []],
        "absent": [{"endpoint": o["endpoint"], "label": o.get("label") or "",
                    "group": o.get("group") or "", "page": o.get("page"),
                    "why": o.get("why") or ""}
                   for o in inv.get("absent") or []],
        "page": "/appliances/%d/not-in-gui" % a.id,
    }
    if endpoint:
        want = endpoint.strip().lower()

        def hit(o):
            return want in (o["endpoint"].lower(), str(o.get("cli_path") or "").lower())
        for k in ("objects", "fields", "layout_pages", "absent"):
            doc[k] = [o for o in doc[k] if hit(o)]
        if not any(doc[k] for k in ("objects", "fields", "layout_pages", "absent")):
            known = sorted({o["endpoint"] for k in ("objects", "fields", "layout_pages", "absent")
                            for o in _endpoints(inv, k)})
            _print({"error": "nothing outside the GUI for %r on %s" % (endpoint, a.name),
                    "endpoints": known})
            raise SystemExit(1)
        doc["endpoint"] = endpoint
    _print(doc)


def _endpoints(inv, key):
    return [{"endpoint": o["endpoint"]} for o in inv.get(key) or []]
