"""``flask naming discover`` — Naming Discovery from the console.

The operator CLI (``satom get device naming``) runs this as the service
account, like ``flask knowledge``: it reads the configuration tree SATOM
already holds for a device (``data/reports/<slug>/_config.json``) and never
calls the device. The analysis is the one the Discovery tab draws
(:mod:`app.services.naming_discovery` through ``views.naming._load``), so the
console and the page cannot disagree. Read-only: it never runs the Naming
page's one-time settings migration, so it also answers on a standby. Output
is one JSON document.
"""
from __future__ import annotations

import json

import click
from flask.cli import AppGroup

naming_cli = AppGroup("naming", help="Naming Discovery: the convention the devices already follow.")

#: Exceptions listed per object type; the page lists them all, a terminal does not.
_EXCEPTIONS = 25


def _print(obj) -> None:
    click.echo(json.dumps(obj, indent=1, sort_keys=True, default=str))


def _is(t: dict, wanted: str) -> bool:
    """An object type is named by its key or by the label the page shows."""
    w = wanted.strip().lower()
    return w in (t["table"].lower(), str(t.get("label") or "").lower())


def _scheme(product: str):
    """table -> the Naming scheme pattern of its entry ('' when none)."""
    from .services import settings_store as store
    from .views.naming import _catalog, _scheme_key
    overrides = store.naming_overrides(product)
    defaults = {e.key: e.default for e in _catalog(product)}

    def pattern(table: str) -> str:
        key = _scheme_key(product, table)
        return (overrides.get(key) or "").strip() or defaults.get(key, "") or ""
    return pattern


def _table(t: dict, full: bool, scheme_pattern: str) -> dict:
    from .services import naming_discovery as nd
    exc = t.get("exceptions") or []
    check = nd.conformance(scheme_pattern, t.get("names") or []) if scheme_pattern else None
    return {
        "table": t["table"], "label": t.get("label") or t["table"],
        "section": t.get("section") or "", "status": t.get("status") or "",
        "main": t.get("main"), "conform": t.get("conform") or 0,
        "user": t.get("user") or 0, "factory": t.get("factory") or 0,
        "case": t.get("case"), "separator": t.get("separator"),
        "variants": [{"pattern": p["pattern"], "count": p["count"]}
                     for p in (t.get("patterns") or [])],
        "exceptions": exc if full else exc[:_EXCEPTIONS],
        "exceptions_total": len(exc),
        "linked": t.get("linked") or [],
        "scheme": scheme_pattern or None,
        "scheme_conform": check["conform"] if check else None,
    }


@naming_cli.command("discover")
@click.argument("device", required=False, default="")
@click.option("--product", default="", help="Fleet view of one product (no device).")
@click.option("--table", "table", default="", help="Only this object type; lists every exception.")
def discover_cmd(device, product, table):
    """One device's naming conventions, or the fleet view of a product."""
    from .extensions import db
    from .models import Appliance
    from .services import naming_discovery as nd
    from .views.naming import _device_products, _load, _table_labels

    products = [k for k, _ in _device_products()]
    if device:
        a = (Appliance.query.filter_by(name=device).first()
             or (db.session.get(Appliance, int(device)) if device.isdigit() else None))
        if a is None:
            _print({"error": "no appliance named %r" % device,
                    "appliances": sorted(x.name for x in Appliance.query.all())})
            raise SystemExit(1)
        _tree, analysis = _load(a, a.kind, _table_labels(a.kind))
        if analysis is None:
            _print({"mode": "device", "device": a.name, "product": a.kind,
                    "missing": True, "tables": []})
            return
        pattern = _scheme(a.kind)
        tables = [_table(t, bool(table), pattern(t["table"])) for t in analysis["tables"]
                  if not table or _is(t, table)]
        if table and not tables:
            _print({"error": "no object type %r on %s" % (table, a.name),
                    "tables": sorted(t["table"] for t in analysis["tables"])})
            raise SystemExit(1)
        _print({"mode": "device", "device": a.name, "product": a.kind, "missing": False,
                "generated_at": analysis.get("generated_at"),
                "user_objects": analysis.get("user_objects", 0),
                "factory_objects": analysis.get("factory_objects", 0),
                "tables": tables,
                "factory_source": (nd.factory_catalog().get(a.kind) or {}).get("measured_on", "")})
        return

    out = {"mode": "fleet", "products": []}
    for p in ([product] if product else products):
        if p not in products:
            _print({"error": "unknown product %r" % p, "products": products})
            raise SystemExit(1)
        fleet = Appliance.query.filter_by(kind=p).order_by(Appliance.name).all()
        if not fleet:
            continue
        labels = _table_labels(p)
        loaded = [(x, _load(x, p, labels)[1]) for x in fleet]
        analyses = [an for _x, an in loaded if an is not None]
        pattern = _scheme(p)
        out["products"].append({
            "product": p,
            "devices": [x.name for x, an in loaded if an is not None],
            "missing": [x.name for x, an in loaded if an is None],
            "tables": [{"table": r["table"], "label": r["label"], "section": r["section"],
                        "consensus": r["consensus"], "agree": r["agree"], "single": r["single"],
                        "scheme": pattern(r["table"]) or None,
                        "devices": [{"device": d["device"], "main": d["main"],
                                     "conform": d["conform"], "user": d["user"]}
                                    for d in r["devices"]]}
                       for r in nd.fleet_view(analyses) if not table or _is(r, table)],
        })
    _print(out)
