"""Offline harvester: build per-(product,line) field schemas for guided provisioning.

Authoritative source = a LIVE GET from a reference appliance of that line
(exact field names + value-inferred types). Enrichment = Firecrawl of the
FortiWeb CLI-reference docs (labels / help / enum options) — wired as the
extension hook, gated by ``FIRECRAWL_ENRICH=1`` and never fatal. Writes
``data/field_schemas/<product>/<line>/<object>.json`` plus a ``_default``
fallback. Idempotent and non-destructive: existing files are preserved (so
hand-curated seeds survive); pass ``--force`` to overwrite. NOT run at request
time.

Usage (on LXC 248, repo root, venv):
    set -a && . ./.env && set +a
    PYTHONPATH=. venv/bin/python -m scripts.build_field_catalog --product fortiweb
    # add --force to regenerate existing schema files
"""
from __future__ import annotations

import argparse
import json
import os

from app.services import field_catalog as fc
from app.services import provisioning as prov

# (line, appliance-name) reference sources. Add rows for new lines/products.
SOURCES = {"fortiweb": [("8.0", "fw1"), ("7.6", "fw2")]}

# Firecrawl (LAN, no auth). Enrichment is opt-in (gated) to keep the harvest fast.
FIRECRAWL = os.environ.get("FIRECRAWL_URL", "http://192.0.2.66:3002")

# Fields known to be mandatory that a bare GET can't tell us are required.
REQUIRED_HINTS = {"dns": {"primary"}, "ntp": {"mode"}}

_READONLY_EXACT = {"_id", "systemTime", "time"}


def is_readonly_name(name: str) -> bool:
    return name in _READONLY_EXACT or name.endswith("_val")


def fields_from_live_object(live: dict) -> list:
    """Field dicts from a live cmdb object: skip readonly/_val/_id; infer types.

    An int/str field that has a sibling ``<name>_val`` is an enum => ``bool``
    when the companion reads enable/disable, else ``select`` (options unknown
    here, filled by docs)."""
    out = []
    for name, value in live.items():
        if is_readonly_name(name):
            continue
        ftype = fc.infer_type(value)
        companion = live.get(f"{name}_val")
        if companion is not None and ftype in ("number", "text"):
            ftype = "bool" if str(companion).lower() in ("enable", "disable") else "select"
        out.append({
            "name": name, "label": name.replace("-", " ").replace("_", " ").title(),
            "type": ftype, "required": False, "default": "",
            "help": "", "group": "Basic", "options": [],
        })
    return out


def merge_doc(fields: list, doc: dict) -> list:
    """Overlay doc-sourced label/help/options onto live-derived fields."""
    for f in fields:
        d = doc.get(f["name"])
        if not d:
            continue
        if d.get("label"):
            f["label"] = d["label"]
        if d.get("help"):
            f["help"] = d["help"]
        if d.get("options"):
            f["options"] = d["options"]
            if f["type"] in ("text", "number"):
                f["type"] = "select"
    return fields


def firecrawl_doc(obj_key: str) -> dict:
    """Best-effort field metadata from FortiWeb docs. Returns {} on any failure.

    Gated by FIRECRAWL_ENRICH (off by default). The markdown->{field:{label,
    help,options}} parser is the documented extension point; today it returns {}
    so the live GET stays authoritative."""
    if not os.environ.get("FIRECRAWL_ENRICH"):
        return {}
    try:
        import httpx
        url = "https://docs.fortinet.com/document/fortiweb/8.0.0/cli-reference"
        r = httpx.post(f"{FIRECRAWL}/v1/scrape",
                       json={"url": url, "formats": ["markdown"]}, timeout=40)
        if r.status_code != 200:
            return {}
        # TODO: parse the object's field table out of the markdown. Live GET
        # already yields correct names+types, so {} still gives a usable schema.
        return {}
    except Exception:
        return {}


def _live_object(appliance, endpoint_urn: str) -> dict:
    return appliance.build_client()._safe_one(endpoint_urn)


def _write_if(path: str, payload: dict, force: bool) -> bool:
    if os.path.exists(path) and not force:
        return False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    return True


def build(product: str = "fortiweb", force: bool = False) -> None:
    from app.models import Appliance
    from app.registry import loader

    reg = loader.load_registry()
    specs = prov.PROVISION_CATALOG
    default_written: set = set()
    for line, appliance_name in SOURCES.get(product, []):
        appliance = Appliance.query.filter_by(name=appliance_name).first()
        if appliance is None:
            print(f"! {appliance_name} not registered — skipping line {line}")
            continue
        print(f"== line {line} via {appliance_name} ==")
        for spec in specs:
            urn = reg.get(spec.endpoint or "")
            if not urn:
                print(f"  - {spec.key}: endpoint {spec.endpoint!r} not in registry, skip")
                continue
            try:
                live = _live_object(appliance, urn)
            except Exception as exc:
                print(f"  - {spec.key}@{line}: live GET failed ({type(exc).__name__}); skip")
                continue
            if not live:
                print(f"  - {spec.key}@{line}: empty live object; skip")
                continue
            fields = merge_doc(fields_from_live_object(live), firecrawl_doc(spec.key))
            req = REQUIRED_HINTS.get(spec.key, set())
            for f in fields:
                f["required"] = f["name"] in req
            readonly = [k for k in live if is_readonly_name(k)]
            schema = {
                "object": spec.key, "endpoint": spec.endpoint, "label": spec.label,
                "product": product, "line": line, "singleton": spec.singleton,
                "readonly": readonly, "fields": fields,
                "source": f"live:{appliance_name}@{line}", "generated_at": "2026-06-28",
            }
            wrote = _write_if(os.path.join(fc.SCHEMA_ROOT, product, line, f"{spec.key}.json"),
                              schema, force)
            print(f"  {'+' if wrote else '=' } {spec.key}@{line} ({len(fields)} fields)"
                  f"{'' if wrote else ' [kept existing]'}")
            if spec.key not in default_written:
                d = dict(schema, line="_default", source=f"default<-{appliance_name}@{line}")
                _write_if(os.path.join(fc.SCHEMA_ROOT, product, "_default", f"{spec.key}.json"),
                          d, force)
                default_written.add(spec.key)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--product", default="fortiweb")
    ap.add_argument("--force", action="store_true", help="overwrite existing schema files")
    args = ap.parse_args()
    from app import create_app
    app = create_app()
    with app.app_context():
        print(f"Building field catalog for product={args.product} (force={args.force}) …")
        build(args.product, force=args.force)
    print("Done.")


if __name__ == "__main__":
    main()
