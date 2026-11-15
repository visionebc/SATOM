#!/usr/bin/env python3
"""Re-measure app/registry/data/gui_endpoint_alias.json against FortiWeb devices.

GETs only. For every alias: the cmdb collection answers 200, the objects the
GUI API lists (when gui_bound.safe_api lets SATOM read it) are the same names
cmdb lists, and every renamed key exists in the cmdb rows or in the build's
measured fields. Run it when a new firmware build is crawled:

    sudo -u satom bash -c 'set -a; . /opt/satom/.env; set +a; \
        venv/bin/python deploy/verify_gui_alias.py <appliance id> [...]'

Exit 1 when an alias no longer holds on a device.
"""
from __future__ import annotations

import re
import sys

sys.path.insert(0, ".")


def _rows(resp):
    try:
        body = resp.json()
    except ValueError:
        return None
    res = body.get("results") if isinstance(body, dict) else body
    if isinstance(res, dict):
        res = res.get("datas") if isinstance(res.get("datas"), list) else [res]
    return [r for r in (res or []) if isinstance(r, dict)]


def check(appliance) -> list:
    from app.clients.fortiweb import FortiWebClient
    from app.services import api_library, gui_alias, gui_bound, gui_store
    client = FortiWebClient(appliance)
    ver = (re.search(r"(\d+\.\d+\.\d+)", gui_store.firmware_of(appliance) or "") or [None, ""])[1]
    t = gui_alias.table()
    bad = []
    entries = [(k, v, False) for k, v in t["aliases"].items()] \
        + [(k, v, True) for k, v in t["pages"].items()]
    for name, al, is_page in entries:
        resp = client.get("/api/v2.0/cmdb/" + al["cmdb"])
        crows = _rows(resp) if resp.status_code == 200 else None
        line = "%-55s -> %-45s cmdb %s" % (name, al["cmdb"], resp.status_code)
        if crows is None:
            bad.append(name)
            print(line + "  FAIL: cmdb does not answer")
            continue
        if not is_page and gui_bound.safe_api("api:" + name):
            g = client.get("/api/v2.0/" + name)
            grows = _rows(g) if g.status_code == 200 else None
            if grows is not None:
                gn = sorted(str(r.get("name") or "") for r in grows)
                cn = sorted(str(r.get("name") or r.get("id") or "") for r in crows)
                if gn != cn:
                    bad.append(name)
                    print(line + "  FAIL: GUI lists %d object(s), cmdb %d" % (len(gn), len(cn)))
                    continue
        fields = set((api_library.fields_at("fortiweb", al["cmdb"], ver).get("fields") or {}))
        for r in crows:
            fields |= set(r)
        missing = [ck for ck in (al.get("keys") or {}).values() if fields and ck not in fields]
        if missing:
            bad.append(name)
            print(line + "  FAIL: keys not on this build: %s" % ", ".join(missing))
            continue
        print(line + "  ok (%d row(s), %s)" % (len(crows), al.get("confidence")))
    for ep in t["live"]:
        ok = gui_bound.read_rows(appliance, "api:" + ep, client=client)
        print("%-55s live %s" % (ep, "ok (%d row(s))" % len(ok) if ok is not None else "FAIL"))
        if ok is None:
            bad.append(ep)
    return bad


def main(argv) -> int:
    from app import create_app
    app = create_app()
    with app.app_context():
        from app.extensions import db
        from app.models import Appliance
        failed = []
        for aid in argv or []:
            a = db.session.get(Appliance, int(aid))
            print("=== %s (%s)" % (a.name, a.fw_version or "?"))
            failed += check(a)
        return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
