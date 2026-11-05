"""SATOM data for Script Library scripts: ``satom.devices()``,
``satom.lb_lookup()``, ``satom.dns_lookup()`` in ``satom_script``.

WHY THIS SHAPE
--------------
The scripts runner (``satom-scripts.service``) has no database on purpose, and
the script runs in a jail with even less. So a script cannot read SATOM's
data itself; it asks the connection broker (outside the jail), and the broker
asks THIS module on the web side, over the loopback, with a grant:

1. ``grant`` -- when a run is queued (``script_library.enqueue_run``) for a
   script that declares SATOM data, the web side signs a grant: the person who
   runs it, the ADOM it was started from, the operations the script declares,
   and an expiry (the run's timeout + the queue wait). It goes into the 0600
   request file next to the wrapped connection tokens. The jail never sees it.
2. the broker (``studio_broker.satom_call``) POSTs one JSON object per call to
   ``/studio/scripts/_data/<op>`` on the loopback (gunicorn, not nginx).
3. ``answer`` checks the grant, loads the person, and answers AS THEM, in
   THAT ADOM: the same code and the same permission as the Plugin Studio step
   of the same name (``studio_dns``, ``studio_satom``). A person who lost the
   permission, was disabled, or left the ADOM gets a refusal, not data.

READ-ONLY BY CONSTRUCTION: every operation here reads SATOM's own caches (the
device list, the LB cache, SATOM's DNS resolvers). Nothing goes to a device
(NAF: the script is Presentation; it reads what the Collector left), and
nothing writes.
"""
from __future__ import annotations

import os
from typing import Any

from .script_manifest import SATOM_OPS

#: Salt of the signature: a grant is good for nothing else signed with the key.
SALT = "satom.script-data.v1"
#: Header the broker sends the grant in.
HEADER = "X-Satom-Script-Grant"
#: The permission each operation needs -- the one its Plugin Studio step needs.
PERMISSION = {"devices": None, "lb_lookup": "network.view", "dns_lookup": "network.view"}
#: Longest grant. A run is at most TIMEOUT_MAX + its queue wait.
MAX_TTL = 3600
#: Names per call: the DNS & LB Lookup page's own limit (dns_tool.MAX_ENTRIES).
#: More is refused, never cut; the SDK splits a longer list into calls.
MAX_ENTRIES = 50


class DataError(ValueError):
    """A call that is refused; the message goes back to the script."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _serializer():
    from flask import current_app
    from itsdangerous import URLSafeTimedSerializer
    return URLSafeTimedSerializer(current_app.config["SECRET_KEY"], salt=SALT)


def web_url() -> str:
    """Where the runner's broker reaches this server: gunicorn on the loopback
    (deploy/gunicorn.conf.py, ``SATOM_WEB_BIND``)."""
    bind = os.environ.get("SATOM_WEB_BIND") or "127.0.0.1:8000"
    if bind.startswith("unix:") or ":" not in bind:
        raise ValueError("SATOM data for scripts needs gunicorn on a TCP loopback "
                         "address (SATOM_WEB_BIND is %r)" % bind)
    host, port = bind.rsplit(":", 1)
    if host in ("0.0.0.0", "", "*"):
        host = "127.0.0.1"
    if host == "::":
        host = "[::1]"
    return "http://%s:%s" % (host, port)


def grant(user, ops: list[str], product: str | None, ttl: int) -> dict:
    """``{"url", "token"}`` for a run of a script that declares *ops*."""
    bad = [o for o in ops if o not in SATOM_OPS]
    if bad:
        raise ValueError("unknown SATOM data: %s" % ", ".join(bad))
    if user is None or not getattr(user, "id", None):
        raise ValueError("SATOM data is read for a person; this run has none")
    if product is None:
        from .product_scope import session_product
        product = session_product()
    token = _serializer().dumps({"u": int(user.id), "ops": sorted(set(ops)),
                                 "p": product or "", "ttl": int(min(max(ttl, 60), MAX_TTL))})
    return {"url": web_url(), "token": token}


def open_grant(token: str) -> dict:
    """The grant's content, or DataError 403."""
    from itsdangerous import BadSignature, SignatureExpired
    s = _serializer()
    try:
        data, _ts = s.loads(token or "", max_age=MAX_TTL, return_timestamp=True)
    except SignatureExpired:
        raise DataError("the SATOM data grant of this run expired", 403) from None
    except BadSignature:
        raise DataError("invalid SATOM data grant", 403) from None
    try:
        s.loads(token, max_age=int(data.get("ttl") or 60))
    except SignatureExpired:
        raise DataError("the SATOM data grant of this run expired", 403) from None
    return data


def _entries(args: dict) -> list[str]:
    from . import studio_dns as DNS
    raw = args.get("entries")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)) or not raw:
        raise DataError("entries: a name, an address, or a list of them")
    from . import dns_tool
    limit = min(MAX_ENTRIES, dns_tool.MAX_ENTRIES)
    entries, dropped = DNS.clean_entries([str(x) for x in raw])
    if dropped:
        raise DataError("at most %d different names per call (%d given): satom_script splits "
                        "a longer list by itself; a direct call must too"
                        % (limit, len(entries) + dropped))
    if not entries:
        raise DataError("no valid name or address in entries")
    return entries


def _flag(args: dict, key: str) -> bool:
    v = args.get(key)
    return v is True or str(v or "").strip().lower() in ("1", "true", "yes", "on")


def answer(token: str, op: str, args: Any) -> dict:
    """The answer to one ``satom.<op>(**args)`` call of a run."""
    from ..extensions import db
    from ..models import User
    from . import studio_dns as DNS
    from . import studio_flow as F
    from . import studio_satom as S
    g = open_grant(token)
    if op not in SATOM_OPS:
        raise DataError("unknown SATOM data %r" % op, 404)
    if op not in (g.get("ops") or []):
        raise DataError("this script does not declare SATOM data %r (add it to "
                        "SATOM['satom'] in main.py, or to the script's settings)" % op, 403)
    if not isinstance(args, dict):
        raise DataError("arguments must be a JSON object")
    user = db.session.get(User, int(g.get("u") or 0))
    if user is None or not user.is_active:
        raise DataError("the person this run reads for no longer exists or is disabled", 403)
    perm = PERMISSION.get(op)
    if perm and not user.can(perm):
        raise DataError("satom.%s needs the %s permission, which %s does not hold"
                        % (op, perm, user.username), 403)
    try:
        with DNS.as_user(user, g.get("p") or ""):
            if op == "devices":
                rows = S.select_appliances(
                    S._fleet_rows(), product=str(args.get("product") or ""),
                    zone=str(args.get("zone") or ""), line=str(args.get("line") or ""),
                    department=str(args.get("department") or ""),
                    maintenance=str(args.get("maintenance") or "include"))
                if args.get("resolve", True) not in (False, "no", "false", "0"):
                    S.resolve_names(rows)
                return {"rows": rows, "count": len(rows)}
            if op == "lb_lookup":
                from . import dns_tool
                entries = _entries(args)
                lb_rows = dns_tool.fleet_lb_rows()
                res = DNS.lb_lookup(entries, lb_rows, exact=_flag(args, "exact"))
                res["cached_rows"] = len(lb_rows)
                return res
            entries = _entries(args)
            return DNS.dns_lookup(entries, ttl=_flag(args, "ttl"))
    except F.FlowError as exc:
        raise DataError(str(exc)) from None


def summary(op: str, res: dict) -> str:
    """One line for the run record (the broker's log)."""
    if op == "devices":
        return "%d device(s)" % len(res.get("rows") or [])
    if op == "lb_lookup":
        return "%d match(es), %d member(s)" % (len(res.get("rows") or []),
                                                len(res.get("members") or []))
    return "%d name(s), %d without an answer" % (len(res.get("entries") or []),
                                                 len(res.get("unresolved") or []))
