"""Web hosts: the certificates of the managed web servers, watched for expiry.

Every Plugin Studio server connection (a server prepared with satom-webctl)
is asked ``certs.list`` -- a read; nothing on the server changes. A
certificate that an ENABLED virtual host serves and that is about to expire
raises a bell notification to the administrators, once per stage:
30, 14 and 7 days left, and expired. A certificate nothing serves is not
news; a renewal (another certificate, another SHA-256) starts over.

A connection that cannot be read is a named error in the run, never "no
certificates": an unreachable server is exactly the one whose certificate
nobody is watching. Runs as the scheduled action ``webhost_cert_expiry``
(:mod:`scheduled_actions`), which :func:`ensure_scheduled` creates the first
time a server connection exists.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta

_log = logging.getLogger(__name__)

ACTION = "webhost_cert_expiry"
ACTION_NAME = "Web hosts -- certificate expiry check"
NOTIFIED_KEY = "webhost_certs.notified"
#: (stage, days_left below which it applies), the most urgent first.
STAGES = (("expired", 0), ("7", 7), ("14", 14), ("30", 30))
#: The panel app the notification links to (the Web hosts example).
PANEL_SLUG = "ex-web-panel"
KEEP_DAYS = 400


def stage_of(days_left: int) -> str:
    for stage, below in STAGES:
        if days_left < below:
            return stage
    return ""


def _notified() -> dict:
    from ..models import AppSetting
    try:
        val = json.loads(AppSetting.get(NOTIFIED_KEY) or "{}")
    except (TypeError, ValueError):
        val = {}
    return val if isinstance(val, dict) else {}


def _save_notified(seen: dict) -> None:
    from ..extensions import db
    from ..models import AppSetting
    cut = (datetime.utcnow() - timedelta(days=KEEP_DAYS)).isoformat(timespec="seconds")
    AppSetting.set(NOTIFIED_KEY, json.dumps({k: v for k, v in seen.items() if v >= cut},
                                            sort_keys=True))
    db.session.commit()


def _link(slug: str = "") -> str:
    """The Web Server Manager's certificates page of the server (2026-11-06:
    the manager replaced the Web hosts apps)."""
    return "/webserver/%s/certs" % slug if slug else "/webserver/"


def connections() -> list:
    """The server connections that can be asked unattended: a trusted host key
    and either the satom-webctl agent key or a shared service credential of
    the Web Server Manager that keeps its secret."""
    from . import studio_connections as SC
    from . import wsm
    out = []
    for c in SC.list_connections("server"):
        if SC.server_opts(c.slug).get("host_key") and (
                SC.has_secret(c.slug) or wsm.service_credential(c.slug) is not None):
            out.append(c)
    return out


def serving(cert: dict) -> list[str]:
    """``server/vhost`` of the ENABLED virtual hosts that use this certificate."""
    return ["%s/%s" % (u["server"], u["vhost"]) for u in cert.get("used_by") or []
            if u.get("enabled")]


def scan(*, notify: bool = True) -> dict:
    """Ask every server connection; notify each new stage once. NEVER raises."""
    from . import studio_connections as SC
    from . import wsm
    out = {"connections": 0, "certs": 0, "due": [], "errors": [], "notified": 0}
    try:
        conns = connections()
    except Exception as exc:  # noqa: BLE001
        out["errors"].append("cannot list the server connections: %s" % exc)
        return out
    seen = _notified()
    fresh = []
    for c in conns:
        out["connections"] += 1
        try:
            if not SC.has_secret(c.slug) and wsm.service_credential(c.slug) is not None:
                res = wsm.read_as_service(c, "certs.list")     # no agent: the manager's
            else:                                              # service credential reads
                res = SC.server_call(c, "certs.list")
        except Exception as exc:  # noqa: BLE001 -- one server must not stop the others
            out["errors"].append("%s: %s" % (c.slug, str(exc)[:300]))
            continue
        for cert in res.get("certs") or []:
            out["certs"] += 1
            hosts = serving(cert)
            if not hosts or cert.get("status") not in ("valid", "expiring", "expired"):
                continue
            stage = stage_of(int(cert.get("days_left") or 0))
            if not stage:
                continue
            label = cert.get("name") or cert.get("path") or "?"
            item = {"connection": c.slug, "cert": label, "subject": cert.get("subject") or "",
                    "days_left": int(cert.get("days_left") or 0), "stage": stage,
                    "hosts": hosts}
            out["due"].append(item)
            tag = "%s|%s|%s" % (c.slug, cert.get("sha256") or cert.get("path"), stage)
            if tag not in seen:
                fresh.append((tag, item))
    if notify and fresh:
        try:
            from ..models_notifications import Notification
            from . import notifications as notify_svc
            from .alerts import _admin_ids
            from ..branding import PRODUCTS
            admins = _admin_ids()
            # the Linux ADOM's bell (and Global's) when there is one; Global otherwise
            adom = "linux" if "linux" in PRODUCTS else "global"
            for tag, it in fresh:
                expired = it["stage"] == "expired"
                title = ("Certificate %s on %s %s" % (
                    it["cert"], it["connection"],
                    "has expired" if expired else "expires in %d day(s)" % it["days_left"]))
                body = ("%s (%s) is served by %s. Renew it in Web Server Manager > SSL "
                        "Certificates: Renew makes a new request on the server, the provider "
                        "signs it and the sites reload with the new certificate." % (
                            it["cert"], it["subject"] or "no common name",
                            ", ".join(it["hosts"][:10])))
                out["notified"] += notify_svc.push_many(
                    admins, title, kind=(Notification.KIND_ERROR if expired
                                         else Notification.KIND_WARNING),
                    body=body, link=_link(it["connection"]), product=adom)
                seen[tag] = datetime.utcnow().isoformat(timespec="seconds")
            _save_notified(seen)
        except Exception as exc:  # noqa: BLE001 -- a bell must not fail the check
            _log.warning("webhost_certs notify failed: %s", exc, exc_info=True)
            out["errors"].append("notification failed: %s" % exc)
    return out


def ensure_scheduled(by: str = "system:web-hosts") -> bool:
    """Create the daily check when it does not exist yet. True when created.
    Rows are data: one an administrator disabled or edited stays as it is."""
    from ..models import ScheduledAction, db
    from . import scheduled_actions as sa
    from .scheduler import compute_next_run
    try:
        if ScheduledAction.query.filter_by(action=ACTION).first() is not None:
            return False
        sched = {"time": "06:40"}
        row = ScheduledAction(
            name=ACTION_NAME, scope="admin", product="global", action=ACTION,
            targets="[]", params="{}", schedule_kind="daily", schedule=json.dumps(sched),
            enabled=True, catch_up=True, created_by=by)
        row.next_run = compute_next_run("daily", sched, tz=sa._configured_tz())
        db.session.add(row)
        db.session.commit()
        return True
    except Exception as exc:  # noqa: BLE001 -- never break the save that called it
        _log.warning("webhost_certs.ensure_scheduled failed: %s", exc, exc_info=True)
        try:
            from ..extensions import db as _db
            _db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
        return False
