"""Service checks: is a SERVICE really working — not merely its port open.

Operator request 2026-11-17: "a more specific monitoring — a web page with its
screenshot and certificate, the health of a service like an IPsec VPN, HTTP,
HTTPS, other ports and protocols … SSL VPN, OpenVPN, IPsec, WireGuard, and the
certificate of each; the port can be up while the service is not."

* :class:`ServiceCheck` — one watched endpoint. ``kind`` is a protocol of
  :mod:`app.services.service_probes`; ``target_json`` its validated target,
  WITHOUT secrets (OpenVPN static keys, WireGuard private / preshared keys live
  in the vault or Fernet-encrypted app settings, ``svccheck.<id>.<field>``,
  services.prefixed_secret). ``product`` is the ADOM it was created in, which
  is what scopes the list (services.product_scope).
* :class:`ServiceCheckResult` — one run: status, latency, the protocol facts,
  the certificate facts when the protocol exposes one, and for web kinds the
  screenshot file name (``data/service_checks/<id>/<file>.png``).

Free targets by nature (a partner's VPN head-end is not in the inventory), so
creating or editing one needs ``monitoring.probe_free`` (net_guard), and every
socket a run opens is authorised by net_guard first.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


def _loads(raw, default):
    try:
        v = json.loads(raw or "")
    except (TypeError, ValueError):
        return default
    return v if isinstance(v, type(default)) else default


class ServiceCheck(db.Model):
    __tablename__ = "service_checks"

    STATUSES = ("up", "degraded", "down", "error", "unknown")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    kind = db.Column(db.String(24), nullable=False, index=True)
    #: validated target (services.service_probes.validate_target), secrets out
    target_json = db.Column(db.Text, nullable=False, default="{}")
    #: names of the target fields kept as secrets (svccheck.<id>.<field>)
    secret_fields = db.Column(db.String(200), nullable=False, default="")
    #: ADOM the check belongs to (services.product_scope)
    product = db.Column(db.String(32), nullable=False, default="global", index=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    #: minutes between runs; a multiple of the 3-minute monitor sweep
    interval_min = db.Column(db.Integer, nullable=False, default=3)
    timeout_s = db.Column(db.Integer, nullable=False, default=10)
    #: certificate warning threshold (degraded at or below)
    cert_warn_days = db.Column(db.Integer, nullable=False, default=21)
    #: web kinds: take a screenshot every N minutes (0 = never)
    screenshot_every_min = db.Column(db.Integer, nullable=False, default=60)
    #: optional FortiGate whose tunnel table is read for an IPsec check
    fgt_appliance_id = db.Column(db.Integer, nullable=True)
    fgt_tunnel = db.Column(db.String(120), nullable=False, default="")
    #: alerts muted for this check (it still runs and records)
    muted = db.Column(db.Boolean, nullable=False, default=False)

    last_status = db.Column(db.String(16), nullable=False, default="unknown")
    last_summary = db.Column(db.Text, nullable=False, default="")
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_changed_at = db.Column(db.DateTime, nullable=True)
    last_shot_at = db.Column(db.DateTime, nullable=True)
    last_shot = db.Column(db.String(120), nullable=False, default="")

    created_by = db.Column(db.String(80), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @property
    def target(self) -> dict:
        return _loads(self.target_json, {})

    @property
    def secret_list(self) -> list[str]:
        return [f for f in (self.secret_fields or "").split(",") if f]

    def as_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "kind": self.kind,
            "target": self.target, "secret_fields": self.secret_list,
            "product": self.product, "enabled": bool(self.enabled),
            "interval_min": self.interval_min, "timeout_s": self.timeout_s,
            "cert_warn_days": self.cert_warn_days,
            "screenshot_every_min": self.screenshot_every_min,
            "fgt_appliance_id": self.fgt_appliance_id, "fgt_tunnel": self.fgt_tunnel,
            "muted": bool(self.muted),
            "last_status": self.last_status, "last_summary": self.last_summary,
            "last_checked_at": _iso(self.last_checked_at),
            "last_changed_at": _iso(self.last_changed_at),
            "last_shot_at": _iso(self.last_shot_at), "has_shot": bool(self.last_shot),
            "created_by": self.created_by,
        }


class ServiceCheckResult(db.Model):
    __tablename__ = "service_check_results"
    __table_args__ = (db.Index("ix_svcres_check_at", "check_id", "at"),)

    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey("service_checks.id", ondelete="CASCADE"),
                         nullable=False)
    at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(16), nullable=False)
    latency_ms = db.Column(db.Float, nullable=True)
    summary = db.Column(db.Text, nullable=False, default="")
    detail_json = db.Column(db.Text, nullable=False, default="{}")
    cert_json = db.Column(db.Text, nullable=False, default="")
    cert_days_left = db.Column(db.Integer, nullable=True)
    shot = db.Column(db.String(120), nullable=False, default="")

    @property
    def detail(self) -> dict:
        return _loads(self.detail_json, {})

    @property
    def cert(self) -> dict | None:
        return _loads(self.cert_json, {}) or None

    def as_dict(self) -> dict:
        return {"id": self.id, "at": _iso(self.at), "status": self.status,
                "latency_ms": self.latency_ms, "summary": self.summary,
                "detail": self.detail, "cert": self.cert,
                "cert_days_left": self.cert_days_left, "has_shot": bool(self.shot)}


def _iso(dt):
    return dt.isoformat(timespec="seconds") + "Z" if dt else None
