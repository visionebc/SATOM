"""Audit logging must never crash the operation it records.

``FortiWebOps`` writes happen from background/scheduled/CLI paths with NO Flask
request context (and no logged-in user). ``current_user`` then resolves to
``None`` and ``current_user.is_authenticated`` raises ``AttributeError`` — which
must be swallowed, not propagated into the device write.
"""
from __future__ import annotations


def test_log_action_outside_request_context_does_not_raise(app):
    from app.services.audit import log_action
    from app.models import AuditLog

    with app.app_context():            # app context only — NO request context
        log_action("config.create", target="waf/probe", detail="x")  # must not raise
        rows = AuditLog.query.filter_by(action="config.create").all()
        assert len(rows) == 1
        assert rows[0].user_id is None
        assert rows[0].username == "system"


def test_fortiwebops_dry_run_then_record_path_is_context_safe(app):
    """A real apply records a ChangeHistory row + audit entry from outside a
    request — exercising the exact path the live inject hit."""
    import types
    from app.services.fortiweb_ops import FortiWebOps

    with app.app_context():
        ops = FortiWebOps(types.SimpleNamespace(id=None))
        # _record is the audit/changelog sink; calling it directly proves it is
        # safe with no request context (the live crash was here).
        ops._record("delete", "waf/x", "zzz", None, None, False, "")  # must not raise
        from app.models import AuditLog
        assert AuditLog.query.filter_by(action="config.delete").count() == 1
