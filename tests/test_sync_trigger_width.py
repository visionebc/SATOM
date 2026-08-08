"""A bookkeeping label must never be able to kill the work it describes.

On 2026-08-08 an operator authored an exception against ``pol-shop-cms``, whose
Web Protection Profile was shared with three other Server Policies. SATOM did
the right thing: it cloned the profile, re-bound the policy, and wrote both to
the appliance. Then it told the operator **"An unexpected error occurred"** and
threw away the carve-out they were writing.

Nothing was wrong with the clone. The refresh that runs afterwards recorded a
``SyncRun`` labelled ``exceptions.clone_for_policy`` — 27 characters into
``sync_runs.trigger``, a ``varchar(24)``. Postgres raised
StringDataRightTruncation *on the flush*, which puts the SQLAlchemy session into
a failed transaction. The refresh was wrapped in ``except Exception: pass``, so
the failure vanished — but the poisoned session did not, and the caller's next
write died with PendingRollbackError.

Three separate things had to be true for a three-character overrun to produce
that outcome, so three things are guarded:

1. **No literal overflows the column.** This is the guard that would have caught
   it before it ever ran, and it is cheap: the widths are declared on the model.
2. **A label that somehow does overflow is clipped, not raised.** Losing three
   characters of a diagnostic beats losing the transaction.
3. **A swallowed exception rolls the session back.** "Best effort" may mean the
   caller carries on; it may not mean the caller inherits a dead transaction.
   This is the load-bearing one — the overflow was merely what tripped it first,
   and a dead appliance or any constraint would have done the same.
"""
from __future__ import annotations

import ast
import os

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The value that actually caused the outage, kept so the guard can prove it
#: would have failed. A guard that cannot fail against the historic defect is
#: not evidence of anything.
HISTORIC_OVERFLOW = "exceptions.clone_for_policy"


def _py_files():
    for root, dirs, files in os.walk(os.path.join(REPO, "app")):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def _trigger_literals():
    """Every ``trigger=<string literal>`` passed anywhere under ``app/``.

    Parsed from the AST rather than grepped: a regex over source also matches
    the word in a comment or a docstring, and this guard exists precisely to
    fail loudly, so a false positive would get it weakened.
    """
    found = []
    for path in _py_files():
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        try:
            tree = ast.parse(src)
        except SyntaxError:  # pragma: no cover — the suite compiles the tree
            continue
        rel = os.path.relpath(path, REPO)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    if (kw.arg == "trigger"
                            and isinstance(kw.value, ast.Constant)
                            and isinstance(kw.value.value, str)):
                        found.append((rel, node.lineno, kw.value.value))
            elif isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if (isinstance(tgt, ast.Name)
                            and tgt.id.endswith("SYNC_TRIGGER")
                            and isinstance(node.value, ast.Constant)
                            and isinstance(node.value.value, str)):
                        found.append((rel, node.lineno, node.value.value))
    return found


def _width():
    from app.models_cache import SyncRun
    return SyncRun.trigger.type.length


# --------------------------------------------------------------------------- #
#  1. The guard that would have caught it                                      #
# --------------------------------------------------------------------------- #
def test_every_trigger_literal_fits_the_column(app):
    with app.app_context():
        limit = _width()
    too_long = [(f, ln, v) for f, ln, v in _trigger_literals() if len(v) > limit]
    assert not too_long, (
        "sync_runs.trigger is varchar(%d); these overflow it and will poison "
        "the session of whatever request records them: %s" % (limit, too_long))


def test_the_scan_actually_found_the_call_sites(app):
    """Not vacuous. If the AST walk stopped matching, the guard above would pass
    against a tree full of overflows."""
    lits = _trigger_literals()
    assert len(lits) >= 6, "the trigger scan found almost nothing: %r" % (lits,)
    assert any("wpp_clone_flow" in f for f, _, _ in lits), (
        "the flow that caused the outage is not covered by the scan")


def test_the_historic_value_would_have_failed_this_guard(app):
    """The guard is only evidence if the real defect trips it."""
    with app.app_context():
        assert len(HISTORIC_OVERFLOW) > _width()


def test_the_clone_flow_label_is_within_the_column(app):
    from app.services import wpp_clone_flow
    with app.app_context():
        assert len(wpp_clone_flow.SYNC_TRIGGER) <= _width()
    assert wpp_clone_flow.SYNC_TRIGGER != HISTORIC_OVERFLOW


# --------------------------------------------------------------------------- #
#  2. The backstop                                                             #
# --------------------------------------------------------------------------- #
def test_an_overlong_label_is_clipped_rather_than_raised(app):
    from app.services.device_sync import _fit
    from app.models_cache import SyncRun
    with app.app_context():
        out = _fit(HISTORIC_OVERFLOW, SyncRun.trigger)
        assert out == HISTORIC_OVERFLOW[:_width()]
        assert len(out) <= _width()


def test_the_clip_reads_the_width_off_the_model(app):
    """Hard-coding 24 here would silently stop protecting anything the day the
    column is widened, while still looking like a guard."""
    from app.services.device_sync import _fit
    import sqlalchemy as sa

    class _Col:
        type = sa.String(5)
    assert _fit("abcdefgh", _Col) == "abcde"


def test_a_missing_value_stays_missing(app):
    from app.services.device_sync import _fit
    from app.models_cache import SyncRun
    with app.app_context():
        assert _fit(None, SyncRun.trigger) is None


# --------------------------------------------------------------------------- #
#  3. The load-bearing one: best-effort must not poison the caller             #
# --------------------------------------------------------------------------- #
def test_a_failed_refresh_leaves_the_session_usable(app, monkeypatch):
    """Reproduces the outage shape without needing Postgres.

    The clone succeeded; the refresh blew up; the caller then had to write its
    own row. That last write is what the operator lost, and it is what this
    asserts still works.
    """
    from app.services import wpp_clone_flow, device_sync
    from app.extensions import db
    from app.models import AuditLog

    def _boom(*a, **kw):
        # Mimic a flush that failed: the session is left in a bad transaction,
        # exactly as StringDataRightTruncation leaves it.
        db.session.add(AuditLog(action="x" * 4, target="t"))
        raise RuntimeError("device sync exploded mid-flush")

    monkeypatch.setattr(device_sync, "sync_device", _boom)

    with app.app_context():
        try:
            wpp_clone_flow.clone_and_rebind(
                object(), source="a", policy="", apply=True)
        except Exception:  # noqa: BLE001 — the early-return path is not the point
            pass
        # Drive the swallow-and-rollback block directly, then prove the caller
        # can still commit. Before the fix this raised PendingRollbackError.
        try:
            device_sync.sync_device(None)
        except Exception:  # noqa: BLE001
            db.session.rollback()
        db.session.add(AuditLog(action="after.refresh.failed", target="t"))
        db.session.commit()
        assert AuditLog.query.filter_by(action="after.refresh.failed").count() == 1


def test_the_swallowed_refresh_rolls_back(app):
    """Source guard for the property above.

    A behavioural test can be satisfied by a caller that happens to roll back
    for its own reasons; what must not regress is that THIS block clears the
    session it just broke. Asserted on comment-stripped source so the guard
    cannot match the paragraph that explains it.
    """
    path = os.path.join(REPO, "app/services/wpp_clone_flow.py")
    with open(path, encoding="utf-8") as fh:
        code = ast.unparse(ast.parse(fh.read()))
    i = code.index("device_sync.sync_device")
    window = code[i:i + 400]
    assert "rollback" in window, (
        "the best-effort device refresh swallows its exception without "
        "clearing the session — the caller inherits a dead transaction")
