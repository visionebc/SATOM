"""How this installation takes its software updates   [SATOM-UPDATE-METHODS]

Two ways have always existed side by side, on two different pages that knew
nothing of each other:

* **Git repository** -- ``git fetch`` of the update repository, applied by the
  privileged runner (``self_update.request_update``), by hand or by the
  reconciler in AUTO.
* **Signed packages** -- ``satom-update-<version>.tar.gz``, downloaded from the
  update feed or uploaded, verified against the trust store and applied by the
  same runner (``update_package_service.request_package_apply``).

An operator may use either or both (operator, 2026-11-24: "the user may upgrade
by both ways or by only one"). This module is the one answer to "which are
allowed here", stored in the replicated ``app_settings`` so both nodes of a
pair read the same choice, and the rule that lets the two coexist.

The rule is a VERSION rule, not a commit rule. Applying a package leaves a
local commit; the reconciler used to compare commits only (``HEAD..origin``),
so in AUTO it would park that commit and reset the node to the remote tip the
moment the remote moved -- a silent downgrade whenever the package was newer
than the remote. Now neither way moves a node to an older VERSION unless the
operator ticks the downgrade confirmation, and the reconciler HOLDS instead.

What a method switch does NOT govern: the HA link. A standby's ``origin`` is
its primary, and that is how a primary's update (git or package) reaches the
standby. It is replication, not an update method, so a standby always follows
its primary whatever is chosen here.

Unset means ``both``: an installation upgraded to this release behaves exactly
as it did before until the operator chooses.
"""
from __future__ import annotations

from pathlib import Path

KEY = "update.methods"
GIT, PACKAGES, BOTH = "git", "packages", "both"
CHOICES = (GIT, PACKAGES, BOTH)
DEFAULT = BOTH

LABELS = {
    GIT: "Git repository only",
    PACKAGES: "Signed packages only",
    BOTH: "Both",
}


class MethodDisabled(Exception):
    """The update was asked for by a method this installation has switched off."""


class DowngradeRefused(Exception):
    """The target is an older version and the operator did not confirm it."""


def _normal(value) -> str:
    v = str(value or "").strip().lower()
    return v if v in CHOICES else ""


def configured() -> str:
    """The stored choice, ``""`` when none was made. Readable with or without a
    Flask app context: the reconciler loop has none, and reads through psql
    like its deploy mode does."""
    try:
        from flask import has_app_context
        if has_app_context():
            from ..models import AppSetting
            return _normal(AppSetting.get(KEY))
    except Exception:  # noqa: BLE001 -- fall through to the loop-side read
        pass
    try:
        from . import reconciler
        return _normal(reconciler._setting(KEY))
    except Exception:  # noqa: BLE001
        return ""


def effective() -> str:
    return configured() or DEFAULT


def allows_git(method: str | None = None) -> bool:
    return (method or effective()) in (GIT, BOTH)


def allows_packages(method: str | None = None) -> bool:
    return (method or effective()) in (PACKAGES, BOTH)


def set_method(value: str) -> None:
    """Persist the choice (replicated). Writable only where Postgres is
    read-write: the caller checks for the primary, as for the deploy mode."""
    v = _normal(value)
    if not v:
        raise ValueError("update method must be one of: %s" % ", ".join(CHOICES))
    from ..models import AppSetting
    AppSetting.set(KEY, v)


# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------
def _up():
    from . import update_package_service as upkg
    return upkg.up


def running_version() -> str:
    """The VERSION file on disk, read now. Not ``app.version.APP_VERSION``:
    that is frozen at import, and the reconciler is a long-lived process that
    outlives the update it is judging."""
    from . import self_update as su
    try:
        return (Path(su.APP_DIR) / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def version_at(ref: str) -> str:
    """VERSION as committed at ``ref``; ``""`` when git cannot say."""
    if not ref:
        return ""
    from . import self_update as su
    try:
        r = su._git("show", "%s:VERSION" % ref, timeout=30)
    except Exception:  # noqa: BLE001
        return ""
    return (r.stdout or "").strip() if r.returncode == 0 else ""


def compare(a: str, b: str) -> int | None:
    """-1/0/1 like ``cmp``; ``None`` when either side is not a version. An
    unknown version never blocks anything: the guard is for the case it can
    prove, not a new way to refuse every update of a tree without VERSION."""
    up = _up()
    if not (a and b and up.VERSION_RE.match(a) and up.VERSION_RE.match(b)):
        return None
    return up.compare_versions(a, b)


def git_target(target: str) -> dict:
    """What moving this node to ``target`` would do to its version."""
    run, tgt = running_version(), version_at(target)
    c = compare(tgt, run)
    return {"running": run, "target": tgt, "cmp": c,
            "is_downgrade": c is not None and c < 0}


def check_git_request(target: str, *, role: str, origin: str,
                      allow_downgrade: bool = False,
                      method: str | None = None) -> dict:
    """Raise when a git update may not be queued; return :func:`git_target`.

    The standby is exempt: its remote is its primary (see the module note),
    and a code rollback (System Backup & Restore) is a recovery that already
    asks for its own confirmation.
    """
    if role == "standby" or origin == "code-rollback":
        return {}
    if not allows_git(method):
        raise MethodDisabled(
            "Updates from the git repository are switched off on this "
            "installation (Settings > Software Update > Update methods is "
            "'%s'). Apply a signed update package, or allow the git repository "
            "there." % LABELS[method or effective()])
    v = git_target(target)
    if v["is_downgrade"] and not allow_downgrade:
        raise DowngradeRefused(
            "The repository offers %s, OLDER than the running %s (a newer "
            "signed package is installed here). Nothing was queued. Tick the "
            "downgrade confirmation to go back to %s on purpose -- database "
            "migrations are not reversed." % (v["target"], v["running"], v["target"]))
    return v
