"""Release Notes (topbar banner modal) — same logic as the desktop app.

Ports ``app/ui/pages/release_notes_page.py`` + its pure ``services.release_notes``
harvester to the web. The whole UI lives in a Bootstrap modal opened from the
top banner (``partials/release_notes_modal.html`` + ``static/js/release_notes.js``);
this blueprint is the JSON backend it talks to.

One button + three tabs:

* **⟳ Reload corpus** — re-read the JSON from disk and report its age (any
  logged-in user). This blueprint does NOT touch git: see :func:`reload_corpus`.
* **Issues / Upgrade advisor / Notes** — read-only queries over the corpus via
  the pure ``release_notes`` functions (``filter_issues`` / ``advise``); no SQL
  projection is needed on the web (the JSON IS the source of truth here).

The corpus comes ONLY from signed packs (SATOM 3.0): the API pack that ships
with each release and the rolling knowledge pack (Software Update → Knowledge
packs, ``services.knowledge_fetch``). The docs.fortinet.com scan that used to
live here — its Scan / Discover buttons, routes and status file — was removed;
the crawler lives only in the knowledge harvester. Every answer carries
``knowledge`` (which pack the data came from and how old it is) so the modal
can say so and warn when it is older than 30 days.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from flask import Blueprint, g, jsonify, request, session
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import release_advisor as ra
from ..services import release_notes as rn
from ..services import release_corpus
from ..services import scout_config
from ..services.audit import log_action

bp = Blueprint("release_notes", __name__, url_prefix="/release-notes")

#: The ADOMs that offer the modal. FortiGate has release notes too
#: (``rn.SECTIONS_BY_PRODUCT``); its corpus is read by the other pages that
#: use it (Scout, the migration report).
_SUPPORTED_PRODUCTS = ("fortiweb", "fortiadc", "fortiauthenticator", "fortianalyzer")
_PRODUCT_LABEL = {"fortiweb": "FortiWeb", "fortiadc": "FortiADC",
                  "fortiauthenticator": "FortiAuthenticator",
                  "fortianalyzer": "FortiAnalyzer", "fortigate": "FortiGate"}


def _product() -> str:
    """The ADOM/product this request is scoped to. The Release-Notes modal is only
    surfaced in the product ADOMs listed in ``_SUPPORTED_PRODUCTS`` (see
    base.html), so anything else (the Global ADOM, or an unset session) safely
    defaults to FortiWeb. Every
    corpus read/scan is filtered by this so products never cross-contaminate
    (the shared ``reports/_release_notes.json`` holds all of them, tagged per row)."""
    p = getattr(g, "product", None) or session.get("product")
    return p if p in _SUPPORTED_PRODUCTS else "fortiweb"


# --------------------------------------------------------------------------- #
#  Corpus helpers                                                               #
# --------------------------------------------------------------------------- #
def _corpus_root() -> Path:
    """Where ``_release_notes.json`` lives — see :func:`app.services.release_corpus.root`.

    Moved out of this view when the Upgrade page started reading the same corpus
    to ask Scout about a firmware move. Kept as a thin alias because this module
    already names it in several places, and because a SECOND definition of
    "where the corpus is" fails silently: a loader pointed at an empty directory
    renders exactly like a corpus that had nothing to say."""
    return release_corpus.root()


def _load(product: str | None = None) -> rn.ReleaseNotesDB:
    """The corpus SCOPED to the active product — see
    :func:`app.services.release_corpus.load`."""
    return release_corpus.load(product or _product())


def _counts(db: rn.ReleaseNotesDB) -> dict:
    known = sum(1 for i in db.issues if i.status == "known")
    resolved = sum(1 for i in db.issues if i.status == "resolved")
    return {
        "issues": len(db.issues), "known": known, "resolved": resolved,
        "sections": len(db.sections), "versions": len(db.versions),
        "generated_at": db.generated_at or "",
    }


def _versions_desc(db: rn.ReleaseNotesDB) -> list[str]:
    return list(reversed(sorted(db.versions, key=rn.version_key)))


def _topics(db: rn.ReleaseNotesDB) -> list[str]:
    return sorted({i.topic for i in db.issues if i.topic})


def _knowledge() -> dict:
    """Which pack the corpus came from and how old it is (C7 freshness)."""
    from ..services import knowledge_fetch
    return knowledge_fetch.freshness()


def _fleet_builds(product: str) -> list[str]:
    """The firmware versions this user's appliances of ``product`` run.

    Offered in the version pickers next to the corpus versions, because "the
    build I run" is the question an operator opens this modal with — and a
    build with no harvested notes must SAY so instead of rendering an empty
    list that reads like a build with no issues."""
    from ..models import visible_appliances
    from ..services.upgrade_scout import normalise
    try:
        rows = visible_appliances().filter_by(kind=product).all()
    except Exception:  # noqa: BLE001 — the picker must not fail on the fleet
        return []
    return sorted({v for v in (normalise(getattr(a, "firmware", "")) for a in rows)
                   if v}, key=rn.version_key, reverse=True)


def _missing_reason(db: rn.ReleaseNotesDB, version: str | None) -> str:
    """Why a query over ``db`` has nothing to show for ``version`` — or ``''``.

    Non-empty only when the corpus holds NOTHING for the build asked about (or
    nothing at all when no build is named): the moment to point at the
    knowledge packs."""
    if version:
        if version in db.versions:
            return ""
    elif db.versions:
        return ""
    return rn.NO_NOTES


# --------------------------------------------------------------------------- #
#  Read-only query endpoints (Issues / Advisor / Notes)                          #
# --------------------------------------------------------------------------- #
@bp.route("/data")
@login_required
@require_permission(Permission.VIEW)
def data():
    """Summary + filter options for the modal's first paint."""
    product = _product()
    db = _load(product)
    have = set(db.versions)
    secmap = rn.sections_for(product)
    empty = _missing_reason(db, None)
    return jsonify({
        "product": product,
        "product_label": _PRODUCT_LABEL.get(product, "Fortinet"),
        "counts": _counts(db),
        "versions": _versions_desc(db),
        # Builds the fleet runs that the corpus does not hold: listed in the
        # pickers so choosing one explains itself (see _missing_reason).
        "fleet_missing": [v for v in _fleet_builds(product) if v not in have],
        "topics": _topics(db),
        "sections": [{"key": k, "label": rn.section_label(k, product)}
                     for k in rn.PROSE_SECTIONS if k in secmap],
        "is_admin": bool(current_user.can(Permission.USER_MANAGE)),
        "scout_enabled": scout_config.enabled(),
        "empty_reason": empty,
        "knowledge": _knowledge(),
    })


@bp.route("/issues")
@login_required
@require_permission(Permission.VIEW)
def issues():
    db = _load()
    version = request.args.get("version") or None
    rows = rn.filter_issues(
        db.issues,
        version=version,
        status=request.args.get("status") or None,
        topic=request.args.get("topic") or None,
        query=request.args.get("q") or None,
    )
    rows.sort(key=lambda i: (rn.version_key(i.version), i.status, i.bug_id))
    return jsonify({"issues": [asdict(i) for i in rows], "count": len(rows),
                    "empty_reason": "" if rows else _missing_reason(db, version)})


@bp.route("/notes")
@login_required
@require_permission(Permission.VIEW)
def notes():
    db = _load()
    version = request.args.get("version") or None
    section = request.args.get("section") or None
    q = (request.args.get("q") or "").lower().strip()
    out = []
    for s in db.sections:
        if version and s.version != version:
            continue
        if section and s.section != section:
            continue
        if q and q not in (s.content or "").lower() and q not in (s.title or "").lower():
            continue
        out.append(s)
    out.sort(key=lambda s: (rn.version_key(s.version), s.section))
    return jsonify({"sections": [asdict(s) for s in out[:60]], "count": len(out),
                    "empty_reason": "" if out else _missing_reason(db, version)})


@bp.route("/advise")
@login_required
@require_permission(Permission.VIEW)
def advise():
    current = (request.args.get("current") or "").strip()
    target = (request.args.get("target") or "").strip()
    if not current or not target:
        return jsonify({"error": "Pick a current and a target version."}), 400
    if current == target:
        return jsonify({"error": "Pick two different versions."}), 400
    db = _load()
    adv = rn.advise(db.issues, db.sections, current, target)
    return jsonify({
        "current": adv.current, "target": adv.target, "is_upgrade": adv.is_upgrade,
        "resolved": [asdict(i) for i in adv.resolved],
        "known_in_target": [asdict(i) for i in adv.known_in_target],
        "notes": [asdict(s) for s in adv.notes],
    })


@bp.route("/advisory")
@login_required
@require_permission(Permission.VIEW)
def advisory():
    """Scout's verdicts for a move, over the harvested upgrade prose.

    Separate from ``/advise`` on purpose. ``/advise`` answers "which bugs
    change hands", which is a diff and is always true of the corpus. This
    answers "what will stop this window", which is a JUDGEMENT — it has a rule
    set, a seal, and a coverage statement, and it can be switched off."""
    if not scout_config.enabled():
        return jsonify({"disabled": True,
                        "error": "Scout is switched off for this site."}), 503
    current = (request.args.get("current") or "").strip()
    target = (request.args.get("target") or "").strip()
    if not current or not target:
        return jsonify({"error": "Pick a current and a target version."}), 400
    if current == target:
        return jsonify({"error": "Pick two different versions."}), 400
    product = _product()
    adv = ra.analyse(_load(product).sections, current, target, product=product)
    return jsonify(dict(asdict(adv), knowledge=_knowledge()))


@bp.route("/scout-switch", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def scout_switch():
    """Turn the advisory on or off from where its absence is noticed.

    The same site setting the Scout settings pane writes — NOT a second flag.
    Two switches for one feature is how a product ends up with a pane that
    says ON over a page that is off."""
    body = request.get_json(silent=True) or {}
    want = bool(body.get("enabled"))
    scout_config.set_value("enabled", want)
    try:
        log_action("scout.switch", target="enabled" if want else "disabled")
    except Exception:  # noqa: BLE001
        pass
    return jsonify({"enabled": scout_config.enabled()})


# --------------------------------------------------------------------------- #
#  ⟳ Reload corpus (was: ⤓ Sync from git)                                       #
# --------------------------------------------------------------------------- #
@bp.route("/reload", methods=["POST"])
@login_required
@require_permission(Permission.VIEW)
def reload_corpus():
    """Re-read the corpus from disk and say how old it is.

    This was "⤓ Sync from git" until 2026-09-14, and it was wrong three ways
    at once — only the first of which was visible:

    1. **It could not publish or pull the corpus.** ``reports/`` is a symlink
       into ``data/reports/`` and ``/reports`` is in ``.gitignore``; git refuses
       the path outright (``fatal: pathspec ... is beyond a symbolic link``).
       True since the git SoT was retired on 2026-08-05.
    2. **It ran ``git pull`` over the RUNNING code tree, for VIEW.** The same
       operation is gated behind ``USER_MANAGE`` in ``settings.git_pull``, and
       is owned by ``satom-reconciler``. A read-only user could move the
       application's code out from under the workers. That is the reason this
       route had to change even if the corpus HAD been in git.
    3. **Its answer was false either way.** Nothing was ever 'ingested from the
       shared reference': :func:`_load` re-reads the JSON on every request, so
       the counts it printed were always the local file's.

    What the operator actually reached for is real: the counts on screen go
    stale while a pack import finishes in another worker, or while
    ``satom-ha-datasync`` drops a fresher corpus in. So this re-reads, and
    names where from and how old — the two facts a "sync" button owes you."""
    db = _load()
    counts = _counts(db)
    src = rn.db_path(_corpus_root())
    try:
        log_action("release_notes.reload", target="disk",
                   extra={"issues": counts["issues"], "sections": counts["sections"]})
    except Exception:  # noqa: BLE001
        pass
    if counts["issues"]:
        msg = (f"Reloaded {counts['issues']} issues and {counts['sections']} "
               f"sections from disk")
        msg += (f" (corpus written {counts['generated_at']})."
                if counts["generated_at"] else ".")
    else:
        msg = ("No corpus on this node yet — import a knowledge pack (Software "
               "Update → Knowledge packs). It is not fetched from git.")
    return jsonify({"counts": counts, "message": msg, "knowledge": _knowledge(),
                    "source": str(src), "generated_at": counts["generated_at"]})
