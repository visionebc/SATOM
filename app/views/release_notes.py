"""Release Notes (topbar banner modal) — same logic as the desktop app.

Ports ``app/ui/pages/release_notes_page.py`` + its pure ``services.release_notes``
harvester to the web. The whole UI lives in a Bootstrap modal opened from the
top banner (``partials/release_notes_modal.html`` + ``static/js/release_notes.js``);
this blueprint is the JSON backend it talks to.

Two buttons + three tabs, exactly like the standalone:

* **🔎 Scan from Fortinet** — auto-discover every FortiWeb version from
  docs.fortinet.com and harvest the Known/Resolved issue tables + the prose
  sections into ``reports/_release_notes.json`` (httpx direct with a Firecrawl
  fallback). Admin-only (``USER_MANAGE``). Runs in a background thread; progress
  is written to a small status file so any of the 4 gunicorn workers can serve
  the poll.
* **⟳ Reload corpus** — re-read the JSON from disk and report its age (any
  logged-in user). This blueprint does NOT touch git: see :func:`reload_corpus`.
* **Issues / Upgrade advisor / Notes** — read-only queries over the corpus via
  the pure ``release_notes`` functions (``filter_issues`` / ``advise``); no SQL
  projection is needed on the web (the JSON IS the source of truth here).
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Blueprint, current_app, g, jsonify, render_template, request, session,
)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import release_advisor as ra
from ..services import release_notes as rn
from ..services import scout_config
from ..services import notifications as notify
from ..services.audit import log_action

bp = Blueprint("release_notes", __name__, url_prefix="/release-notes")

_SUPPORTED_PRODUCTS = ("fortiweb", "fortiadc")
_SCAN_FILE = "_release_notes_scan.json"   # progress/status (under data/, worker-shared)


def _product() -> str:
    """The ADOM/product this request is scoped to. The Release-Notes modal is only
    surfaced in the FortiWeb and FortiADC ADOMs (see base.html), so anything else
    (the Global ADOM, or an unset session) safely defaults to FortiWeb. Every
    corpus read/scan is filtered by this so the two products never cross-contaminate
    (the shared ``reports/_release_notes.json`` holds both, tagged per row)."""
    p = getattr(g, "product", None) or session.get("product")
    return p if p in _SUPPORTED_PRODUCTS else "fortiweb"


# --------------------------------------------------------------------------- #
#  Corpus helpers                                                               #
# --------------------------------------------------------------------------- #
def _corpus_root() -> Path:
    """Where ``_release_notes.json`` lives. Production = the ``reports/`` dir,
    which is a symlink into the gitignored ``data/reports/`` — NOT version
    controlled and NOT shared by git (see :func:`reload_corpus`); the standby
    receives it through ``satom-ha-datasync``. Under tests it is isolated next to
    the throwaway SQLite DB so the suite never reads/writes the live corpus —
    same isolation trick as the firmware repository."""
    cfg = current_app.config.get("RELEASE_NOTES_DIR")
    if cfg:
        p = Path(cfg)
        p.mkdir(parents=True, exist_ok=True)
        return p
    if current_app.config.get("TESTING"):
        uri = current_app.config.get("SQLALCHEMY_DATABASE_URI", "") or ""
        if uri.startswith("sqlite:///"):
            p = Path(os.path.dirname(uri[len("sqlite:///"):])) / "reports"
            p.mkdir(parents=True, exist_ok=True)
            return p
    return rn.reports_root()


def _load(product: str | None = None) -> rn.ReleaseNotesDB:
    """The corpus SCOPED to the active product. Issues/sections are filtered by
    ``product`` and the version list is derived from the surviving rows (not the
    flat cross-product ``db.versions``), so a FortiADC ADOM never sees FortiWeb
    rows and vice-versa — even though both live in the one shared JSON."""
    product = product or _product()
    db = rn.load_db(root=_corpus_root()) or rn.ReleaseNotesDB(generated_at="")
    issues = [i for i in db.issues if i.product == product]
    sections = [s for s in db.sections if s.product == product]
    versions = sorted({i.version for i in issues} | {s.version for s in sections},
                      key=rn.version_key)
    return rn.ReleaseNotesDB(generated_at=db.generated_at, versions=versions,
                             issues=issues, sections=sections)


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


# --------------------------------------------------------------------------- #
#  Scan status file (shared across the 4 gunicorn workers)                       #
# --------------------------------------------------------------------------- #
_SCAN_STALE_AFTER = 1800.0   # a "running" scan older than this (s) is treated as
#  dead — the worker/thread crashed without clearing the flag — so a stuck lock can
#  never permanently trap the user at HTTP 409. The longest real scan is well under.


def _scan_path() -> str:
    # Isolate the worker-shared progress file the same way the corpus is isolated
    # (see _corpus_root) so the test suite never reads/writes the production data/
    # file — and a stale production lock can never fail an unrelated test.
    if current_app.config.get("RELEASE_NOTES_DIR") or current_app.config.get("TESTING"):
        d = str(_corpus_root())
    else:
        d = os.path.join(os.path.dirname(current_app.root_path), "data")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, _SCAN_FILE)


def _scan_is_stale(st: dict) -> bool:
    """A scan flagged ``running`` but whose ``started_at`` is older than
    ``_SCAN_STALE_AFTER`` is presumed dead (thread crashed mid-scan)."""
    if not st.get("running"):
        return True
    started = st.get("started_at")
    if not started:
        return False
    try:
        t0 = datetime.fromisoformat(started)
    except (TypeError, ValueError):
        return False
    if t0.tzinfo is None:
        t0 = t0.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - t0).total_seconds() > _SCAN_STALE_AFTER


def _scan_read(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"running": False, "lines": [], "result": None, "error": None}


def _scan_write(path: str, state: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, ensure_ascii=False)
    os.replace(tmp, path)


def _scan_append(path: str, line: str) -> None:
    st = _scan_read(path)
    st.setdefault("lines", []).append(line)
    _scan_write(path, st)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
#  Read-only query endpoints (Issues / Advisor / Notes)                          #
# --------------------------------------------------------------------------- #
@bp.route("/data")
@login_required
@require_permission(Permission.VIEW)
def data():
    """Summary + filter options for the modal's first paint."""
    db = _load()
    scan = _scan_read(_scan_path())
    return jsonify({
        "counts": _counts(db),
        "versions": _versions_desc(db),
        "topics": _topics(db),
        "sections": [{"key": k, "label": rn.SECTION_LABEL.get(k, k)}
                     for k in rn.PROSE_SECTIONS],
        "is_admin": bool(current_user.can(Permission.USER_MANAGE)),
        "scan_running": bool(scan.get("running")),
        "scout_enabled": scout_config.enabled(),
        "firecrawl_default": rn.FIRECRAWL_LAN_DEFAULT,
    })


@bp.route("/issues")
@login_required
@require_permission(Permission.VIEW)
def issues():
    db = _load()
    rows = rn.filter_issues(
        db.issues,
        version=request.args.get("version") or None,
        status=request.args.get("status") or None,
        topic=request.args.get("topic") or None,
        query=request.args.get("q") or None,
    )
    rows.sort(key=lambda i: (rn.version_key(i.version), i.status, i.bug_id))
    return jsonify({"issues": [asdict(i) for i in rows], "count": len(rows)})


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
    return jsonify({"sections": [asdict(s) for s in out[:60]], "count": len(out)})


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
    return jsonify(asdict(adv))


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
    stale while another gunicorn worker finishes a scan, or while
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
        msg += (f" (harvested {counts['generated_at']})."
                if counts["generated_at"] else ".")
    else:
        msg = ("No corpus on this node yet — an admin has to run a scan here. "
               "It is not fetched from git: each node harvests its own.")
    return jsonify({"counts": counts, "message": msg,
                    "source": str(src), "generated_at": counts["generated_at"]})


# --------------------------------------------------------------------------- #
#  🔎 Scan from Fortinet (background thread + worker-shared progress file)       #
# --------------------------------------------------------------------------- #
def _notify_scan_done(user_id, product, *, ok, result=None, error=None, lines=None):
    """Raise a bell notification for the admin who launched the scan, so a scan
    that finishes after they closed the modal ('Run in background') still surfaces.
    Product-scoped so it lights the bell only in the matching ADOM. Best-effort."""
    plabel = {"fortiweb": "FortiWeb", "fortiadc": "FortiADC"}.get(product, "Fortinet")
    tail = "\n".join((lines or [])[-8:]) or None
    if ok:
        r = result or {}
        unread = r.get("unreadable") or []
        if unread:
            # A scan that harvested something AND failed to read a published
            # section is not a success: the corpus is now silently incomplete
            # for those versions, which is the exact failure mode that let the
            # 8.0.7 docset go unnoticed. Warn, and name the versions.
            vs = sorted({u.get("version", "?") for u in unread}, key=rn.version_key)
            notify.push(user_id,
                        (f"{plabel} release-notes scan INCOMPLETE — "
                         f"{len(unread)} published section(s) unreadable "
                         f"({', '.join(vs)})"),
                        kind="warning", body=tail, product=product)
            return
        title = (f"{plabel} release-notes scan done — "
                 f"{r.get('scanned', 0)} version(s), {r.get('new_issues', 0)} new issue(s)")
        notify.push(user_id, title, kind="success", body=tail, product=product)
    else:
        notify.push(user_id, f"{plabel} release-notes scan failed",
                    kind="error", body=(error or tail), product=product)


def _do_scan(app, *, product, majors, use_direct, fc_endpoint, fc_key,
             username, user_id, versions=None):
    with app.app_context():
        path = _scan_path()
        root = _corpus_root()

        def emit(msg: str) -> None:
            _scan_append(path, msg)

        try:
            fetch = rn.make_fetcher(use_direct=use_direct,
                                    firecrawl_endpoint=fc_endpoint, firecrawl_key=fc_key)
            if versions:
                # The operator ticked an explicit list (the Discover flow). Do NOT
                # re-derive it: discovery is a suggestion, the ticks are the order.
                picked = list(versions)
                emit(f"Harvesting {len(picked)} selected version(s): "
                     f"{', '.join(picked)}")
            else:
                emit(f"Discovering {product} versions…")
                all_versions = rn.discover_versions(fetch, product=product)
                emit(f"Discovered {len(all_versions)} versions.")
                picked = rn.select_versions(all_versions, majors)
                if not picked:
                    raise RuntimeError("No versions matched. Check the majors or tick 'All'.")
                emit(f"Harvesting {len(picked)} version(s)…")
            new = rn.scan_release_notes(fetch, picked, product=product, on_progress=emit)
            merged = rn.merge_db(rn.load_db(root=root), new)
            stored = rn.save_db(merged, root=root)
            # No git leg. The corpus is not version-controlled (reports/ is a
            # symlink into the gitignored data/reports/), so the publish this
            # used to attempt could only ever log a failure — which is exactly
            # what it did, on every scan, since 2026-08-05. The standby gets
            # this file from satom-ha-datasync within 5 minutes.
            emit(f"Corpus written to {stored}.")
            counts = _counts(merged)
            unreadable = [asdict(u) for u in new.unreadable]
            if unreadable:
                emit(f"✗ {len(unreadable)} PUBLISHED section(s) could not be read — "
                     "the corpus is INCOMPLETE for those versions. "
                     "This usually means docs.fortinet.com changed renderer again.")
            result = {
                "scanned": len(new.versions), "new_issues": len(new.issues),
                "total_issues": counts["issues"], "total_sections": counts["sections"],
                "total_versions": counts["versions"],
                "unreadable": unreadable,
            }
            emit(f"✓ Scanned {len(new.versions)} version(s); {len(new.issues)} issue(s) parsed. "
                 f"Corpus now: {counts['issues']} issues, {counts['sections']} sections, "
                 f"{counts['versions']} versions.")
            st = _scan_read(path)
            st.update(running=False, result=result, error=None, finished_at=_now())
            _scan_write(path, st)
            _notify_scan_done(user_id, product, ok=True, result=result,
                              lines=st.get("lines"))
            try:
                log_action("release_notes.scan", target=username,
                           extra={"scanned": result["scanned"],
                                  "new_issues": result["new_issues"]})
            except Exception:  # noqa: BLE001
                pass
        except Exception as exc:  # noqa: BLE001
            st = _scan_read(path)
            st.update(running=False, error=f"{type(exc).__name__}: {exc}",
                      finished_at=_now())
            _scan_write(path, st)
            _notify_scan_done(user_id, product, ok=False,
                              error=f"{type(exc).__name__}: {exc}",
                              lines=st.get("lines"))


@bp.route("/discover", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def discover():
    """The versions docs.fortinet.com actually publishes, each marked against the
    corpus we already hold.

    ONE fetch (~1 s) — the version history lives in the seed page. This exists so
    the operator ticks a real list instead of typing ``major.minor`` blind: the
    old free-text field could not express 'just 8.0.7' at all (the filter matched
    on major.minor, so a full version matched nothing and the scan died), and it
    sat next to an 'All discovered' checkbox that silently overrode it."""
    product = _product()
    body = request.get_json(silent=True) or {}
    use_direct = bool(body.get("use_direct", True))
    use_fc = bool(body.get("use_firecrawl", True))
    fc_endpoint = (body.get("firecrawl_endpoint") or "").strip() if use_fc else ""
    fc_key = (body.get("firecrawl_key") or "").strip()
    if not (use_direct or fc_endpoint):
        return jsonify({"error": "Enable at least one transport (direct or Firecrawl)."}), 400
    fetch = rn.make_fetcher(use_direct=use_direct, firecrawl_endpoint=fc_endpoint,
                            firecrawl_key=fc_key)
    try:
        found = rn.discover_versions(fetch, product=product)
    except Exception as exc:  # noqa: BLE001 — network is the expected failure
        return jsonify({"error": f"{type(exc).__name__}: {exc}"}), 502
    if not found:
        return jsonify({"error": "Discovery returned nothing — docs.fortinet.com "
                                 "unreachable, or the seed version was retired."}), 502
    have = set(_load(product).versions)
    rows = [{"version": v, "major": rn.major_of(v), "in_corpus": v in have}
            for v in sorted(found, key=rn.version_key, reverse=True)]
    return jsonify({"product": product, "versions": rows, "count": len(rows),
                    "new": sum(1 for r in rows if not r["in_corpus"])})


@bp.route("/scan", methods=["POST"])
@login_required
@require_permission(Permission.USER_MANAGE)
def scan():
    path = _scan_path()
    if not _scan_is_stale(_scan_read(path)):
        return jsonify({"error": "A scan is already running."}), 409

    body = request.get_json(silent=True) or {}
    scan_all = bool(body.get("all"))
    majors_raw = (body.get("majors") or "").strip()
    raw_versions = body.get("versions")
    versions = None
    if isinstance(raw_versions, list):
        versions = [str(v).strip() for v in raw_versions if str(v).strip()]
        if not versions:
            return jsonify({"error": "Pick at least one version to scan."}), 400
    # Two controls that disagree must not resolve silently. Before this, ticking
    # 'All discovered' while 8.0 sat typed in the box scanned all 59 versions and
    # said nothing — the operator had every reason to believe they had asked for
    # one line. Make the contradiction impossible to submit instead.
    if versions is not None and (scan_all or majors_raw):
        return jsonify({"error": "Pick EITHER an explicit version list OR the "
                                 "majors/All filter — not both."}), 400
    if versions is None and scan_all and majors_raw:
        return jsonify({"error": "'All discovered' and a majors filter contradict "
                                 "each other. Untick All, or clear the box."}), 400
    majors = None if scan_all else [m.strip() for m in majors_raw.split(",") if m.strip()]
    if versions is None and not scan_all and not majors:
        majors = ["7.0", "7.2", "7.4", "7.6", "8.0"]
    use_direct = bool(body.get("use_direct", True))
    use_fc = bool(body.get("use_firecrawl", True))
    fc_endpoint = (body.get("firecrawl_endpoint") or "").strip() if use_fc else ""
    fc_key = (body.get("firecrawl_key") or "").strip()
    # NB: a legacy client may still post "publish": true. It is ignored on
    # purpose rather than rejected — the corpus cannot be published (see
    # reload_corpus), and failing an otherwise valid scan over a dead flag
    # would turn a cosmetic staleness into an outage.
    if not (use_direct or fc_endpoint):
        return jsonify({"error": "Enable at least one transport (direct or Firecrawl)."}), 400

    product = _product()
    _scan_write(path, {"running": True, "lines": [f"Starting {product} scan…"],
                       "result": None, "error": None, "started_at": _now(),
                       "started_by": current_user.username, "product": product})

    app = current_app._get_current_object()
    t = threading.Thread(
        target=_do_scan, args=(app,),
        kwargs=dict(product=product, majors=majors, versions=versions,
                    use_direct=use_direct,
                    fc_endpoint=fc_endpoint, fc_key=fc_key,
                    username=current_user.username, user_id=current_user.id),
        daemon=True)
    t.start()
    return jsonify({"started": True}), 202


@bp.route("/scan/status")
@login_required
@require_permission(Permission.USER_MANAGE)
def scan_status():
    return jsonify(_scan_read(_scan_path()))
