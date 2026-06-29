"""Release Notes (topbar banner modal) — same logic as the desktop app.

Ports ``app/ui/pages/release_notes_page.py`` + its pure ``services.release_notes``
harvester to the web. The whole UI lives in a Bootstrap modal opened from the
top banner (``partials/release_notes_modal.html`` + ``static/js/release_notes.js``);
this blueprint is the JSON backend it talks to.

Two buttons + three tabs, exactly like the standalone:

* **🔎 Scan from Fortinet** — auto-discover every FortiWeb version from
  docs.fortinet.com and harvest the Known/Resolved issue tables + the prose
  sections into the git-shared ``reports/_release_notes.json`` (httpx direct with
  a Firecrawl fallback). Admin-only (``USER_MANAGE``); optionally commits+pushes
  the corpus so the team shares it. Runs in a background thread; progress is
  written to a small status file so any of the 4 gunicorn workers can serve the
  poll.
* **⤓ Sync from git** — ``git pull`` then reload the corpus from disk (any
  logged-in user).
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
    Blueprint, current_app, jsonify, render_template, request,
)
from flask_login import current_user, login_required

from ..auth.decorators import require_permission
from ..models import Permission
from ..services import release_notes as rn
from ..services.audit import log_action

bp = Blueprint("release_notes", __name__, url_prefix="/release-notes")

_PRODUCT = "fortiweb"
_SCAN_FILE = "_release_notes_scan.json"   # progress/status (under data/, worker-shared)


# --------------------------------------------------------------------------- #
#  Corpus helpers                                                               #
# --------------------------------------------------------------------------- #
def _corpus_root() -> Path:
    """Where ``_release_notes.json`` lives. Production = the git-tracked
    ``reports/`` dir (shared with the team). Under tests it is isolated next to
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


def _load() -> rn.ReleaseNotesDB:
    return rn.load_db(root=_corpus_root()) or rn.ReleaseNotesDB(generated_at="")


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


# --------------------------------------------------------------------------- #
#  ⤓ Sync from git                                                              #
# --------------------------------------------------------------------------- #
@bp.route("/sync", methods=["POST"])
@login_required
@require_permission(Permission.VIEW)
def sync():
    log = ""
    try:
        from ..services.git_service import git_pull
        log = git_pull()
    except Exception as exc:  # noqa: BLE001 — offline / no remote is fine
        log = f"(git pull skipped: {exc})"
    db = _load()
    counts = _counts(db)
    try:
        log_action("release_notes.sync", target="git",
                   extra={"issues": counts["issues"], "sections": counts["sections"]})
    except Exception:  # noqa: BLE001
        pass
    return jsonify({"counts": counts, "log": log,
                    "message": (f"Ingested {counts['issues']} issues and "
                                f"{counts['sections']} sections from the shared reference."
                                if counts["issues"] else
                                "No release-notes reference found in git yet. Run a scan first.")})


# --------------------------------------------------------------------------- #
#  🔎 Scan from Fortinet (background thread + worker-shared progress file)       #
# --------------------------------------------------------------------------- #
def _do_scan(app, *, majors, use_direct, fc_endpoint, fc_key, publish, username):
    with app.app_context():
        path = _scan_path()
        root = _corpus_root()

        def emit(msg: str) -> None:
            _scan_append(path, msg)

        try:
            fetch = rn.make_fetcher(use_direct=use_direct,
                                    firecrawl_endpoint=fc_endpoint, firecrawl_key=fc_key)
            emit("Discovering versions…")
            all_versions = rn.discover_versions(fetch)
            emit(f"Discovered {len(all_versions)} versions.")
            versions = rn.select_versions(all_versions, majors)
            if not versions:
                raise RuntimeError("No versions matched. Check the majors or tick 'All'.")
            emit(f"Harvesting {len(versions)} version(s)…")
            new = rn.scan_release_notes(fetch, versions, on_progress=emit)
            merged = rn.merge_db(rn.load_db(root=root), new)
            stored = rn.save_db(merged, root=root)
            published = False
            if publish:
                try:
                    from ..services.git_service import git_publish
                    rel = os.path.relpath(str(stored), os.path.dirname(app.root_path))
                    log = git_publish(
                        f"chore(release-notes): scan {len(new.versions)} version(s) "
                        f"({len(new.issues)} issues)", [rel])
                    published = "fatal" not in (log or "").lower()
                    emit("Published corpus to git." if published
                         else "(git publish reported an issue — corpus saved locally)")
                except Exception as exc:  # noqa: BLE001 — git is best-effort
                    emit(f"(git publish failed: {exc})")
            counts = _counts(merged)
            result = {
                "scanned": len(new.versions), "new_issues": len(new.issues),
                "total_issues": counts["issues"], "total_sections": counts["sections"],
                "total_versions": counts["versions"], "published": published,
            }
            emit(f"✓ Scanned {len(new.versions)} version(s); {len(new.issues)} issue(s) parsed. "
                 f"Corpus now: {counts['issues']} issues, {counts['sections']} sections, "
                 f"{counts['versions']} versions.")
            st = _scan_read(path)
            st.update(running=False, result=result, error=None, finished_at=_now())
            _scan_write(path, st)
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
    majors = None if scan_all else [m.strip() for m in majors_raw.split(",") if m.strip()]
    if not scan_all and not majors:
        majors = ["7.0", "7.2", "7.4", "7.6", "8.0"]
    use_direct = bool(body.get("use_direct", True))
    use_fc = bool(body.get("use_firecrawl", True))
    fc_endpoint = (body.get("firecrawl_endpoint") or "").strip() if use_fc else ""
    fc_key = (body.get("firecrawl_key") or "").strip()
    publish = bool(body.get("publish", True))
    if not (use_direct or fc_endpoint):
        return jsonify({"error": "Enable at least one transport (direct or Firecrawl)."}), 400

    _scan_write(path, {"running": True, "lines": ["Starting scan…"], "result": None,
                       "error": None, "started_at": _now(),
                       "started_by": current_user.username})

    app = current_app._get_current_object()
    t = threading.Thread(
        target=_do_scan, args=(app,),
        kwargs=dict(majors=majors, use_direct=use_direct, fc_endpoint=fc_endpoint,
                    fc_key=fc_key, publish=publish, username=current_user.username),
        daemon=True)
    t.start()
    return jsonify({"started": True}), 202


@bp.route("/scan/status")
@login_required
@require_permission(Permission.USER_MANAGE)
def scan_status():
    return jsonify(_scan_read(_scan_path()))
