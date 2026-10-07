"""Knowledge packs from the online feed (contract C7).

Release notes, the Scout advisory, upgrade paths and the signature metadata
no longer come from vendor web sites: SATOM imports them from signed API packs.
Two lanes carry the same sections:

* ``api_pack``  — pinned to a SATOM release, shipped inside the update
  (``api-packs/``) and imported by the update runner;
* ``knowledge`` — rolling, published whenever the knowledge harvester's
  content changes. Its feed is a small ``latest.json`` naming the newest pack.

This module reads that feed, compares it with the newest knowledge pack this
node has imported, downloads the pack into the API-pack upload directory and
imports it through :mod:`app.services.api_pack` — where the signature is
verified against the knowledge lane's keys. The feed is an address book, not a
reason to trust anything: a forged feed can at most point at a pack no trusted
key signed, and that pack is refused by the import.

The HTTP client is the system-upgrade feed's (``deploy/upgrade_feed.py``
through :mod:`app.services.update_package_service`): HTTPS only (redirects
included), the process proxy environment, the system CA store, a size cap.

What runs when is the operator's choice (``knowledge.fetch_mode``):

``off``              the scheduled action does nothing;
``notify``           it checks and tells the administrators when a newer pack exists;
``download``         it also downloads (and verifies the sha256 of) the pack;
``download_import``  it also imports it (the default).

The buttons on Software Update and ``satom execute knowledge fetch`` act
whatever the mode is: a person asked. Only the PRIMARY imports — a standby's
database is read-only and receives the knowledge by replication.

Air-gapped networks never reach the feed: the pack is downloaded elsewhere and
uploaded under Software Update → API library packs (``/self-update/apipack/upload``).
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

#: Default feed: the ``knowledge`` release of the public repository (a
#: prerelease that is never "Latest"). Overridable per node (a mirror, a
#: staging feed) with the ``knowledge.feed_url`` setting.
DEFAULT_FEED_URL = ("https://github.com/visionebc/SATOM/releases/download/"
                    "knowledge/latest.json")

K_MODE = "knowledge.fetch_mode"
K_FEED = "knowledge.feed_url"
K_LAST = "knowledge.fetch_last"
#: The newest pack version the administrators were already told about
#: (``notify`` mode tells once per version, not once per day).
K_NOTIFIED = "knowledge.fetch_notified"
SETTINGS_KEYS = (K_MODE, K_FEED, K_LAST, K_NOTIFIED)

MODE_OFF = "off"
MODE_NOTIFY = "notify"
MODE_DOWNLOAD = "download"
MODE_IMPORT = "download_import"
MODES = (MODE_OFF, MODE_NOTIFY, MODE_DOWNLOAD, MODE_IMPORT)
DEFAULT_MODE = MODE_IMPORT
MODE_LABELS = {
    MODE_OFF: "Off — never check on a schedule",
    MODE_NOTIFY: "Notify — check daily and tell the administrators",
    MODE_DOWNLOAD: "Download — check daily and stage the pack",
    MODE_IMPORT: "Download and import — keep the knowledge current (default)",
}

LANE_API_PACK = "api_pack"
LANE_KNOWLEDGE = "knowledge"
LANES = (LANE_API_PACK, LANE_KNOWLEDGE)
LANE_LABELS = {LANE_API_PACK: "API pack (pinned to the release)",
               LANE_KNOWLEDGE: "Knowledge pack (rolling)"}

#: Knowledge older than this gets a warning badge next to what it feeds.
STALE_DAYS = 30

#: A latest.json is a few hundred bytes.
MAX_FEED_BYTES = 64 * 1024
#: Same ceiling as an uploaded pack (api_pack.MAX_UPLOAD_BYTES).
MAX_PACK_BYTES = 200 * 1024 * 1024

PACK_FILE_RE = re.compile(r"^satom-apipack-[A-Za-z0-9._-]{1,64}\.tar\.gz$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_KB_DATE_RE = re.compile(r"^kb-(\d{8})(?:\.\d+)?$")

ST_DISABLED = "disabled"
ST_STANDBY = "standby"
ST_ERROR = "error"
ST_CURRENT = "current"
ST_AVAILABLE = "available"
ST_DOWNLOADED = "downloaded"
ST_IMPORTED = "imported"
ST_FAILED = "failed"


class KnowledgeFeedError(Exception):
    """The feed, or the pack it names, cannot be used. Message is for the operator."""


# ---------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------
def _get(key: str, default: str = "") -> str:
    from ..models import AppSetting
    try:
        v = AppSetting.get(key)
    except Exception:  # noqa: BLE001 — a settings read never takes a page down
        return default
    return default if v is None else v


def mode() -> str:
    m = (_get(K_MODE) or "").strip()
    return m if m in MODES else DEFAULT_MODE


def feed_url() -> str:
    return (_get(K_FEED) or "").strip() or DEFAULT_FEED_URL


def save_settings(new_mode: str, new_feed: str) -> None:
    """Persist the mode and the feed URL. Raises ValueError on bad input —
    an unknown mode is refused, never coerced to ``off``."""
    from ..models import AppSetting
    if new_mode not in MODES:
        raise ValueError("unknown mode %r (valid: %s)" % (new_mode, ", ".join(MODES)))
    url = (new_feed or "").strip()
    if url and not url.lower().startswith("https://"):
        raise ValueError("the feed URL must be https://")
    if len(url) > 500:
        raise ValueError("the feed URL is too long")
    AppSetting.set(K_MODE, new_mode)
    # Empty = the default. Stored empty rather than as the default so a later
    # release that moves the default carries this node along.
    AppSetting.set(K_FEED, "" if url == DEFAULT_FEED_URL else url)


def last_result() -> dict:
    try:
        doc = json.loads(_get(K_LAST) or "{}")
    except ValueError:
        doc = {}
    return doc if isinstance(doc, dict) else {}


def _record(res: dict) -> dict:
    """Persist the outcome (status, message, checked_at, pack). Best effort: a
    read-only standby cannot write, and that must not turn a no-op into an error."""
    from ..models import AppSetting, db
    keep = {k: res.get(k) for k in ("status", "message", "checked_at", "pack",
                                    "version", "feed_url", "trigger", "imported",
                                    "errors")}
    try:
        AppSetting.set(K_LAST, json.dumps(keep))
    except Exception:  # noqa: BLE001
        try:
            db.session.rollback()
        except Exception:  # noqa: BLE001
            pass
    return res


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def node_role() -> str:
    """The existing node-role helper (``pg_is_in_recovery()``)."""
    from . import self_update as su
    return su.node_role()


def standby_reason() -> str:
    if node_role() == "standby":
        return ("This node is the STANDBY: its database is read-only. Knowledge "
                "packs are fetched and imported on the PRIMARY and arrive here "
                "by replication.")
    return ""


# ---------------------------------------------------------------------------
# the feed
# ---------------------------------------------------------------------------
def _transport():
    """The system-upgrade feed's HTTP module (same client, proxy and TLS rules)."""
    from . import update_package_service as upkg
    return upkg.feed


def parse_feed(raw: bytes, url: str = "") -> dict:
    """Validate a knowledge ``latest.json``. Raises KnowledgeFeedError.

    Keys: ``version, file, sha256, size, url, sha256_url, signer,
    content_fingerprint, approved_at, diff_summary``. A document that wraps
    them in ``{"pack": {...}}`` is accepted too."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise KnowledgeFeedError("the knowledge feed is not JSON: %s" % exc) from None
    if isinstance(doc, dict) and isinstance(doc.get("pack"), dict):
        doc = doc["pack"]
    if not isinstance(doc, dict):
        raise KnowledgeFeedError("the knowledge feed is not a JSON object")
    name = str(doc.get("file") or "")
    if not PACK_FILE_RE.match(name):
        raise KnowledgeFeedError("the feed names %r, which is not an API pack" % name[:80])
    version = str(doc.get("version") or "")
    if name != "satom-apipack-%s.tar.gz" % version:
        raise KnowledgeFeedError("the feed version %r does not match its pack %s"
                                 % (version[:40], name))
    link = str(doc.get("url") or "")
    if not link.lower().startswith("https://") or not link.endswith("/" + name):
        raise KnowledgeFeedError("the pack URL must be https:// and end in /%s" % name)
    sha = str(doc.get("sha256") or "").lower()
    if not _SHA_RE.match(sha):
        raise KnowledgeFeedError("the feed carries no valid sha256 for %s" % name)
    size = doc.get("size")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_PACK_BYTES:
        raise KnowledgeFeedError("the feed declares an implausible size for %s: %r"
                                 % (name, size))
    out = {k: doc.get(k) for k in ("signer", "content_fingerprint", "approved_at",
                                   "diff_summary", "sha256_url")}
    out.update(version=version, file=name, url=link, sha256=sha, size=size,
               feed_url=url)
    return out


def fetch_feed(url: str = "", timeout: float = 10) -> dict:
    """Download and validate the feed. Raises KnowledgeFeedError."""
    url = (url or feed_url()).strip()
    tr = _transport()
    try:
        raw = tr.fetch_small(url, timeout=timeout, max_bytes=MAX_FEED_BYTES)
    except tr.FeedError as exc:
        raise KnowledgeFeedError(str(exc)) from None
    return parse_feed(raw, url)


# ---------------------------------------------------------------------------
# what this node holds
# ---------------------------------------------------------------------------
def _version_of(name: str) -> str:
    return (name or "")[len("satom-apipack-"):-len(".tar.gz")]


def version_key(version: str):
    """Order inside one lane: ``kb-20261007`` < ``kb-20261007.1`` <
    ``kb-20261008``; ``2.9.1`` < ``2.10.0``. Tagged parts never compare a word
    with a number."""
    return tuple((0, int(x), "") if x.isdigit() else (1, 0, x)
                 for x in re.split(r"[.-]", version or ""))


def lane_of(record: dict) -> str:
    """The lane of an import record or a pack listing. Packs of schema /2 say
    it (``lane``); older names are classified like ``api_pack.pack_series``:
    ``kb-*`` is knowledge, anything else is the release-pinned lane."""
    lane = record.get("lane")
    if lane in LANES:
        return lane
    from . import api_pack
    series = api_pack.pack_series(record.get("pack") or record.get("name") or "")
    return LANE_KNOWLEDGE if series == "knowledge" else LANE_API_PACK


def _parse_at(value: str):
    try:
        at = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def knowledge_date(pack: str, imported_at: str = ""):
    """When the knowledge in ``pack`` was built: the date in a ``kb-YYYYMMDD``
    name, else the import time (a release pack is at least that old)."""
    m = _KB_DATE_RE.match(_version_of(pack))
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y%m%d").replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return _parse_at(imported_at)


def installed(history: list | None = None, now: datetime | None = None) -> dict:
    """The newest pack this node imported per lane, from the api_pack import
    log: ``{lane: {pack, version, imported_at, date, age_days, stale} | None}``.
    Only runs with no failed item count."""
    from . import api_pack
    if history is None:
        history = api_pack.import_history(limit=500)
    now = now or datetime.now(timezone.utc)
    best: dict = {lane: None for lane in LANES}
    for rec in history or []:
        pack = rec.get("pack") or ""
        if not PACK_FILE_RE.match(pack) or rec.get("errors") or rec.get("partial"):
            continue
        lane = lane_of(rec)
        cur = best[lane]
        if cur is None or (version_key(_version_of(pack)), rec.get("at") or "") > \
                (version_key(cur["version"]), cur["imported_at"]):
            best[lane] = {"pack": pack, "version": _version_of(pack),
                          "imported_at": rec.get("at") or "", "lane": lane}
    for lane, row in best.items():
        if row is None:
            continue
        built = knowledge_date(row["pack"], row["imported_at"])
        row["date"] = built.date().isoformat() if built else ""
        row["age_days"] = (now - built).days if built else None
        row["stale"] = row["age_days"] is None or row["age_days"] > STALE_DAYS
    return best


def freshness(history: list | None = None, now: datetime | None = None) -> dict:
    """What the release notes, Scout and the migration report say about where
    their knowledge comes from: the most recently BUILT pack of either lane.
    ``{"pack", "date", "age_days", "stale", "lane"}`` or ``{"pack": ""}``."""
    try:
        rows = [r for r in installed(history, now).values() if r]
    except Exception:  # noqa: BLE001 — a banner must never take a page down
        rows = []
    if not rows:
        return {"pack": "", "date": "", "age_days": None, "stale": True, "lane": "",
                "stale_days": STALE_DAYS}
    rows.sort(key=lambda r: (r["age_days"] is None, r["age_days"] or 0))
    out = dict(rows[0])
    out["stale_days"] = STALE_DAYS
    return out


def _staged(name: str) -> bool:
    from . import api_pack
    try:
        return (api_pack.upload_dir() / name).is_file()
    except Exception:  # noqa: BLE001
        return False


def compare(feed: dict, inst: dict | None = None) -> dict:
    """The feed against what is installed: ``newer`` and why."""
    inst = inst if inst is not None else installed()
    have = inst.get(LANE_KNOWLEDGE)
    newer = have is None or version_key(feed["version"]) > version_key(have["version"])
    return {"newer": newer, "installed": have, "staged": _staged(feed["file"])}


def check(url: str = "", timeout: float = 10) -> dict:
    """What the feed offers compared with this node. Never raises: a node with
    no internet gets ``reachable: False`` and the reason."""
    url = (url or feed_url()).strip()
    try:
        feed = fetch_feed(url, timeout=timeout)
    except KnowledgeFeedError as exc:
        return {"reachable": False, "error": str(exc), "feed_url": url,
                "installed": _safe_installed()}
    inst = _safe_installed()
    cmp = compare(feed, inst)
    return {"reachable": True, "error": "", "feed_url": url, "feed": feed,
            "installed": inst, "newer": cmp["newer"], "staged": cmp["staged"]}


def _safe_installed() -> dict:
    try:
        return installed()
    except Exception:  # noqa: BLE001
        return {lane: None for lane in LANES}


# ---------------------------------------------------------------------------
# download + import
# ---------------------------------------------------------------------------
def download(feed: dict, progress=None) -> Path:
    """Download the pack the feed names into the API-pack upload directory.

    The bytes land in a private temporary directory first and must match the
    feed's size and sha256 there; only then are they handed to
    ``api_pack.save_upload`` (which applies its own size cap and keeps the
    newest few uploads). A mismatch leaves nothing behind."""
    from . import api_pack
    tr = _transport()
    dest = api_pack.upload_dir()
    tmp = Path(tempfile.mkdtemp(prefix=".knowledge-", dir=str(dest)))
    try:
        try:
            got = tr.download_file(feed["url"], feed["file"], feed["sha256"], feed["size"],
                                   tmp, progress=progress)
        except tr.FeedError as exc:
            raise KnowledgeFeedError(str(exc)) from None
        # Re-hash the file we are about to stage: the transport checked the
        # stream, this checks what is on disk (a second, independent read).
        h = hashlib.sha256()
        with open(got, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != feed["sha256"]:
            raise KnowledgeFeedError("%s: sha256 on disk does not match the feed"
                                     % feed["file"])
        with open(got, "rb") as fh:
            info = api_pack.save_upload(fh, feed["file"])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return dest / info["name"]


def import_staged(name: str, actor: str = "", progress=None) -> dict:
    """Import an uploaded pack through api_pack (signature verified there).
    Returns api_pack's result."""
    from . import api_pack
    refusal = standby_reason()
    if refusal:
        raise KnowledgeFeedError(refusal)
    path = api_pack.resolve_pack(api_pack.SOURCE_UPLOADED, name)
    return api_pack.import_pack(path, actor=actor or "knowledge_fetch", progress=progress)


def run(*, url: str = "", do_download: bool = True, do_import: bool = True,
        actor: str = "", trigger: str = "manual", progress=None) -> dict:
    """Check → (download) → (import), recorded as the last result.

    Returns ``{"status", "message", "checked_at", "pack", "version", ...}``.
    Never raises for an expected failure (unreachable feed, bad sha256,
    refused signature): those come back as ``status: error|failed``."""
    url = (url or feed_url()).strip()
    base = {"checked_at": _now(), "feed_url": url, "trigger": trigger, "pack": "",
            "version": ""}
    refusal = standby_reason()
    if refusal and (do_download or do_import):
        # No-op with the reason. Not recorded: the standby cannot write.
        return dict(base, status=ST_STANDBY, message=refusal)
    res = check(url)
    if not res["reachable"]:
        return _record(dict(base, status=ST_ERROR, message=res["error"]))
    feed = res["feed"]
    base.update(pack=feed["file"], version=feed["version"])
    if not res["newer"]:
        have = res["installed"].get(LANE_KNOWLEDGE) or {}
        return _record(dict(base, status=ST_CURRENT,
                            message="Up to date: %s is the newest knowledge pack "
                                    "(installed %s)." % (feed["version"],
                                                         have.get("pack") or "?")))
    if not do_download:
        return _record(dict(base, status=ST_AVAILABLE,
                            message="Knowledge pack %s is available (%s)."
                                    % (feed["version"], _size(feed["size"]))))
    try:
        if not res["staged"]:
            download(feed, progress=progress)
    except (KnowledgeFeedError, OSError) as exc:
        return _record(dict(base, status=ST_ERROR,
                            message="Download failed: %s" % exc))
    except Exception as exc:  # noqa: BLE001 — api_pack.PackError and friends
        return _record(dict(base, status=ST_ERROR,
                            message="Download failed: %s" % exc))
    if not do_import:
        return _record(dict(base, status=ST_DOWNLOADED,
                            message="Downloaded %s; import it from Software Update "
                                    "or with 'satom execute knowledge fetch --import "
                                    "--yes'." % feed["file"]))
    try:
        out = import_staged(feed["file"], actor=actor, progress=progress)
    except Exception as exc:  # noqa: BLE001 — refused signature, schema, standby
        return _record(dict(base, status=ST_FAILED,
                            message="Import refused: %s" % exc))
    if out.get("errors"):
        return _record(dict(base, status=ST_FAILED, imported=out.get("imported", 0),
                            errors=out["errors"],
                            message="%d item(s) of %s failed to import; %d imported."
                                    % (out["errors"], feed["file"], out.get("imported", 0))))
    return _record(dict(base, status=ST_IMPORTED, imported=out.get("imported", 0),
                        errors=0,
                        message="Imported %s: %d new item(s)."
                                % (feed["file"], out.get("imported", 0))))


def _size(n: int) -> str:
    return "%.1f MB" % (n / 1048576.0)


def _notify_admins(res: dict) -> None:
    """Tell the administrators once per version (``notify`` mode)."""
    from ..models import AppSetting
    from . import notifications as notify
    from .alerts import _admin_ids
    if _get(K_NOTIFIED) == res.get("version"):
        return
    notify.push_many(_admin_ids(),
                     "Knowledge pack %s is available" % res.get("version"),
                     kind="info", body=res.get("message"),
                     link="/self-update/#knowledge-packs")
    try:
        AppSetting.set(K_NOTIFIED, res.get("version") or "")
    except Exception:  # noqa: BLE001
        pass


def scheduled(dry_run: bool = False) -> dict:
    """The ``knowledge_fetch`` scheduled action. ``{"ok", "summary", "log"}``.

    ``ok`` is "the round ran" (an unreachable feed on an offline node is not a
    red action every day), except a refused import or a failed download of a
    pack the feed offered, which is red: somebody has to look."""
    m = mode()
    if m == MODE_OFF:
        return {"ok": True, "summary": "Knowledge fetch is off (knowledge.fetch_mode).",
                "log": ""}
    refusal = standby_reason()
    if refusal:
        return {"ok": True, "summary": "Skipped: " + refusal, "log": ""}
    if dry_run:
        return {"ok": True,
                "summary": "[dry-run] would check %s (mode %s)" % (feed_url(), m),
                "log": ""}
    res = run(do_download=m in (MODE_DOWNLOAD, MODE_IMPORT), do_import=m == MODE_IMPORT,
              actor="scheduler", trigger="schedule")
    if res["status"] == ST_AVAILABLE and m == MODE_NOTIFY:
        _notify_admins(res)
    ok = res["status"] not in (ST_FAILED,) and not (
        res["status"] == ST_ERROR and res.get("pack"))
    return {"ok": ok, "summary": "%s: %s" % (res["status"], res["message"]),
            "log": json.dumps(res, indent=1, default=str)[:4000]}


def state() -> dict:
    """Everything the Software Update block shows. Network-free."""
    return {"mode": mode(), "modes": [(m, MODE_LABELS[m]) for m in MODES],
            "feed_url": feed_url(), "default_feed_url": DEFAULT_FEED_URL,
            "last": last_result(), "installed": _safe_installed(),
            "lane_labels": LANE_LABELS, "stale_days": STALE_DAYS,
            "role": node_role(), "refusal": standby_reason()}


__all__ = ["DEFAULT_FEED_URL", "MODES", "DEFAULT_MODE", "LANES", "STALE_DAYS",
           "SETTINGS_KEYS", "KnowledgeFeedError", "mode", "feed_url", "save_settings",
           "last_result", "parse_feed", "fetch_feed", "installed", "freshness",
           "check", "download", "import_staged", "run", "scheduled", "state",
           "knowledge_date", "lane_of", "version_key"]
