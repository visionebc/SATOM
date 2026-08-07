"""Renewal journal — every certificate renewal attempt, with its error text.

The nightly satom-cert-renew timer used to print its result to stdout and
nothing else: the only trace of a failed renewal was journalctl, and the
only *notification* was the alert e-mail at T-N days. This module persists every
attempt so the UI can show WHAT ran, WHEN, and WHY it failed.

Why a FILE and not a table — deliberate, do not "fix" this into Postgres:

* the standby's Postgres is a **read-only replica**, so the node that fails to
  renew is exactly the node that cannot write a DB row about that failure;
* data/ is not an option either — satom-ha-datasync pulls it with
  rsync --delete, so anything the standby writes under data/ is erased
  within 5 minutes.

So the journal is node-local at /opt/satom/state/cert-renew.jsonl (outside
data/, gitignored) and each node publishes its own over
/healthz/cert-renewals — the same peer-probe pattern as
/healthz/backups — so one page renders both nodes side by side.

DURABILITY (the archiver, below) — that gives *visibility*, not *durability*:
lose the standby's disk and its journal is gone, and on this estate both HA
nodes and the backup host share one hypervisor, so "the other node survives" is
not a safe assumption. The fix does NOT move the journal (that would reintroduce
exactly the two problems above). Instead the **PRIMARY** pulls the peer's
journal over the same authenticated peer channel and appends it under
``data/cert-renew-archive/<node>.jsonl``.

The direction is what makes this safe, and it was verified against
/usr/local/sbin/satom-ha-datasync.sh: the unit runs ON THE STANDBY, exits 0
unless ``pg_is_in_recovery()`` is true, and rsyncs ``primary:data/ -> local
data/``. So ``--delete`` erases what the STANDBY writes under data/ and
propagates what the PRIMARY writes. An archive owned by the primary therefore
survives *and* is copied to the standby for free — two disks, one file.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

STATE = Path("/opt/satom/state")
JOURNAL = STATE / "cert-renew.jsonl"
MAX_ENTRIES = 400

# --- archive (durable copy, primary-owned, under data/) ---------------------
APP_DIR = Path(os.environ.get("FM_APP_DIR", "/opt/satom"))
ARCHIVE_DIR = Path(os.environ.get("SATOM_CERT_ARCHIVE_DIR")
                   or (APP_DIR / "data" / "cert-renew-archive"))
# Retention — TWO bounds, both applied on every append (see _trim_archive):
#   1. age: a record whose ``at`` is older than ARCHIVE_MAX_AGE_DAYS is dropped;
#   2. count: at most ARCHIVE_MAX_ENTRIES lines per node, oldest dropped first.
# Records are appended oldest-first, so append order == chronological order and
# "drop from the head" == "drop the oldest".
ARCHIVE_MAX_ENTRIES = 2000      # per node; the live journal itself holds 400
ARCHIVE_MAX_AGE_DAYS = 400      # > 1 year of renewals, incl. the annual one
ARCHIVE_MAX_PULLS = 500         # per node, pull-attempt log
PULL_MIN_INTERVAL_S = 900       # opportunistic pulls (page render) throttle
PULL_STALE_AFTER_S = 6 * 3600   # a last-success older than this = stale

# channel = which renewal pipeline produced the entry
CH_INTERNAL = "internal-ca"     # re-mint of a CA-issued leaf (renew_if_needed)
CH_AUTOPULL = "autopull"        # SFTP fetch of a renewed cert from the source
CH_IMPORT = "import"            # operator/pull installed an external PEM
CH_ISSUE = "issue"              # operator minted from the internal CA
CH_TIMER = "timer"              # the nightly runner itself (crash/exception)

OK_RENEWED = "renewed"
OK_SKIPPED = "skipped"
OK_ERROR = "error"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _node() -> tuple[str, str]:
    try:
        from . import self_update as su
        return su.this_node_name() or "?", su.node_role() or "?"
    except Exception:
        return "?", "?"


def record(channel: str, status: str, summary: str = "", *, error: str = "",
           by: str = "", days_left=None, not_after: str | None = None,
           extra: dict | None = None) -> dict:
    """Append one attempt. NEVER raises — a journal problem must not turn a
    successful renewal into a failure, nor mask the real error."""
    name, role = _node()
    entry = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "node": name, "role": role,
        "channel": channel, "status": status,
        "summary": (summary or "")[:600],
        "error": (error or "")[:2000],
        "by": by, "days_left": days_left, "not_after": not_after,
    }
    if extra:
        entry["extra"] = extra
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        os.chmod(STATE, 0o700)
        with JOURNAL.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        _trim()
    except Exception:  # noqa: BLE001 — journaling is best-effort by design
        pass
    return entry


def _trim() -> None:
    try:
        lines = JOURNAL.read_text(encoding="utf-8").splitlines()
        if len(lines) > MAX_ENTRIES:
            JOURNAL.write_text("\n".join(lines[-MAX_ENTRIES:]) + "\n", encoding="utf-8")
    except Exception:
        pass


def history(limit: int = 200, only_errors: bool = False) -> list[dict]:
    """Newest first."""
    out = []
    try:
        for line in JOURNAL.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except FileNotFoundError:
        return []
    except Exception:
        return []
    out.reverse()
    if only_errors:
        out = [e for e in out if e.get("status") == OK_ERROR]
    return out[:limit]


def summary() -> dict:
    """Compact state for the page header / peer probe."""
    runs = history(limit=MAX_ENTRIES)
    name, role = _node()
    last = runs[0] if runs else None
    last_err = next((e for e in runs if e.get("status") == OK_ERROR), None)
    # consecutive failures at the head of the journal (an ongoing problem)
    streak = 0
    for e in runs:
        if e.get("status") == OK_ERROR:
            streak += 1
        else:
            break
    return {"node": name, "role": role, "count": len(runs),
            "errors": sum(1 for e in runs if e.get("status") == OK_ERROR),
            "last": last, "last_error": last_err, "fail_streak": streak}


# ---------------------------------------------------------------------------
# Fleet view — this node + the peer, without any SSH between them
# ---------------------------------------------------------------------------
def _cert_state() -> dict:
    from . import cert_service as cs
    try:
        cur = cs.current()
        out = {k: cur.get(k) for k in
               ("source", "days_left", "not_after", "subject", "hostname",
                "installed_at", "can_issue_internal", "issuer")}
        out["renew_mode"] = cs.renew_mode()
        try:
            out["autopull_configured"] = bool(cs.autopull_config().get("configured"))
        except Exception:
            out["autopull_configured"] = False
        return out
    except Exception as exc:  # noqa: BLE001
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


def local_view(limit: int = 100) -> dict:
    return {"reachable": True, "is_self": True, "secure": None,
            "host": "127.0.0.1", "cert": _cert_state(),
            "summary": summary(), "runs": history(limit=limit)}


def peer_view(host: str, limit: int = 100, timeout: float = 2.5) -> dict:
    """Read the PEER's journal over the authenticated HTTPS peer channel
    (node_security.peer_get → /healthz/cert-renewals). No SSH, no shared FS —
    the peer's journal is node-local and only the peer can produce it."""
    out = {"reachable": False, "is_self": False, "secure": False, "host": host,
           "cert": {}, "summary": {}, "runs": [], "error": ""}
    if not host or host in ("127.0.0.1", "localhost"):
        return out
    try:
        from . import node_security as nsec
        st, body, secure = nsec.peer_get(
            host, "/healthz/cert-renewals?limit=%d" % int(limit), timeout=timeout)
        out["secure"] = bool(secure)
        if st != 200:
            out["error"] = "peer answered %s" % (st if st is not None else "nothing (unreachable)")
            return out
        data = json.loads(body.decode("utf-8", "replace"))
        out.update(reachable=True, cert=data.get("cert") or {},
                   summary=data.get("summary") or {}, runs=data.get("runs") or [])
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def fleet_view(limit: int = 100) -> list[dict]:
    """One entry per HA node: this node read locally, every other node probed."""
    try:
        from . import self_update as su
        me = su.this_node_name()
        nodes = su.load_nodes()
    except Exception:
        me, nodes = "", []
    out = []
    for n in nodes or []:
        name = (n.get("name") or "").strip()
        host = (n.get("host") or "").strip()
        if n.get("self") or (name and name == me) or host in ("127.0.0.1", "localhost"):
            v = local_view(limit=limit)
        else:
            v = peer_view(host, limit=limit)
        v["name"] = name or host or me or "this node"
        v["desc"] = n.get("desc") or ""
        out.append(v)
    if not out:
        v = local_view(limit=limit)
        v["name"] = me or "this node"
        v["desc"] = ""
        out.append(v)
    # Durable side of the same question: what survives this node's disk.
    for v in out:
        v["archive"] = archive_status(v["name"])
        v["archived"] = archived_history(v["name"], limit=limit)
    return out


# ---------------------------------------------------------------------------
# Durable archive — the primary pulls the peer's journal into data/
# ---------------------------------------------------------------------------
def _safe_name(name: str) -> str:
    """Filesystem-safe node name. A node name comes from ha_nodes.json, which an
    admin edits, so it must not be able to escape ARCHIVE_DIR."""
    keep = [c if (c.isalnum() or c in "-_.") else "_" for c in (name or "").strip()]
    out = "".join(keep).strip("._") or "unknown"
    return out[:64]


def _archive_path(name: str) -> Path:
    return ARCHIVE_DIR / ("%s.jsonl" % _safe_name(name))


def _pulls_path(name: str) -> Path:
    # own subdir: a node literally named "x.pulls" must not collide with x's log
    return ARCHIVE_DIR / "pulls" / ("%s.jsonl" % _safe_name(name))


def entry_id(rec: dict) -> str:
    """Identity of ONE renewal attempt, derived from the attempt's own content.

    Not a counter and not a position: the peer republishes its whole journal on
    every pull, so the same attempt arrives at a different index every time. Any
    positional identity would re-append the entire journal on each pull.
    Bookkeeping keys (``_``-prefixed) are excluded so an archived record hashes
    to the same id as the live one it came from.
    """
    body = {k: v for k, v in (rec or {}).items() if not str(k).startswith("_")}
    blob = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def _parse_at(value) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value))
    except Exception:  # noqa: BLE001 — a record with an unreadable date is still evidence
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out
    except Exception:  # noqa: BLE001
        return out
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:  # noqa: BLE001 — one corrupt line must not hide the rest
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(json.dumps(r, ensure_ascii=False, default=str) + "\n"
                           for r in rows), encoding="utf-8")
    tmp.replace(path)


def retention_policy() -> dict:
    """The trimming rule, explicit and machine-readable (the UI shows it, so an
    operator never has to guess how far back the archive goes)."""
    return {
        "max_entries": ARCHIVE_MAX_ENTRIES,
        "max_age_days": ARCHIVE_MAX_AGE_DAYS,
        "max_pulls": ARCHIVE_MAX_PULLS,
        "stale_after_s": PULL_STALE_AFTER_S,
        "min_interval_s": PULL_MIN_INTERVAL_S,
        "rule": ("per node: drop records older than %d days, then keep the newest "
                 "%d by append order (append order is chronological)"
                 % (ARCHIVE_MAX_AGE_DAYS, ARCHIVE_MAX_ENTRIES)),
    }


def _age_cutoff() -> datetime:
    return _utcnow() - timedelta(days=ARCHIVE_MAX_AGE_DAYS)


def _trim_archive(rows: list[dict]) -> list[dict]:
    cutoff = _age_cutoff()
    kept = []
    for r in rows:
        at = _parse_at(r.get("at"))
        if at is not None and at < cutoff:
            continue          # bound 1: too old
        kept.append(r)         # an undateable record survives bound 1, not bound 2
    if len(kept) > ARCHIVE_MAX_ENTRIES:
        kept = kept[-ARCHIVE_MAX_ENTRIES:]   # bound 2: newest N, oldest dropped
    return kept


def archive_runs(name: str, runs: list[dict]) -> dict:
    """Append the peer's attempts to ``name``'s archive: append-only, deduped by
    content id, bounded by :func:`retention_policy`.

    ``runs`` arrive newest-first (that is what ``history()`` publishes) and are
    appended oldest-first so the file stays chronological.
    """
    path = _archive_path(name)
    existing = _read_jsonl(path)
    seen = {r.get("_id") or entry_id(r) for r in existing}
    at_capacity = len(existing) >= ARCHIVE_MAX_ENTRIES
    # Anything below this line was already deliberately trimmed; re-appending it
    # would resurrect records the retention rule just dropped, forever.
    floor = None
    if at_capacity:
        stamps = [d for d in (_parse_at(r.get("at")) for r in existing) if d]
        floor = min(stamps) if stamps else None
    cutoff = _age_cutoff()

    added = dup = old = 0
    now = _utcnow().isoformat(timespec="seconds")
    for rec in reversed(list(runs or [])):
        if not isinstance(rec, dict):
            continue
        rid = entry_id(rec)
        if rid in seen:
            dup += 1
            continue
        at = _parse_at(rec.get("at"))
        if at is not None and (at < cutoff or (floor is not None and at < floor)):
            old += 1
            continue
        row = dict(rec)
        row["_id"] = rid
        row["_node"] = name
        row["_archived_at"] = now
        existing.append(row)
        seen.add(rid)
        added += 1

    if added:
        _write_jsonl(path, _trim_archive(existing))
    return {"added": added, "skipped_dup": dup, "skipped_old": old,
            "entries": len(_read_jsonl(path)) if added else len(existing)}


def record_pull(name: str, ok: bool, *, error: str = "", host: str = "",
                pulled: int = 0, added: int = 0, source: str = "peer") -> dict:
    """Journal ONE pull attempt — success or failure.

    A pull that could not answer is written down as a failed pull. It is never
    dropped: silence would be indistinguishable from "the peer has no failures",
    which is this repo's most repeated bug.
    """
    row = {"at": _utcnow().isoformat(timespec="seconds"), "node": name,
           "host": host, "ok": bool(ok), "error": (error or "")[:600],
           "pulled": int(pulled or 0), "added": int(added or 0), "source": source}
    try:
        rows = _read_jsonl(_pulls_path(name))
        rows.append(row)
        _write_jsonl(_pulls_path(name), rows[-ARCHIVE_MAX_PULLS:])
    except Exception:  # noqa: BLE001 — archiving is best-effort, like record()
        pass
    return row


def pull_history(name: str, limit: int = 50) -> list[dict]:
    """Pull attempts for ``name``, newest first."""
    rows = _read_jsonl(_pulls_path(name))
    rows.reverse()
    return rows[:limit]


def archived_history(name: str, limit: int = 200) -> list[dict]:
    """Archived attempts for ``name``, newest first (same shape as history())."""
    rows = _read_jsonl(_archive_path(name))
    rows.reverse()
    return rows[:limit]


def _throttled(name: str) -> bool:
    last = pull_history(name, limit=1)
    if not last:
        return False
    at = _parse_at(last[0].get("at"))
    if at is None:
        return False
    return (_utcnow() - at).total_seconds() < PULL_MIN_INTERVAL_S


def pull_peer(host: str, name: str | None = None, *, limit: int = 400,
              timeout: float = 2.5, force: bool = False) -> dict:
    """Pull the PEER's journal over the authenticated peer channel and archive it.

    Returns ``ok=False`` for both "unreachable" and "throttled" — neither is a
    pull, and neither may be mistaken for one. They are distinguishable via
    ``skipped``: a throttled call writes nothing at all, an unreachable peer
    writes a failure row.
    """
    if not force and _throttled(name or host):
        return {"ok": False, "skipped": "throttled", "node": name or host,
                "host": host, "added": 0, "pulled": 0}
    view = peer_view(host, limit=limit, timeout=timeout)
    node = name or (view.get("summary") or {}).get("node") or host
    if not view.get("reachable"):
        err = view.get("error") or "peer unreachable"
        record_pull(node, False, error=err, host=host)
        return {"ok": False, "node": node, "host": host, "error": err,
                "added": 0, "pulled": 0, "skipped_dup": 0, "skipped_old": 0}
    runs = view.get("runs") or []
    res = archive_runs(node, runs)
    record_pull(node, True, host=host, pulled=len(runs), added=res["added"])
    return {"ok": True, "node": node, "host": host, "error": "",
            "pulled": len(runs), **res}


def archive_local(name: str | None = None, *, force: bool = False) -> dict:
    """Archive THIS node's own journal into data/.

    The primary's journal is just as node-local as the standby's; copying it into
    the primary-owned archive makes it durable and hands the standby a copy via
    the same datasync.
    """
    node = name or _node()[0] or "this node"
    if not force and _throttled(node):
        return {"ok": False, "skipped": "throttled", "node": node, "added": 0,
                "pulled": 0}
    runs = history(limit=MAX_ENTRIES)
    res = archive_runs(node, runs)
    record_pull(node, True, host="127.0.0.1", pulled=len(runs),
                added=res["added"], source="local")
    return {"ok": True, "node": node, "host": "127.0.0.1", "error": "",
            "pulled": len(runs), **res}


def archive_refresh(force: bool = False, limit: int = 400) -> dict:
    """Archive every node in the HA registry. Cheap and idempotent — safe to call
    on a page render (the per-node throttle keeps it off the peer's back).

    Inert on a STANDBY: the standby's writes under data/ are erased by the next
    datasync pass, so pretending to archive there would produce an archive that
    silently vanishes. The primary owns this file.
    """
    try:
        from . import self_update as su
        role = su.node_role()
        me = su.this_node_name()
        nodes = su.load_nodes()
    except Exception as exc:  # noqa: BLE001
        return {"role": "unknown", "skipped": "registry-unreadable",
                "error": "%s: %s" % (type(exc).__name__, exc), "results": []}
    if role == "standby":
        return {"role": role, "skipped": "standby", "results": []}
    results = []
    for n in nodes or []:
        name = (n.get("name") or "").strip()
        host = (n.get("host") or "").strip()
        if n.get("self") or (name and name == me) or host in ("127.0.0.1", "localhost"):
            results.append(archive_local(name or me, force=force))
        else:
            results.append(pull_peer(host, name or host, limit=limit, force=force))
    return {"role": role, "skipped": None, "results": results}


def archive_status(name: str) -> dict:
    """What the archive can honestly say about ``name``.

    ``state`` is four-valued and only ONE of them is good:

    * ``never``   — no pull was ever recorded. Unknown, not fine.
    * ``failing`` — the last pull failed; ``unreachable_since`` is the START of
      the current failure streak, so the card can say "not reachable since X".
    * ``stale``   — the last SUCCESSFUL pull is older than PULL_STALE_AFTER_S.
    * ``ok``      — a recent successful pull.

    ``ok`` is True only for ``ok``. A probe that cannot answer must never
    default to "healthy".
    """
    rows = _read_jsonl(_archive_path(name))
    pulls = _read_jsonl(_pulls_path(name))
    stamps = [d for d in (_parse_at(r.get("at")) for r in rows) if d]
    st = {"node": name, "entries": len(rows),
          "oldest_at": min(stamps).isoformat(timespec="seconds") if stamps else None,
          "newest_at": max(stamps).isoformat(timespec="seconds") if stamps else None,
          "path": str(_archive_path(name)), "retention": retention_policy(),
          "pulls": len(pulls), "last_pull": pulls[-1] if pulls else None,
          "last_success_at": None, "last_success_age_s": None,
          "fail_streak": 0, "unreachable_since": None, "stale": False,
          "state": "never", "ok": False, "message": ""}

    last_ok = next((r for r in reversed(pulls) if r.get("ok")), None)
    if last_ok:
        st["last_success_at"] = last_ok.get("at")
        at = _parse_at(last_ok.get("at"))
        if at is not None:
            st["last_success_age_s"] = max(0, int((_utcnow() - at).total_seconds()))

    streak = []
    for r in reversed(pulls):
        if r.get("ok"):
            break
        streak.append(r)
    st["fail_streak"] = len(streak)
    if streak:
        st["unreachable_since"] = streak[-1].get("at")   # the FIRST of the streak

    if not pulls:
        st["state"] = "never"
        st["message"] = ("no pull of %s's journal has ever been recorded — the "
                         "archive cannot vouch for it" % name)
    elif streak:
        st["state"] = "failing"
        st["message"] = ("cannot reach %s since %s (%d failed pull(s)) — archived "
                         "history stops at %s" % (name, st["unreachable_since"],
                                                  len(streak), st["newest_at"] or "nothing"))
    elif (st["last_success_age_s"] is None
          or st["last_success_age_s"] > PULL_STALE_AFTER_S):
        st["state"] = "stale"
        st["stale"] = True
        st["message"] = ("%s's archive has not been refreshed since %s"
                         % (name, st["last_success_at"] or "?"))
    else:
        st["state"] = "ok"
        st["ok"] = True
    return st


def durability_alerts(nodes: list[dict], role: str = "") -> list[dict]:
    """The subset of archive states an operator must act on — and NOTHING else.

    A healthy pair produces an empty list. ``never`` is only actionable on the
    node that owns the archive (the primary): on a standby the archive arrives
    by datasync, so "I have not archived anything" is expected, not a fault.
    """
    out = []
    for n in nodes or []:
        st = (n or {}).get("archive") or {}
        state = st.get("state")
        if state in ("failing", "stale") or (state == "never" and role == "primary"):
            out.append({"node": n.get("name") or st.get("node") or "?",
                        "state": state, "message": st.get("message") or "",
                        "unreachable_since": st.get("unreachable_since"),
                        "last_success_at": st.get("last_success_at"),
                        "last_success_age_s": st.get("last_success_age_s")})
    return out
