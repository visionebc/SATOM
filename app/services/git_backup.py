"""Git repository backup — self-contained ``git bundle`` copies of the repo.

Why this exists
---------------
The repo carries two different things: the application code and, under
``reports/``, the per-device source of truth. Gitea (LXC 237) is a
*distribution* point for both, not a custody point — but it is the only place
where the **history** of ``reports/`` lives off this node. While Gitea is
unreachable the hourly publisher keeps committing locally with nowhere to push,
and those local-only commits are exactly what ``self_update_runner``'s
``git reset --hard origin/<branch>`` throws away. The runner now parks them on
a ``refs/backup/pre-reset-*`` ref first; this module is what gets them (and the
rest of the history) *off the box*.

A ``git bundle`` is the right artifact: ONE file holding the whole history and
every ref (``--all`` — including those ``refs/backup/*`` safety refs),
verifiable offline (``git bundle verify``) and clonable directly
(``git clone satom-repo-<ts>.bundle``). No server, no daemon, no credentials.

Where the copies land
---------------------
* **this node** — ``data/git-bundles/``. Under ``data/`` on purpose: the
  standby's ``satom-ha-datasync`` timer mirrors that tree every 5 min, so a
  bundle is on both nodes without any extra plumbing.
* **the external backup server** — ``<system_path>/git/`` on backup-server
  (LXC 251 on hypervisor04): a third failure domain, away from the primary (hypervisor06)
  and away from the Gitea/standby pair (both on hypervisor03).
* **the operator** — the download button on System Backup & Restore.

Cheap: the delta-compressed pack of the whole history is a few MB (the 208 MB
``.git`` on disk is mostly unreachable objects and old packs), so the default
retention of 7 costs little and the standby mirrors every copy.
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Only files this module wrote can be listed, downloaded or deleted.
NAME_RE = re.compile(r"^satom-repo-\d{8}-\d{6}\.bundle$")
K_KEEP = "gitbackup.keep"            # how many bundles to retain per node
K_PUSH = "gitbackup.push_server"     # "1" → also SFTP-push to backup-server
DEFAULT_KEEP = 7
REMOTE_SUBDIR = "git"                # <system_path>/git on the backup server


# ── paths / small helpers ────────────────────────────────────────────────────

def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent  # app/services → app → root


def bundle_dir() -> Path:
    d = _repo_root() / "data" / "git-bundles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _git(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    root = _repo_root()
    return subprocess.run(
        ["git", "-C", str(root), "-c", "safe.directory=%s" % root, *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _out(*args: str, default: str = "") -> str:
    try:
        r = _git(*args, timeout=30)
    except Exception:  # noqa: BLE001
        return default
    return (r.stdout or "").strip() if r.returncode == 0 else default


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _setting(key: str, fallback):
    """AppSetting read that also works outside an app context (the scheduler
    calls in with one; a CLI smoke test may not)."""
    try:
        from ..models import AppSetting
        v = AppSetting.get(key)
        return fallback if v is None else v
    except Exception:  # noqa: BLE001
        return fallback


def keep_count() -> int:
    try:
        return max(1, min(50, int(str(_setting(K_KEEP, DEFAULT_KEEP)).strip())))
    except (TypeError, ValueError):
        return DEFAULT_KEEP


def push_enabled() -> bool:
    return str(_setting(K_PUSH, "1")).strip() in ("1", "on", "true", "True")


def save_config(form) -> dict:
    """Persist the two knobs from the System Backup page. Returns the new
    values so the caller can flash them."""
    from ..models import AppSetting
    try:
        keep = max(1, min(50, int(str(form.get("keep") or DEFAULT_KEEP).strip())))
    except (TypeError, ValueError):
        keep = DEFAULT_KEEP
    push = "1" if form.get("push_server") in ("on", "1", "true", "True", True) else "0"
    AppSetting.set(K_KEEP, str(keep))
    AppSetting.set(K_PUSH, push)
    return {"keep": keep, "push_server": push == "1"}


# ── unpushed state (what a bundle would rescue) ──────────────────────────────

def unpushed_state() -> dict:
    """How far this checkout has drifted from its upstream, and — the number
    that actually matters — how long the oldest unpushed commit has been
    stranded. ``ahead>0, behind==0`` is the exact signature of a Gitea outage
    and it is the one combination the old alert rules did not cover.

    Never raises: a repo with no upstream returns zeros."""
    up = _out("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    out = {"upstream": up, "ahead": 0, "behind": 0, "oldest_iso": "",
           "oldest_age_h": 0.0, "dirty": bool(_out("status", "--porcelain")),
           "head": _out("rev-parse", "HEAD")[:12]}
    if not up:
        return out
    counts = _out("rev-list", "--left-right", "--count", "%s...HEAD" % up)
    if "\t" in counts:
        b, a = counts.split("\t", 1)
        try:
            out["behind"], out["ahead"] = int(b), int(a)
        except ValueError:
            pass
    if out["ahead"] > 0:
        first = _out("log", "--reverse", "--format=%cI", "%s..HEAD" % up)
        oldest = first.splitlines()[0] if first else ""
        out["oldest_iso"] = oldest
        if oldest:
            try:
                dt = datetime.fromisoformat(oldest)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                delta = datetime.now(timezone.utc) - dt
                out["oldest_age_h"] = round(delta.total_seconds() / 3600.0, 1)
            except ValueError:
                pass
    return out


def safety_refs() -> list[dict]:
    """``refs/backup/*`` — commits the update runner parked before a
    ``reset --hard`` would have discarded them. Visible in the UI so an
    operator knows there is something to recover (and can see it is captured
    in the bundles, which are ``--all``)."""
    raw = _out("for-each-ref", "--format=%(refname)|%(objectname:short)|%(creatordate:iso8601)",
               "refs/backup/")
    rows = []
    for line in raw.splitlines():
        parts = line.split("|", 2)
        if len(parts) == 3:
            rows.append({"ref": parts[0], "sha": parts[1], "created": parts[2]})
    rows.sort(key=lambda r: r["created"], reverse=True)
    return rows


# ── local store ──────────────────────────────────────────────────────────────

def _meta_path(name: str) -> Path:
    return bundle_dir() / (name + ".json")


def bundle_path(name: str) -> Path | None:
    """Validated path for *name*, or None when the name is not one of ours."""
    if not NAME_RE.match(name or ""):
        return None
    p = bundle_dir() / name
    return p if p.exists() else None


def list_bundles() -> list[dict]:
    """Newest first: name, size, when, and the metadata sidecar (sha256, head
    commit, ref count, how many unpushed commits it rescued)."""
    rows = []
    d = bundle_dir()
    for p in d.iterdir():
        if not NAME_RE.match(p.name):
            continue
        try:
            stt = p.stat()
        except OSError:
            continue
        meta = {}
        mp = _meta_path(p.name)
        if mp.exists():
            try:
                meta = json.loads(mp.read_text())
            except (OSError, ValueError):
                meta = {}
        rows.append({
            "name": p.name,
            "size": int(stt.st_size),
            "mtime": datetime.utcfromtimestamp(stt.st_mtime).strftime("%Y-%m-%d %H:%M"),
            "sha256": meta.get("sha256", ""),
            "head": meta.get("head", ""),
            "branch": meta.get("branch", ""),
            "refs": meta.get("refs", 0),
            "unpushed": meta.get("unpushed", 0),
            "label": meta.get("label", ""),
            "pushed": meta.get("pushed", ""),
        })
    rows.sort(key=lambda r: r["name"], reverse=True)
    return rows


def _prune(keep: int) -> list[str]:
    dropped = []
    for row in list_bundles()[keep:]:
        p = bundle_dir() / row["name"]
        try:
            p.unlink()
            _meta_path(row["name"]).unlink(missing_ok=True)
            dropped.append(row["name"])
        except OSError:
            pass
    return dropped


def delete_bundle(name: str) -> dict:
    """Delete one bundle from THIS node. Primary-only by design, same reason as
    the DB bundles: ``satom-ha-datasync`` rsyncs ``data/`` with ``--delete``
    from the primary, so deleting on the standby is undone within 5 min."""
    if not NAME_RE.match(name or ""):
        return {"ok": False, "detail": "invalid bundle name"}
    p = bundle_dir() / name
    if not p.exists():
        return {"ok": False, "detail": "not found"}
    try:
        p.unlink()
        _meta_path(name).unlink(missing_ok=True)
    except OSError as exc:
        return {"ok": False, "detail": str(exc)}
    return {"ok": True, "detail": "%s deleted" % name}


# ── create ───────────────────────────────────────────────────────────────────

def create_bundle(*, label: str = "manual", push_server: bool | None = None,
                  keep: int | None = None, by: str = "") -> dict:
    """Write a verified ``git bundle`` of the whole repo, prune to the retention
    limit and (optionally) push it to the external backup server.

    Returns ``{ok, name, path, size, sha256, detail}``. Never raises: this runs
    from the scheduler as well as from the page."""
    d = bundle_dir()
    # Second-resolution names collide if two bundles are requested inside the
    # same second (two admins, or the scheduler racing a click). Walk the
    # stamp forward instead of silently overwriting the earlier bundle.
    stamp = datetime.utcnow().replace(microsecond=0)
    while (d / ("satom-repo-%s.bundle" % stamp.strftime("%Y%m%d-%H%M%S"))).exists():
        stamp += timedelta(seconds=1)
    ts = stamp.strftime("%Y%m%d-%H%M%S")
    name = "satom-repo-%s.bundle" % ts
    stage = d / ("_stage-%s" % name)
    detail: list[str] = []
    state = unpushed_state()
    try:
        r = _git("bundle", "create", str(stage), "--all", timeout=1800)
        if r.returncode != 0 or not stage.exists():
            return {"ok": False, "name": "", "path": "", "size": 0, "sha256": "",
                    "detail": "git bundle create failed: %s"
                              % ((r.stderr or r.stdout or "")[-300:])}
        v = _git("bundle", "verify", str(stage), timeout=600)
        if v.returncode != 0:
            stage.unlink(missing_ok=True)
            return {"ok": False, "name": "", "path": "", "size": 0, "sha256": "",
                    "detail": "bundle verify failed: %s"
                              % ((v.stderr or v.stdout or "")[-300:])}
        size = stage.stat().st_size
        sha = _sha256(stage)
        final = d / name
        stage.replace(final)
        try:
            os.chmod(final, 0o640)
        except OSError:
            pass
        refs = len([ln for ln in _out("for-each-ref", "--format=%(refname)").splitlines() if ln])
        meta = {
            "name": name, "created": ts, "label": label, "by": by,
            "sha256": sha, "size": size,
            "head": state.get("head", ""),
            "branch": _out("rev-parse", "--abbrev-ref", "HEAD"),
            "refs": refs,
            "unpushed": state.get("ahead", 0),
            "node": _node_name(),
            "pushed": "",
        }
        detail.append("%s (%d MB), %d refs, sha256 %s…"
                      % (name, size // (1024 * 1024), refs, sha[:12]))
        if state.get("ahead"):
            detail.append("captures %d unpushed commit(s)" % state["ahead"])

        do_push = push_enabled() if push_server is None else bool(push_server)
        if do_push:
            pr = push_bundle_to_server(str(final))
            meta["pushed"] = pr.get("remote", "") if pr.get("ok") else ""
            detail.append("backup-server: " + (pr.get("detail") or
                                           ("push failed: " + str(pr.get("detail")))))
        _meta_path(name).write_text(json.dumps(meta, indent=2))

        dropped = _prune(keep if keep is not None else keep_count())
        if dropped:
            detail.append("pruned %d old bundle(s)" % len(dropped))
        return {"ok": True, "name": name, "path": str(final), "size": size,
                "sha256": sha, "detail": "; ".join(detail)}
    except Exception as exc:  # noqa: BLE001 — never sink the scheduler/page
        return {"ok": False, "name": "", "path": "", "size": 0, "sha256": "",
                "detail": "%s: %s" % (type(exc).__name__, exc)}
    finally:
        try:
            stage.unlink(missing_ok=True)
        except OSError:
            pass


def _node_name() -> str:
    import socket
    try:
        return socket.gethostname()
    except Exception:  # noqa: BLE001
        return "node"


# ── external backup server (backup-server) ───────────────────────────────────────

def remote_dir() -> str:
    from . import settings_store as store
    cfg = store.backup_server()
    return posixpath.join(cfg.get("system_path") or "/system", REMOTE_SUBDIR)


def push_bundle_to_server(local_path: str) -> dict:
    """Upload one git bundle into ``<system_path>/git`` on backup-server. Thin
    wrapper over the SFTP put the DB bundles already use, so there is one
    connection/credential path for everything that leaves this box."""
    from . import backup_server as bksrv
    return bksrv.push_bundle(local_path, remote_dir=remote_dir())


def external_inventory() -> dict:
    """What git bundles are already on the backup server, for the side-by-side
    view. Never raises."""
    from . import backup_server as bksrv
    return bksrv.dir_inventory(remote_dir())


def external_download(name: str) -> bytes:
    if not NAME_RE.match(name or ""):
        raise ValueError("invalid bundle name")
    from . import backup_server as bksrv
    return bksrv.fetch_file(remote_dir(), name)
