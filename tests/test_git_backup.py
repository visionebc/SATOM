"""Git repository backup: bundle store, unpushed detection, and the safety
guard the self-update runner runs before a destructive ``git reset --hard``.

The bundle tests build a real throwaway git repo (fast: a couple of commits)
because the whole point of the artifact is that ``git bundle verify`` and
``git clone <file>`` accept it — asserting on a mocked subprocess would prove
nothing about that.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import types
from pathlib import Path

import pytest

from app.services import git_backup as gb


# ── helpers ──────────────────────────────────────────────────────────────────

def _git(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return (r.stdout or "").strip()


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    """A tiny repo with an 'origin' the tests can push to / hold back from."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)],
                   check=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "-q", str(origin), str(work)], check=True)
    _git(work, "config", "user.email", "t@example.invalid")
    _git(work, "config", "user.name", "test")
    (work / "reports").mkdir()
    (work / "reports" / "dev.json").write_text('{"a": 1}')
    _git(work, "add", "-A")
    _git(work, "commit", "-qm", "first")
    _git(work, "push", "-q", "-u", "origin", "main")
    monkeypatch.setattr(gb, "_repo_root", lambda: work)
    return work


# ── name validation (this is the download/delete gate) ───────────────────────

@pytest.mark.parametrize("bad", [
    "", "evil.bundle", "../../etc/passwd", "satom-repo-2026.bundle",
    "satom-repo-20260101-000000.bundle/../x", "satom-repo-20260101-000000.tar",
])
def test_bundle_path_rejects_anything_we_did_not_write(repo, bad):
    assert gb.bundle_path(bad) is None


def test_delete_rejects_bad_name(repo):
    assert gb.delete_bundle("../../boom") == {"ok": False,
                                              "detail": "invalid bundle name"}


# ── the bundle itself ────────────────────────────────────────────────────────

def test_bundle_is_verifiable_and_clonable(repo):
    res = gb.create_bundle(label="t", push_server=False)
    assert res["ok"], res["detail"]
    path = Path(res["path"])
    assert path.exists() and res["size"] > 0
    assert len(res["sha256"]) == 64

    # git itself must accept it, and a clone must carry the history.
    subprocess.run(["git", "-C", str(repo), "bundle", "verify", str(path)],
                   check=True, capture_output=True)
    dest = path.parent.parent / "clone"
    subprocess.run(["git", "clone", "-q", str(path), str(dest)], check=True)
    assert (dest / "reports" / "dev.json").read_text() == '{"a": 1}'


def test_bundle_carries_the_refs_backup_safety_commits(repo):
    """The refs the update runner parks must survive into the off-box copy —
    that is the whole recovery story, so it is asserted, not assumed."""
    _git(repo, "update-ref", "refs/backup/pre-reset-20260101-000000",
         _git(repo, "rev-parse", "HEAD"))
    res = gb.create_bundle(label="t", push_server=False)
    assert res["ok"], res["detail"]
    out = subprocess.run(["git", "-C", str(repo), "bundle", "list-heads",
                          res["path"]], capture_output=True, text=True).stdout
    assert "refs/backup/pre-reset-20260101-000000" in out

    refs = gb.safety_refs()
    assert [r["ref"] for r in refs] == ["refs/backup/pre-reset-20260101-000000"]


def test_retention_prunes_oldest_and_keeps_metadata_in_step(repo):
    for _ in range(3):
        assert gb.create_bundle(label="t", push_server=False, keep=99)["ok"]
    names = [b["name"] for b in gb.list_bundles()]
    assert len(names) == 3
    assert names == sorted(names, reverse=True)          # newest first

    assert gb.create_bundle(label="t", push_server=False, keep=2)["ok"]
    kept = gb.list_bundles()
    assert len(kept) == 2
    # the sidecars of pruned bundles go with them (no orphan metadata)
    stale = [p for p in gb.bundle_dir().iterdir()
             if p.suffix == ".json" and p.name[:-5] not in
             {b["name"] for b in kept}]
    assert stale == []


def test_create_records_sha256_head_and_unpushed_count(repo):
    (repo / "reports" / "dev.json").write_text('{"a": 2}')
    _git(repo, "commit", "-qam", "local only — remote unreachable")
    res = gb.create_bundle(label="t", push_server=False)
    row = gb.list_bundles()[0]
    assert row["sha256"] == res["sha256"]
    assert row["unpushed"] == 1
    assert row["head"] == _git(repo, "rev-parse", "HEAD")[:12]


# ── unpushed detection (what the new alert fires on) ─────────────────────────

def test_unpushed_state_is_clean_right_after_a_push(repo):
    st = gb.unpushed_state()
    assert st["upstream"] == "origin/main"
    assert (st["ahead"], st["behind"]) == (0, 0)
    assert st["oldest_age_h"] == 0.0


def test_unpushed_state_ages_the_oldest_stranded_commit(repo):
    # Two local commits, the older one dated 30h ago: the alert keys off AGE,
    # not count — one commit stuck for days is the dangerous case.
    env = dict(os.environ, GIT_AUTHOR_DATE="2026-01-01T00:00:00+00:00",
               GIT_COMMITTER_DATE="2026-01-01T00:00:00+00:00")
    (repo / "reports" / "dev.json").write_text('{"a": 3}')
    subprocess.run(["git", "-C", str(repo), "commit", "-qam", "old"],
                   check=True, env=env)
    (repo / "reports" / "dev.json").write_text('{"a": 4}')
    _git(repo, "commit", "-qam", "newer")

    st = gb.unpushed_state()
    assert st["ahead"] == 2 and st["behind"] == 0
    assert st["oldest_iso"].startswith("2026-01-01")
    assert st["oldest_age_h"] > 24 * 30      # dated in the past → large age


def test_unpushed_state_survives_a_repo_without_upstream(tmp_path, monkeypatch):
    solo = tmp_path / "solo"
    solo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(solo)], check=True)
    monkeypatch.setattr(gb, "_repo_root", lambda: solo)
    st = gb.unpushed_state()
    assert st["upstream"] == "" and st["ahead"] == 0


# ── settings ────────────────────────────────────────────────────────────────

def test_save_config_clamps_and_round_trips(app):
    with app.app_context():
        cfg = gb.save_config({"keep": "999", "push_server": "on"})
        assert cfg == {"keep": 50, "push_server": True}
        assert gb.keep_count() == 50 and gb.push_enabled() is True

        assert gb.save_config({"keep": "not a number"})["keep"] == gb.DEFAULT_KEEP
        assert gb.push_enabled() is False          # checkbox absent = off


# ── the self-update safety guard ────────────────────────────────────────────

def _load_runner():
    """Import deploy/self_update_runner.py by path — it is a standalone root
    script, not part of the app package."""
    path = Path(__file__).resolve().parent.parent / "deploy" / "self_update_runner.py"
    spec = importlib.util.spec_from_file_location("_sur", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Recorder:
    """Stands in for the runner's ``git()``: records argv, returns canned rcs."""

    def __init__(self, answers):
        self.answers = answers        # first-arg → (rc, stdout)
        self.calls = []

    def __call__(self, *args, **kw):
        self.calls.append(args)
        rc, out = self.answers.get(args[0], (0, ""))
        if args[0] == "rev-list":
            rc, out = self.answers.get("rev-list", (0, "0"))
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")


class _Steps:
    def __init__(self):
        self.steps = []

    def step(self, name, ok=True, detail=""):
        self.steps.append((name, ok, detail))


def test_guard_is_a_no_op_when_there_is_nothing_to_lose(monkeypatch):
    sur = _load_runner()
    rec = _Recorder({"rev-list": (0, "0"), "status": (0, "")})
    monkeypatch.setattr(sur, "git", rec)
    st = _Steps()
    assert sur.preserve_local_commits("origin/main", "abc123", st) is None
    assert st.steps == []
    assert not any(c[0] == "update-ref" for c in rec.calls)


def test_guard_parks_local_commits_before_the_reset(monkeypatch):
    sur = _load_runner()
    rec = _Recorder({"rev-list": (0, "3"), "status": (0, "")})
    monkeypatch.setattr(sur, "git", rec)
    st = _Steps()
    assert sur.preserve_local_commits("origin/main", "abc123def456", st) is True

    ref_calls = [c for c in rec.calls if c[0] == "update-ref"]
    assert len(ref_calls) == 1
    assert ref_calls[0][1].startswith("refs/backup/pre-reset-")
    assert ref_calls[0][2] == "abc123def456"
    assert st.steps[0][0] == "preserve 3 local commit(s)" and st.steps[0][1]


def test_guard_reports_failure_so_the_caller_aborts(monkeypatch):
    """If the commits cannot be parked, losing them silently is worse than a
    deferred update — the runner must be told to stop."""
    sur = _load_runner()
    rec = _Recorder({"rev-list": (0, "2"), "status": (0, ""), "update-ref": (1, "")})
    monkeypatch.setattr(sur, "git", rec)
    st = _Steps()
    assert sur.preserve_local_commits("origin/main", "abc", st) is False


def test_guard_stashes_a_dirty_worktree_without_touching_it(monkeypatch):
    sur = _load_runner()
    rec = _Recorder({"rev-list": (0, "0"), "status": (0, " M reports/dev.json"),
                     "stash": (0, "deadbeef")})
    monkeypatch.setattr(sur, "git", rec)
    st = _Steps()
    # Nothing committed locally → nothing to abort over, but the dirty tree is
    # still parked. `stash create` builds a commit object without mutating the
    # index or worktree, so the update path that follows is unaffected.
    assert sur.preserve_local_commits("origin/main", "abc", st) is True
    assert ("stash", "create") == rec.calls[-2][:2]
    ref = [c for c in rec.calls if c[0] == "update-ref"][0]
    assert ref[1].endswith("-dirty") and ref[2] == "deadbeef"


def test_guard_does_not_abort_when_only_the_stash_fails(monkeypatch):
    """A dirty reports/ tree is normal (device_sync rewrites it between
    publishes) and regenerates on the next sync — not worth blocking on."""
    sur = _load_runner()
    rec = _Recorder({"rev-list": (0, "0"), "status": (0, " M x"), "stash": (1, "")})
    monkeypatch.setattr(sur, "git", rec)
    st = _Steps()
    assert sur.preserve_local_commits("origin/main", "abc", st) is True
    assert st.steps[-1][1] is False          # reported, not fatal


# ── the alert rule that closes the blind spot ───────────────────────────────
#
# Before this, `ahead>0 behind==0` — the exact signature of an unreachable
# remote — fired nothing at all: `git.diverged` needs behind>0 and `git.behind`
# needs behind>25. A silent push failure could last weeks unnoticed.

def _arm_git(monkeypatch, ahead, age_h, behind=0):
    from app.services import alerts, git_service
    monkeypatch.setattr(git_service, "git_info",
                        lambda: {"ahead": ahead, "behind": behind})
    monkeypatch.setattr(gb, "unpushed_state",
                        lambda: {"ahead": ahead, "behind": behind,
                                 "oldest_age_h": age_h, "upstream": "origin/main"})
    return alerts


def test_no_alert_while_the_lag_is_still_normal(app, monkeypatch):
    alerts = _arm_git(monkeypatch, ahead=2, age_h=1.0)   # default threshold 6h
    with app.app_context():
        assert alerts._check_git() == []


def test_alert_when_a_commit_stays_unpushed_past_the_threshold(app, monkeypatch):
    alerts = _arm_git(monkeypatch, ahead=3, age_h=9.0)
    with app.app_context():
        out = alerts._check_git()
    assert [a["key"] for a in out] == ["git.ahead_unpushed"]
    assert out[0]["severity"] == alerts.SEV_WARNING


def test_alert_escalates_to_critical_when_it_drags_on(app, monkeypatch):
    alerts = _arm_git(monkeypatch, ahead=12, age_h=72.0)  # > 8 × 6h
    with app.app_context():
        out = alerts._check_git()
    assert out[0]["severity"] == alerts.SEV_CRITICAL


def test_real_divergence_still_takes_priority(app, monkeypatch):
    """ahead AND behind means the histories forked — a worse problem than a
    stuck push, and it must not be masked by the new rule."""
    alerts = _arm_git(monkeypatch, ahead=3, age_h=99.0, behind=4)
    with app.app_context():
        assert [a["key"] for a in alerts._check_git()] == ["git.diverged"]
