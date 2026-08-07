"""Fail-open regressions: a broken input must never read as "no restriction".

Every guard here is BEHAVIOURAL — it calls the function and asserts the
outcome. None of them match on source text, so none of them can be satisfied
by a comment that happens to contain the right words.

The four shapes, and the counterweight for each:

* ``settings_store`` — a corrupt ``access.*`` row must not collapse into the
  empty list that ``app.__init__._access_gate`` reads as "unconfigured".
  Counterweight: unset / genuinely empty still means no restriction, because
  that is the shipped default and denying on it would lock out every install.
* ``git_backup._out`` — "git could not answer" must not look like "git said
  nothing", because the second is how a healthy repo with no unpushed work
  looks and the alert keys off exactly that.
  Counterweight: a first-run repo with no upstream is still not an error.
* ``self_update`` — a corrupt ``ha_nodes.json`` must not derive
  ``standalone`` and thereby disarm the staged-rollout interlock.
  Counterweight: an ABSENT registry is fair evidence of a single node, and an
  admin who set the mode explicitly still wins.
* ``theme_service.audit_contrast`` — an unparseable colour must produce a
  finding, not the same empty report a perfectly readable palette produces.
  Counterweight: the shipped palette still audits clean.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from app.services import git_backup as gb
from app.services import self_update as su
from app.services import settings_store as store
from app.services import theme_service as ts

from tests.conftest import admin_user_id, login, make_user


# ═══════════════════════════════════════════════════════════════════════════
# FIX 1 — access-control settings: malformed ≠ empty
# ═══════════════════════════════════════════════════════════════════════════

_MALFORMED = [
    '{"broken',                 # half-written value (interrupted write)
    'not json at all',          # hand-edited psql
    '[1, 2,',                   # truncated
    '{"admin": true}',          # valid JSON, wrong shape
    '"admin"',                  # valid JSON, wrong shape
    '42',                       # valid JSON, wrong shape
]


@pytest.mark.parametrize("raw", _MALFORMED)
@pytest.mark.parametrize("key", [store.K_ALLOWED_USERS, store.K_IP_WHITELIST])
def test_a_malformed_access_row_is_reported_not_silently_emptied(app, key, raw):
    with app.app_context():
        store.set_str(key, raw)
        err = store.access_config_error()
        assert err, ("%s=%r must be reported as unreadable, not read as "
                     "'no restriction'" % (key, raw))
        assert key in err, "the error must name the broken key, got %r" % err


@pytest.mark.parametrize("key", [store.K_ALLOWED_USERS, store.K_IP_WHITELIST])
def test_an_unset_access_row_is_not_an_error(app, key):
    """The shipped default. Denying here would lock out every install."""
    with app.app_context():
        assert store.access_config_error() == ""


@pytest.mark.parametrize("key", [store.K_ALLOWED_USERS, store.K_IP_WHITELIST])
def test_a_genuinely_empty_access_row_is_not_an_error(app, key):
    with app.app_context():
        store.set_str(key, "[]")
        assert store.access_config_error() == ""
        store.set_str(key, "")            # blank string, e.g. cleared by hand
        assert store.access_config_error() == ""


def test_a_populated_access_row_is_not_an_error(app):
    with app.app_context():
        store.save_allowed_users(["alice"])
        store.save_ip_whitelist([{"ip": "192.0.2.0/8", "note": "lan"}])
        assert store.access_config_error() == ""
        assert store.allowed_users() == ["alice"]
        assert [r["ip"] for r in store.ip_whitelist()] == ["192.0.2.0/8"]


@pytest.mark.parametrize("key", [store.K_ALLOWED_USERS, store.K_IP_WHITELIST])
def test_a_malformed_access_row_never_yields_phantom_entries(app, key):
    """`allowed_users()` iterating a str would hand back one entry per CHARACTER
    and `ip_whitelist()` would iterate dict KEYS. Neither may reach the gate."""
    with app.app_context():
        store.set_str(key, '"admin"')
        assert store.allowed_users() == []
        assert store.ip_whitelist() == []


# -- the gate itself (end-to-end through the real before_request) -----------

def _readonly_client(app):
    uid = make_user(app, username="ro-user", role="readonly")
    c = app.test_client()
    login(c, uid)
    return c


@pytest.mark.parametrize("key", [store.K_ALLOWED_USERS, store.K_IP_WHITELIST])
def test_the_gate_refuses_to_serve_a_non_admin_when_access_config_is_corrupt(app, key):
    c = _readonly_client(app)
    with app.app_context():
        store.set_str(key, '{"broken')
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 503, (
        "a corrupt %s admitted a non-admin with status %s — the allowlist "
        "collapsed to 'no restriction'" % (key, r.status_code))


def test_the_gate_still_admits_a_non_admin_when_nothing_is_configured(app):
    """Counterweight: empty lists = no restriction. This MUST keep working."""
    c = _readonly_client(app)
    r = c.get("/", follow_redirects=False)
    assert r.status_code not in (403, 503), (
        "unconfigured access control must not restrict anyone, got %s"
        % r.status_code)


def test_the_gate_still_denies_a_user_outside_a_valid_allowlist(app):
    c = _readonly_client(app)
    with app.app_context():
        store.save_allowed_users(["somebody-else"])
    r = c.get("/", follow_redirects=False)
    assert r.status_code == 403


def test_the_gate_never_restricts_an_admin_even_with_a_corrupt_config(app):
    """Lockout safety: the people who can FIX the row must still get in."""
    c = app.test_client()
    login(c, admin_user_id(app))
    with app.app_context():
        store.set_str(store.K_ALLOWED_USERS, '{"broken')
    r = c.get("/", follow_redirects=False)
    assert r.status_code not in (403, 503)


# ═══════════════════════════════════════════════════════════════════════════
# FIX 2 — git_backup: "command failed" ≠ "empty output"
# ═══════════════════════════════════════════════════════════════════════════

def _g(repo: Path, *args: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return (r.stdout or "").strip()


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)],
                   check=True)
    work = tmp_path / "work"
    subprocess.run(["git", "clone", "-q", str(origin), str(work)], check=True)
    _g(work, "config", "user.email", "t@example.invalid")
    _g(work, "config", "user.name", "test")
    (work / "f.txt").write_text("1")
    _g(work, "add", "-A")
    _g(work, "commit", "-qm", "first")
    _g(work, "push", "-q", "-u", "origin", "main")
    monkeypatch.setattr(gb, "_repo_root", lambda: work)
    return work


def test_out_returns_none_when_git_fails_and_a_string_when_it_succeeds(repo):
    ok = gb._out("rev-parse", "HEAD")
    assert isinstance(ok, str) and len(ok) == 40

    empty = gb._out("status", "--porcelain")
    assert empty == "", "a clean tree must be '' — git ran and said nothing"

    failed = gb._out("cat-file", "-p", "0" * 40)
    assert failed is None, ("a failed git command must be None, not %r — that "
                            "is the conflation the alert died of" % failed)


def test_unpushed_state_is_unknown_when_the_repo_cannot_be_read(tmp_path, monkeypatch):
    """`.git` gone / corrupt / safe.directory refusal: NOT a clean repo."""
    notrepo = tmp_path / "notrepo"
    notrepo.mkdir()
    monkeypatch.setattr(gb, "_repo_root", lambda: notrepo)
    st = gb.unpushed_state()
    assert st.get("unknown") is True, (
        "an unreadable repo reported %r — indistinguishable from a healthy "
        "repo with nothing to push" % st)
    assert st.get("error")


def test_unpushed_state_is_unknown_when_the_ahead_behind_probe_fails(repo, monkeypatch):
    """The exact fail-open: rev-list dies, ahead stays 0, no alert fires."""
    real = gb._git

    def flaky(*args, **kw):
        if args and args[0] == "rev-list":
            return subprocess.CompletedProcess(list(args), 128, "", "boom")
        return real(*args, **kw)

    monkeypatch.setattr(gb, "_git", flaky)
    st = gb.unpushed_state()
    assert st["upstream"] == "origin/main"
    assert st.get("unknown") is True, (
        "rev-list failed but unpushed_state reported %r" % st)


def test_unpushed_state_is_unknown_when_the_age_probe_fails(repo, monkeypatch):
    """ahead>0 but the age is unknowable — the alert thresholds on AGE, so a
    silent 0.0 there suppresses the finding just as effectively."""
    (repo / "f.txt").write_text("2")
    _g(repo, "commit", "-qam", "local only")
    real = gb._git

    def flaky(*args, **kw):
        if args and args[0] == "log":
            return subprocess.CompletedProcess(list(args), 128, "", "boom")
        return real(*args, **kw)

    monkeypatch.setattr(gb, "_git", flaky)
    st = gb.unpushed_state()
    assert st["ahead"] == 1
    assert st.get("unknown") is True, (
        "the oldest-commit probe failed but unpushed_state reported %r" % st)


# -- counterweights ---------------------------------------------------------

def test_a_freshly_pushed_repo_is_clean_and_not_unknown(repo):
    st = gb.unpushed_state()
    assert (st["ahead"], st["behind"]) == (0, 0)
    assert st["upstream"] == "origin/main"
    assert st.get("unknown") is False


def test_a_first_run_repo_without_an_upstream_is_not_unknown(tmp_path, monkeypatch):
    solo = tmp_path / "solo"
    solo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(solo)], check=True)
    monkeypatch.setattr(gb, "_repo_root", lambda: solo)
    st = gb.unpushed_state()
    assert st["upstream"] == "" and st["ahead"] == 0
    assert st.get("unknown") is False, (
        "no upstream configured is a normal first-run state, not an error")


def test_real_unpushed_work_is_still_counted(repo):
    (repo / "f.txt").write_text("2")
    _g(repo, "commit", "-qam", "local only")
    st = gb.unpushed_state()
    assert (st["ahead"], st["behind"]) == (1, 0)
    assert st.get("unknown") is False
    assert st["oldest_iso"]


def test_safety_refs_and_bundles_still_work_after_the_out_change(repo):
    _g(repo, "update-ref", "refs/backup/pre-reset-20260101-000000",
       _g(repo, "rev-parse", "HEAD"))
    assert [r["ref"] for r in gb.safety_refs()] == \
        ["refs/backup/pre-reset-20260101-000000"]
    res = gb.create_bundle(label="t", push_server=False)
    assert res["ok"], res["detail"]
    assert gb.list_bundles()[0]["branch"] == "main"


# ═══════════════════════════════════════════════════════════════════════════
# FIX 3 — self_update: a corrupt HA registry must not disarm the interlock
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw", ['{"broken', 'not json', '{"name": "peer"}',
                                 '', '   '])
def test_a_corrupt_node_registry_does_not_derive_standalone(app, tmp_path,
                                                            monkeypatch, raw):
    f = tmp_path / "ha_nodes.json"
    f.write_text(raw)
    monkeypatch.setattr(su, "NODES_FILE", f)
    with app.app_context():
        assert su.ha_mode() == "ha", (
            "an unreadable registry (%r) is not evidence of a single node" % raw)


@pytest.mark.parametrize("raw", ['{"broken', 'not json', '{"name": "peer"}'])
def test_a_corrupt_node_registry_keeps_the_staged_rollout_interlock_armed(
        app, tmp_path, monkeypatch, raw):
    """The payload: `can_apply_to_primary` must NOT wave the revision through
    just because the registry file could not be parsed."""
    f = tmp_path / "ha_nodes.json"
    f.write_text(raw)
    monkeypatch.setattr(su, "NODES_FILE", f)
    with app.app_context():
        assert su.can_apply_to_primary("deadbeefcafe") is False, (
            "a corrupt registry unlocked the primary without any standby "
            "validation")


def test_the_interlock_opens_once_the_standby_validated_that_exact_revision(
        app, tmp_path, monkeypatch):
    f = tmp_path / "ha_nodes.json"
    f.write_text('{"broken')
    monkeypatch.setattr(su, "NODES_FILE", f)
    with app.app_context():
        su.mark_validated("deadbeefcafe", "standby-1")
        assert su.can_apply_to_primary("deadbeefcafe") is True
        assert su.can_apply_to_primary("someothersha") is False


# -- counterweights ---------------------------------------------------------

def test_an_absent_registry_still_derives_standalone(app, tmp_path, monkeypatch):
    monkeypatch.setattr(su, "NODES_FILE", tmp_path / "nope.json")
    with app.app_context():
        assert su.ha_mode() == "standalone"
        assert su.can_apply_to_primary("anything") is True


def test_a_registry_holding_only_this_node_still_derives_standalone(
        app, tmp_path, monkeypatch):
    f = tmp_path / "ha_nodes.json"
    f.write_text(json.dumps([{"name": su.this_node_name(), "host": "127.0.0.1"}]))
    monkeypatch.setattr(su, "NODES_FILE", f)
    with app.app_context():
        assert su.ha_mode() == "standalone"


def test_an_empty_json_list_registry_still_derives_standalone(
        app, tmp_path, monkeypatch):
    f = tmp_path / "ha_nodes.json"
    f.write_text("[]")
    monkeypatch.setattr(su, "NODES_FILE", f)
    with app.app_context():
        assert su.ha_mode() == "standalone"


def test_a_valid_registry_with_a_peer_is_ha(app, tmp_path, monkeypatch):
    f = tmp_path / "ha_nodes.json"
    f.write_text(json.dumps([{"name": "peer-b", "host": "192.0.2.2"}]))
    monkeypatch.setattr(su, "NODES_FILE", f)
    with app.app_context():
        assert su.ha_mode() == "ha"


@pytest.mark.parametrize("mode", ["ha", "standalone"])
def test_an_explicit_admin_mode_still_wins_over_a_corrupt_registry(
        app, tmp_path, monkeypatch, mode):
    f = tmp_path / "ha_nodes.json"
    f.write_text('{"broken')
    monkeypatch.setattr(su, "NODES_FILE", f)
    with app.app_context():
        su.set_ha_mode(mode)
        assert su.ha_mode() == mode


# ═══════════════════════════════════════════════════════════════════════════
# FIX 4 — theme_service: an unparseable colour is a finding, not a skip
# ═══════════════════════════════════════════════════════════════════════════

_UNPARSEABLE = ["", "not-a-color", "#12345", "rgb(1,2)", "url(x)", "#GGGGGG"]


@pytest.mark.parametrize("bad", _UNPARSEABLE)
def test_an_unparseable_token_is_reported(bad):
    findings = ts.audit_contrast({"text-primary": bad})
    assert findings, ("%r produced the same empty report as a perfectly "
                      "readable palette" % bad)
    assert any(f["token"] == "text-primary" for f in findings)


@pytest.mark.parametrize("bad", _UNPARSEABLE)
def test_an_unparseable_token_blocks_the_unconfirmed_apply(bad):
    assert ts.has_unreadable({"text-primary": bad}) is True


def test_an_unparseable_background_is_reported_too(app):
    """The pair has two halves; breaking the surface hides the text as surely."""
    bg = ts.TOKENS["text-primary"]["on"]
    findings = ts.audit_contrast({bg: "nonsense"})
    assert findings
    assert any(f["token"] == "text-primary" for f in findings)


def test_unparseable_findings_keep_the_shape_the_ui_renders():
    findings = ts.audit_contrast({"text-primary": "nonsense"})
    assert findings
    for f in findings:
        for k in ("token", "label", "group", "against", "ratio", "level"):
            assert k in f, "missing %r in %r" % (k, f)
        assert isinstance(f["ratio"], (int, float))
        assert f["level"] in ("fail", "warn")


# -- counterweights ---------------------------------------------------------

def test_the_shipped_palette_still_audits_clean():
    assert ts.audit_contrast({}) == []
    assert ts.has_unreadable({}) is False


def test_every_shipped_alternate_theme_still_audits_clean():
    for spec in ts.BUILTINS:
        if spec["tokens"]:
            assert ts.audit_contrast(spec["tokens"]) == [], spec["name"]


def test_a_merely_low_contrast_pair_still_reports_its_real_ratio():
    findings = ts.audit_contrast({"text-primary": "#EDEDED"})
    assert findings and findings[0]["level"] == "fail"
    assert findings[0]["ratio"] > 0, "a parseable colour must keep its ratio"
