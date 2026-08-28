"""One tab called "SoT & Backup" held three unrelated subjects. These guard
the split into three entries that each name one.

Why this file exists
--------------------
Nothing failed while the three were one. The page rendered, the fields saved,
the suite was green — the word *SoT* simply covered more than it was true of,
and the reader acted on the wider meaning. That is a defect a test can only
catch by asserting the SEPARATION itself: the entries exist apart, each pane
says what it is *not*, and the one authority that is real is the only one
called a source of truth.

Two of the guards below are about the knob rather than the label, because the
split surfaced a setting that had never worked: ``sot_store`` read retention
through ``settings_store.get``, a function this product has never defined, so
every harvest raised ``AttributeError`` inside a blanket ``except`` and fell
back to the defaults. Writing the setting changed nothing and nothing said so.
A guard on the accessor's existence would not have caught it — the call site is
what was wrong — so the guards go through ``_retention`` itself.

Every assertion is scoped to the surface that must carry it. A whole-page
search is how a guard ends up answered by an unrelated paragraph; this repo has
retired more than a dozen of those, including three in the commit before this
one.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from tests.conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASIDE_OPEN = '<aside class="nav fw-settings-nav"'
PANE_OPEN = 'class="tab-pane'


def _page(client):
    return client.get("/settings/").get_data(as_text=True)


def _nav(html):
    nav = html.split(ASIDE_OPEN, 1)[1].split("</aside>", 1)[0]
    assert 'data-set-group="' in nav, "the aside slice is not the menu"
    return nav


def _pane(html, target):
    """The markup of ONE pane, from its own opening tag to the next pane.

    Scoping is the whole point of these guards: 'Configuration SoT' appears in
    the menu, in three panes and in a flash message, so asserting it against
    the page proves nothing about the pane that must carry it.
    """
    marker = '<div class="tab-pane fade" id="%s">' % target
    assert marker in html, "pane %s is not rendered" % target
    body = html.split(marker, 1)[1]
    nxt = body.find(PANE_OPEN)
    return body[:nxt] if nxt > 0 else body


def _admin(app, client):
    login(client, admin_user_id(app))


# --------------------------------------------------------------- the menu --

def test_the_two_authorities_are_separate_menu_entries(app, client):
    _admin(app, client)
    nav = _nav(_page(client))
    for target in ("tab-sot", "tab-backupsrv"):
        assert 'data-bs-target="#%s"' % target in nav, \
            "%s has no menu entry — the pane exists and nobody can reach it" % target


def test_the_tab_that_conflated_them_is_gone(app, client):
    _admin(app, client)
    html = _page(client)
    assert "tab-sotbackup" not in html, \
        "the merged SoT & Backup tab is still rendered"
    assert "SoT &amp; Backup" not in html and "SoT & Backup" not in html, \
        "a surface still labels three subjects with one authority's name"


def test_the_two_entries_form_a_group_of_their_own(app, client):
    """Filed back under System they would read as two knobs of the platform,
    which is the arrangement that made one entry of them in the first place."""
    _admin(app, client)
    nav = _nav(_page(client))
    chunks = nav.split('data-set-group="')[1:]
    group = next((c for c in chunks if c.split('"', 1)[0] == "sot"), None)
    assert group, "there is no 'sot' group in the menu"
    targets = re.findall(r'data-bs-target="#(tab-[a-z-]+)"', group)
    assert targets == ["tab-sot", "tab-backupsrv"], \
        "the group holds %s" % targets


def test_the_code_repository_entry_names_itself(app, client):
    """'Git' is a tool, not a subject. Three repositories-or-destinations were
    in play on this console and that label distinguished none of them."""
    _admin(app, client)
    nav = _nav(_page(client))
    entry = nav.split('data-bs-target="#tab-git"', 1)[1].split("</button>", 1)[0]
    assert "Software Update Repository" in entry, \
        "the update repository entry is labelled %r" % entry


# ------------------------------------------------- each pane disowns the others --

def test_the_sot_pane_sends_the_reader_to_the_other_two(app, client):
    _admin(app, client)
    pane = _pane(_page(client), "tab-sot")
    assert 'data-tab-jump="#tab-backupsrv"' in pane, \
        "the SoT pane does not point at the backup server"
    assert 'data-tab-jump="#tab-git"' in pane, \
        "the SoT pane does not point at the update repository"
    assert "Firmware" in pane, \
        "the SoT pane does not mention the firmware it excludes"


def test_the_backup_server_pane_denies_being_an_authority(app, client):
    _admin(app, client)
    pane = _pane(_page(client), "tab-backupsrv")
    assert "not an authority" in pane, \
        "the backup server pane does not say it is a destination"
    assert 'data-tab-jump="#tab-sot"' in pane, \
        "the backup server pane does not point at the real authority"


def test_the_update_repository_pane_disowns_config_and_backups(app, client):
    _admin(app, client)
    pane = _pane(_page(client), "tab-git")
    assert 'data-tab-jump="#tab-sot"' in pane and 'data-tab-jump="#tab-backupsrv"' in pane, \
        "the update repository pane names neither of the other two"


def test_the_jump_hook_is_not_named_after_one_pane(app, client):
    """It was `data-theme-jump`, bound inside the Appearance block. Reused from
    here, three cross-references would have depended on a handler that returns
    early when the theme form is absent."""
    _admin(app, client)
    html = _page(client)
    assert "data-theme-jump" not in html, "the pane-scoped hook name survived"
    assert html.count('data-tab-jump="') >= 5, \
        "only %d cross-references use the jump hook" % html.count('data-tab-jump="')


# --------------------------------------------- firmware is not a source of truth --

def test_no_settings_surface_offers_a_firmware_sot_repository(app, client):
    _admin(app, client)
    html = _page(client)
    assert "fw_repo_url" not in html and "fw_repo_branch" not in html, \
        "the retired firmware manifest repo still has a form field"


def test_the_retired_keys_survive_only_as_the_note_that_retires_them(app):
    src = (ROOT / "app" / "services" / "settings_store.py").read_text()
    # The keys may still be NAMED — the paragraph that retires them has to say
    # which ones, and that record is the part a reader needs. What may not
    # survive is a string LITERAL, because a literal is a key something can
    # read or write. An earlier version of this guard counted mentions and
    # failed against a perfectly correct file: the retirement note names both.
    assert '"sot.firmware_repo' not in src, \
        "a retired key is a string literal again, so something can read it"
    assert "Retired 2026-08-29" in src, "the record of why they went is gone"
    from app.services import settings_store
    for gone in ("firmware_repo", "save_firmware_repo", "K_FW_REPO_URL"):
        assert not hasattr(settings_store, gone), \
            "%s is still exported" % gone


def test_the_system_backup_page_no_longer_calls_the_archive_a_sot(app):
    tpl = (ROOT / "app" / "templates" / "system_backup" / "index.html").read_text()
    assert "manifest SoT" not in tpl, \
        "the firmware folder is still presented as a source of truth"
    assert "tab-sotbackup" not in tpl, "a dead deep link into the merged tab"


# ------------------------------------------------------- retention actually works --

def test_a_stored_retention_reaches_the_prune(app):
    """THE regression guard.

    ``_retention`` read ``settings_store.get``, which does not exist; the
    AttributeError was swallowed and the defaults returned. Asserting the
    accessor alone would not see that — the call site was what was wrong.
    """
    from app.services import settings_store, sot_store
    with app.app_context():
        settings_store.save_sot_retention(7, 9)
        assert sot_store._retention() == (7, 9), \
            "the configured retention is discarded: %r" % (sot_store._retention(),)


def test_nothing_stored_means_the_product_defaults(app):
    from app.services import settings_store, sot_store
    with app.app_context():
        cfg = settings_store.sot_retention()
        assert cfg["configured"] is False
        assert sot_store._retention() == (sot_store.DEFAULT_KEEP_VERSIONS,
                                          sot_store.DEFAULT_KEEP_DAYS)


@pytest.mark.parametrize("bad", ["0", "-4", "", "keep them all"])
def test_a_meaningless_value_is_not_read_as_keep_nothing(app, bad):
    """Zero through this path would make the next prune delete every version of
    every device — not a policy anyone types into a box labelled *keep*."""
    from app.services import settings_store, sot_store
    with app.app_context():
        settings_store.save_sot_retention(bad, bad)
        assert sot_store._retention() == (sot_store.DEFAULT_KEEP_VERSIONS,
                                          sot_store.DEFAULT_KEEP_DAYS)


# -------------------------------------------------------- one POST per pane --

def _srv(app):
    from app.services import settings_store
    with app.app_context():
        return settings_store.backup_server()


def test_saving_retention_leaves_the_backup_server_alone(app, client):
    """They shared one action, so saving a number rewrote the credentials —
    and a field deleted from one pane went on being written blank by the other.
    """
    from app.services import settings_store
    _admin(app, client)
    with app.app_context():
        settings_store.save_backup_server(
            {"host": "fm.example", "username": "bk", "password": "s3cret",
             "config_path": "/configs", "firmware_path": "/fw",
             "system_path": "/sys"})
    before = _srv(app)
    r = client.post("/settings/sot", data={"keep_versions": "5", "keep_days": "6"})
    assert r.status_code in (302, 303)
    after = _srv(app)
    assert after["host"] == before["host"] == "fm.example"
    assert after["system_path"] == "/sys", \
        "saving retention rewrote the backup server paths"


def test_saving_the_backup_server_leaves_retention_alone(app, client):
    from app.services import settings_store
    _admin(app, client)
    with app.app_context():
        settings_store.save_sot_retention(11, 12)
    client.post("/settings/backup-server",
                data={"host": "fm.example", "username": "bk",
                      "config_path": "/c", "firmware_path": "/f",
                      "system_path": "/s"})
    with app.app_context():
        cfg = settings_store.sot_retention()
    assert (cfg["versions"], cfg["days"]) == (11, 12), \
        "saving the backup server reset the SoT retention"


def test_the_system_path_is_on_the_form_it_is_saved_from(app, client):
    """It was read by the save with a default while absent from the form, so
    every submit quietly rewrote a customised value back to /system."""
    from app.services import settings_store
    _admin(app, client)
    pane = _pane(_page(client), "tab-backupsrv")
    assert 'name="system_path"' in pane, "the field the save writes is not on the form"
    client.post("/settings/backup-server",
                data={"host": "fm.example", "username": "bk",
                      "config_path": "/c", "firmware_path": "/f",
                      "system_path": "/bundles"})
    with app.app_context():
        assert settings_store.backup_server()["system_path"] == "/bundles"


@pytest.mark.parametrize("url,anchor", [("/settings/sot", "#tab-sot"),
                                        ("/settings/backup-server", "#tab-backupsrv")])
def test_each_save_returns_to_the_pane_it_was_fired_from(app, client, url, anchor):
    _admin(app, client)
    r = client.post(url, data={"keep_versions": "5", "keep_days": "5",
                               "host": "fm.example", "username": "bk"})
    assert r.headers.get("Location", "").endswith(anchor), \
        "%s redirects to %r" % (url, r.headers.get("Location"))
