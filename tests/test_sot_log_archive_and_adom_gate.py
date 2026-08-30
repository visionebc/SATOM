"""The change log stops being unbounded — by MOVING, never by discarding.

Why this file exists
--------------------
The previous round made the index permanent and gave it no knob at all, on the
grounds that a setting whose only effect is destroying the record is not a
policy. The operator then asked for the missing half: keep *some* window here
and put the rest on the backup server, from which it can be pulled back.

That is a legitimate request and it is also the most dangerous edit this store
has taken, because it is the first one that DELETES index rows on purpose. So
every guard below is about the conditions that must hold before a row may go:

* the archive file is off-box and the server *listed it back* at exactly the
  size that was written — never "the upload call returned without raising";
* the month is archived WHOLE, so the file is written once and frozen. A
  partial month would be rewritten later with fewer rows in it, replacing a
  complete archive with a truncated one;
* the snapshots those rows point at are already off-box, or the row's deletion
  orphans a local-only blob that the orphan sweep then removes — the archive
  would point at bytes that exist nowhere.

The second half of the file guards the ADOM gate: only an ACTIVE device family
gets a retention form, but a rule written before the family was switched off
keeps resolving, so hiding the form must not hide the rule.

Stubs sit at the SFTP boundary (``backup_server.dir_inventory`` /
``push_log_archive``) and the fake server is one dict that both of them see, so
"upload then list" is a real round trip rather than two independent lies.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

import pytest

from tests.conftest import admin_user_id, login


# --------------------------------------------------------------- helpers --

def _snap(marker: str = "a") -> dict:
    return {
        "device": "dev1", "generated_at": "2026-01-01T00:00:00",
        "total_objects": 1, "section_count": 1,
        "sections": {"System": {"global": [{"name": marker}]}},
    }


class FakeServer:
    """One dict standing in for the backup server, seen by both the upload
    and the listing. ``sot`` holds snapshot blobs, ``sot-log`` archive files."""

    def __init__(self, *, reachable=True, blobs=(), archives=None):
        self.reachable = reachable
        self.blobs = {n: 1 for n in blobs}
        self.archives = dict(archives or {})
        self.contents = {}
        self.uploads = []
        self.swallow_uploads = False

    def install(self, monkeypatch):
        from app.services import backup_server, settings_store
        monkeypatch.setattr(settings_store, "backup_server",
                            lambda reveal_secret=False: {
                                "configured": True, "host": "fm.example",
                                "system_path": "/system",
                                "config_path": "/configs",
                                "firmware_path": "/firmware", "port": 22,
                                "username": "bk", "password": "",
                                "password_enc": ""},
                            raising=False)

        def _dir_inventory(path):
            table = self.archives if path.endswith("/sot-log") else self.blobs
            return {"configured": True, "reachable": self.reachable,
                    "host": "fm.example", "path": path, "error": "",
                    "files": [{"name": n, "size": s, "mtime": "2026-01-01 00:00"}
                              for n, s in table.items()]
                    if self.reachable else []}

        def _push_log_archive(paths):
            pushed = skipped = 0
            for p in paths:
                name = os.path.basename(p)
                self.uploads.append(name)
                if name in self.archives:
                    skipped += 1
                    continue
                if self.swallow_uploads:
                    # The transfer "succeeds" and nothing lands. This is the
                    # shape a full disk or a wrong path takes.
                    pushed += 1
                    continue
                with open(p, "rb") as fh:
                    self.contents[name] = fh.read()
                self.archives[name] = os.path.getsize(p)
                pushed += 1
            return {"ok": True, "pushed": pushed, "skipped": skipped,
                    "detail": "fake"}

        monkeypatch.setattr(backup_server, "dir_inventory", _dir_inventory)
        monkeypatch.setattr(backup_server, "push_log_archive", _push_log_archive)
        return self


#: Two instants inside ONE calendar month, far enough in the past that any
#: retention window under ~10 years puts the whole month behind the cutoff.
#: Fixed datetimes, not day offsets: "400 and 380 days ago" straddles a month
#: boundary depending on the day the suite runs, so the number of archive
#: files the run produces would depend on the calendar. A guard that asserts
#: "one file" must not be answered differently in March than in April.
OLD_A = datetime(2024, 3, 5, 10, 0, 0)
OLD_B = datetime(2024, 3, 20, 10, 0, 0)
OLD_MONTH = "2024-03"


def _series(store, device, markers, ages):
    """Record one version per marker, back-dated to *ages* (a datetime, or a
    number of days before now), and mark every payload as already off-box —
    the common precondition for a row to be allowed to leave."""
    from app.extensions import db
    from app.models_sot import SotVersion
    rows = []
    for marker, age in zip(markers, ages):
        res = store.record(device, _snap(marker))
        row = db.session.get(SotVersion, res["version_id"])
        row.taken_at = (age if isinstance(age, datetime)
                        else datetime.utcnow() - timedelta(days=age))
        row.evacuated_at = datetime.utcnow()
        rows.append(row)
    db.session.commit()
    return rows


def _count(device="dev1"):
    from app.models_sot import SotVersion
    return SotVersion.query.filter_by(device=device).count()


# ======================================================= confirm, then delete

def test_the_log_leaves_only_after_the_server_lists_it_back(app, monkeypatch):
    """The happy path, and the shape of the whole feature: the rows are on the
    server, in full, BEFORE they stop being here."""
    from app.services import settings_store, sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "abc", [OLD_A, OLD_B, 0])
        shas = [r.sha256 for r in rows[:2]]
        srv = FakeServer(blobs=[f"{r.sha256}.json.gz" for r in rows]).install(monkeypatch)
        settings_store.save_sot_local_policy("", "", log_days=30)

        res = sot_store.archive_log("dev1")

        assert res["archived_rows"] == 2, res
        assert _count() == 1, "the recent row was archived away too"
        assert srv.archives, "nothing reached the backup server"
        name = next(iter(srv.archives))
        assert name.startswith("dev1-") and name.endswith(".jsonl"), name
        body = srv.contents[name].decode()
        assert len(body.strip().split("\n")) == 2
        for sha in shas:
            assert sha in body, \
                "a row was deleted here and is not in the file that replaced it"


def test_an_unreachable_server_archives_nothing(app, monkeypatch):
    """A listing that fails must read as "nothing is off-box". This is the one
    line that separates a retention policy from data loss."""
    from app.services import settings_store, sot_store
    with app.app_context():
        _series(sot_store, "dev1", "abc", [OLD_A, OLD_B, 0])
        FakeServer(reachable=False).install(monkeypatch)
        settings_store.save_sot_local_policy("", "", log_days=30)
        sot_store.archive_log("dev1")
        assert _count() == 3, "rows were deleted while the server was unreachable"


def test_an_upload_that_never_lands_deletes_nothing(app, monkeypatch):
    """The delete is authorised by the RE-LISTING, never by the upload call
    returning without an error. A push that reports success and lands nothing
    is what a full disk or a wrong remote path looks like."""
    from app.services import settings_store, sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "abc", [OLD_A, OLD_B, 0])
        srv = FakeServer(blobs=[f"{r.sha256}.json.gz" for r in rows]).install(monkeypatch)
        srv.swallow_uploads = True
        settings_store.save_sot_local_policy("", "", log_days=30)
        res = sot_store.archive_log("dev1")
        assert res["archived_rows"] == 0, res
        assert _count() == 3, "rows were deleted for a file the server does not have"


def test_a_frozen_month_is_never_overwritten(app, monkeypatch):
    """A name already on the server whose size disagrees is HELD, not replaced.
    Replacing it is how a complete archive would become a truncated one."""
    from app.services import settings_store, sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "abc", [OLD_A, OLD_B, 0])
        srv = FakeServer(blobs=[f"{r.sha256}.json.gz" for r in rows],
                         archives={f"dev1-{OLD_MONTH}.jsonl": 999999}).install(monkeypatch)
        settings_store.save_sot_local_policy("", "", log_days=30)
        res = sot_store.archive_log("dev1")
        assert srv.archives[f"dev1-{OLD_MONTH}.jsonl"] == 999999, \
            "a frozen archive file was overwritten"
        assert res["mismatched"] >= 1, res
        assert _count() == 3, "rows were deleted against an archive of another size"


def test_a_month_already_off_box_at_the_same_size_is_not_re_uploaded(app, monkeypatch):
    """Idempotence with teeth: a second run must finish the delete a crashed
    first run left half done, without sending the file again."""
    from app.services import settings_store, sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "abc", [OLD_A, OLD_B, 0])
        srv = FakeServer(blobs=[f"{r.sha256}.json.gz" for r in rows]).install(monkeypatch)
        settings_store.save_sot_local_policy("", "", log_days=30)
        first = sot_store.archive_log("dev1", dry_run=True)
        assert first["files"] == 1
        # Pre-seed the server with exactly what the run would write.
        from app.models_sot import SotVersion
        old = [r for r in SotVersion.query.filter_by(device="dev1").all()
               if r.taken_at < datetime.utcnow() - timedelta(days=60)]
        srv.archives[f"dev1-{OLD_MONTH}.jsonl"] = len(sot_store._archive_payload(old))
        srv.uploads.clear()
        res = sot_store.archive_log("dev1")
        assert res["archived_rows"] == 2, res
        assert srv.uploads == [], "a file the server already held was uploaded again"


def test_a_month_that_straddles_the_window_is_held_whole(app, monkeypatch):
    """Only calendar months entirely past the window are archived. Half a month
    would have to be written again later, shorter."""
    from app.services import settings_store, sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "ab", [3, 0])
        FakeServer(blobs=[f"{r.sha256}.json.gz" for r in rows]).install(monkeypatch)
        settings_store.save_sot_local_policy("", "", log_days=1)
        res = sot_store.archive_log("dev1")
        assert res["archived_rows"] == 0, \
            "a row from the current month was archived while the month is still open"
        assert _count() == 2


def test_a_month_whose_snapshot_is_not_off_box_is_held_whole(app, monkeypatch):
    """Deleting a row whose blob is local-only orphans that blob, and the
    orphan sweep then removes it: the archive would point at bytes that exist
    nowhere. One such row holds its whole month."""
    from app.extensions import db
    from app.services import settings_store, sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "abc", [OLD_A, OLD_B, 0])
        rows[0].evacuated_at = None          # still on this node...
        db.session.commit()
        FakeServer(blobs=[f"{rows[1].sha256}.json.gz"]).install(monkeypatch)  # ...and not off-box
        settings_store.save_sot_local_policy("", "", log_days=30)
        res = sot_store.archive_log("dev1")
        assert res["archived_rows"] == 0, res
        assert res["held_months"] >= 1, res
        assert _count() == 3


def test_the_archive_carries_every_field_of_every_row(app, monkeypatch, tmp_path):
    """The archive is the record after the rows are gone. A file that dropped
    a column would look like a successful archive and be a lossy one."""
    from app.services import sot_store
    from app.models_sot import SotVersion
    with app.app_context():
        rows = _series(sot_store, "dev1", "ab", [OLD_A, OLD_B])
        data = sot_store._archive_payload(rows)
        lines = [json.loads(x) for x in data.decode().strip().split("\n")]
        assert len(lines) == 2
        assert [x["sha256"] for x in lines] == [r.sha256 for r in
                                                sorted(rows, key=lambda r: r.taken_at)]
        for want in ("device", "taken_at", "product", "size_gz", "id"):
            assert want in lines[0], "%s is missing from the archive" % want


def test_the_archive_payload_is_deterministic(app):
    """The delete compares the size of what it would write against what the
    server holds. Bytes that varied between runs would make that comparison
    meaningless — and the comparison is what authorises the delete."""
    from app.services import sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "ab", [OLD_A, OLD_B])
        a = sot_store._archive_payload(rows)
        b = sot_store._archive_payload(list(reversed(rows)))
        assert a == b, "the archive bytes depend on row order"


def test_zero_days_never_trims(app, monkeypatch):
    """0 is the real, asked-for policy "keep the whole log here", not an unset
    value to be replaced by the default."""
    from app.services import settings_store, sot_store
    with app.app_context():
        rows = _series(sot_store, "dev1", "abc", [OLD_A, OLD_B, 0])
        FakeServer(blobs=[f"{r.sha256}.json.gz" for r in rows]).install(monkeypatch)
        settings_store.save_sot_local_policy("", "", log_days=0)
        assert sot_store._log_retention("") == 0
        sot_store.archive_log("dev1")
        assert _count() == 3, "trimming ran on a node that had switched it off"


def test_a_blank_box_is_the_default_not_never_trim(app):
    """A blank house field means "I did not choose". Reading it as the literal
    0 the floor now allows would switch trimming off for the whole node."""
    from app.services import settings_store, sot_store
    with app.app_context():
        settings_store.save_sot_local_policy("", "", log_days="")
        assert (settings_store.sot_local_policy("")["log_days"]
                == sot_store.DEFAULT_LOG_KEEP_DAYS)


def test_the_window_resolves_three_deep(app):
    from app.services import settings_store, sot_store
    with app.app_context():
        assert settings_store.sot_local_policy("fortiweb")["log_days_source"] == "default"
        settings_store.save_sot_local_policy("", "", log_days=90)
        assert settings_store.sot_local_policy("fortiweb")["log_days"] == 90
        assert settings_store.sot_local_policy("fortiweb")["log_days_source"] == "house"
        settings_store.save_sot_local_policy("", "", "fortiweb", log_days=7)
        assert settings_store.sot_local_policy("fortiweb")["log_days"] == 7
        assert settings_store.sot_local_policy("fortiweb")["log_days_source"] == "adom"
        assert sot_store._log_retention("fortiweb") == 7
        assert sot_store._log_retention("fortiadc") == 90


def test_a_caller_without_the_field_leaves_the_window_alone(app):
    """``log_days=None`` means "this form did not carry the field". A form that
    never showed it must not rewrite it — that is how the backup-server panel
    used to reset ``system_path`` on every save."""
    from app.services import settings_store
    with app.app_context():
        settings_store.save_sot_local_policy("", "", log_days=42)
        settings_store.save_sot_local_policy(3, 3)
        assert settings_store.sot_local_policy("")["log_days"] == 42


def test_an_override_of_only_the_window_still_counts_as_own(app):
    """``own`` decides whether the ADOM's boxes render filled or as
    placeholders. Missing this key would show a stored override as an empty
    box, and the next save of the other two fields would clear it unasked."""
    from app.services import settings_store
    with app.app_context():
        settings_store.set_str("sot.log_keep_days.fortiweb", "5")
        assert settings_store.sot_local_policy("fortiweb")["own"] is True


def test_offload_evacuates_before_it_archives(app, monkeypatch):
    """Order, not taste: a month may only be deleted once its snapshots are
    off-box, and the evacuation is what puts them there. Archiving first holds
    exactly the months this call makes eligible, so the trim lags a cycle."""
    from app.services import sot_store
    calls = []
    with app.app_context():
        monkeypatch.setattr(sot_store, "push_to_backup_server",
                            lambda: (calls.append("push"), {"ok": True, "detail": ""})[1])
        monkeypatch.setattr(sot_store, "evacuate",
                            lambda d="", **k: (calls.append("evacuate"),
                                               {"evacuated": 0, "bytes_freed": 0})[1])
        monkeypatch.setattr(sot_store, "archive_log",
                            lambda d="", **k: (calls.append("archive"),
                                               {"detail": "", "archived_rows": 0})[1])
        sot_store.offload()
    assert calls == ["push", "evacuate", "archive"], calls


# ============================================================== the ADOM gate

def _set_active(key: str, active: bool):
    from app.extensions import db
    from app.models_adom import Adom
    row = Adom.query.filter_by(key=key).first()
    if row is None:
        pytest.skip("ADOM registry not seeded in this fixture")
    row.active = active
    db.session.commit()


def _sot_pane(client) -> str:
    html = client.get("/settings/").get_data(as_text=True)
    marker = '<div class="tab-pane fade" id="tab-sot">'
    assert marker in html
    return html.split(marker, 1)[1].split('class="tab-pane', 1)[0]


def test_an_inactive_adom_gets_no_retention_form(app, client):
    """An inactive family is switched off across the whole console — its routes
    404 and it is gone from the selector. Offering a retention form for it
    invites an operator to tune a family this node does not manage."""
    login(client, admin_user_id(app))
    with app.app_context():
        _set_active("fortiadc", False)
    pane = _sot_pane(client)
    assert 'name="product" value="fortiweb"' in pane, "the active ADOM lost its form"
    assert 'name="product" value="fortiadc"' not in pane, \
        "an inactive ADOM is still offered a retention form"


def test_an_inactive_adom_that_still_governs_is_reported(app, client):
    """Hiding the form must not hide the RULE. A policy written before the
    family was switched off keeps resolving for every row filed under it."""
    from app.services import settings_store
    login(client, admin_user_id(app))
    with app.app_context():
        settings_store.save_sot_local_policy(4, 4, "fortiadc", log_days=9)
        _set_active("fortiadc", False)
    pane = _sot_pane(client)
    assert "Inactive ADOMs that still carry a rule" in pane, \
        "a rule that is still in force vanished with its form"
    assert "fortiadc" in pane


def test_a_dormant_override_can_still_be_cleared(app, client):
    """Validating the POST against the ACTIVE set would make the reported rule
    impossible to remove without psql."""
    from app.services import settings_store
    login(client, admin_user_id(app))
    with app.app_context():
        settings_store.save_sot_local_policy(4, 4, "fortiadc", log_days=9)
        _set_active("fortiadc", False)
    r = client.post("/settings/sot", data={"product": "fortiadc",
                                           "keep_versions": "", "keep_days": "",
                                           "keep_log_days": ""})
    assert r.status_code in (302, 303)
    with app.app_context():
        assert settings_store.sot_local_policy("fortiadc")["own"] is False, \
            "the override of a switched-off ADOM cannot be cleared"


def test_an_unknown_adom_is_still_refused(app, client):
    """Widening the POST to the registered set must not widen it to anything."""
    from app.services import settings_store
    login(client, admin_user_id(app))
    client.post("/settings/sot", data={"product": "fortimadeup",
                                       "keep_versions": "5", "keep_days": "5",
                                       "keep_log_days": "5"})
    with app.app_context():
        assert settings_store.get_str("sot.log_keep_days.fortimadeup", "") == ""


# ================================================================ what it says

def test_the_pane_states_the_log_is_moved_not_discarded(app, client):
    """The claim an operator acts on. Before this round the pane said the log
    was kept forever; it now has a window, and the sentence that makes that
    safe is the archive-before-delete order."""
    login(client, admin_user_id(app))
    pane = _sot_pane(client)
    assert "never thrown away" in pane
    assert "listed back at the exact size" in pane, \
        "the pane no longer states what authorises the delete"
    assert 'name="keep_log_days"' in pane, "the log window has no field"


def test_the_button_says_which_two_things_it_removes(app, client):
    """The operator asked what "push and evacuate" meant and whether it deleted
    their SoT. A button whose effect has to be guessed is the defect."""
    login(client, admin_user_id(app))
    pane = _sot_pane(client)
    assert "Free space on this node now" in pane
    assert "Upload and free space now" in pane
    assert "does NOT discard any history" in pane
    assert "push and evacuate" not in pane.lower(), \
        "the wording the operator could not decode is still on the page"
