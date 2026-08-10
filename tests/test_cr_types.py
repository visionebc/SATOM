"""Administrator-editable change types — the guards for what fails silently.

The Change Request picker and every sentence it contributes used to be
compiled into the product. Making them editable introduces four defects that
raise nothing at all, which is the only reason this file exists:

1. **An empty box that overrides.** "Leave it blank to keep the product's
   wording" is a promise about a value nobody typed. If an empty field is
   written through, a section of a signed document goes blank and no test,
   log or exception notices.
2. **A field renamed on one side.** ``cr_types.FIELDS`` and
   ``cr_document.REQUIRED_PROFILE_KEYS`` must name the same nine paragraphs. A
   rename on one side does not error — the override simply stops overriding,
   forever, and the editor keeps happily accepting text nothing reads.
3. **A change type that looks runnable.** A type an administrator invents has
   no executor. If "executable" were storable, somebody would tick it, the CR
   would bind a one-shot scheduled action, and the failure would surface at
   FIRE time — inside the window, resolving to zero targets, closing the
   change as failed hours after anyone could act on it.
4. **Retroactive rewording.** Correcting a paragraph today must not rewrite a
   document that was signed last month. The reprint would differ from the
   paper in the file, and nothing would say so.
"""
from __future__ import annotations

import io
import json
import re
from datetime import datetime
from pathlib import Path

import pytest

from conftest import admin_user_id, login

REPO = Path(__file__).resolve().parents[1]
BASE = REPO / "app" / "templates" / "base.html"


# --------------------------------------------------------------------------- #
#  helpers                                                                      #
# --------------------------------------------------------------------------- #
def _mk_type(key="cabling", *, label="Structured cabling work", lang="en",
             products=None, enabled=True, texts=None):
    from app.services import cr_types
    row = cr_types.upsert(key, source_lang=lang, products=(products or []),
                          enabled=enabled, sort_order=100, username="tester")
    payload = {"label": label}
    payload.update(texts or {})
    cr_types.save_texts(key, payload, source_lang=lang, username="tester")
    return row


def _mk_appliance(name="fwb-1", kind="fortiweb"):
    from app.extensions import db
    from app.models import Appliance
    a = Appliance(name=name, host=f"{name}.example.invalid", kind=kind)
    db.session.add(a)
    db.session.commit()
    return a


def _mk_cr(action="upgrade", *, status="draft", device_ids=None):
    from app.extensions import db
    from app.models import ChangeRequest
    cr = ChangeRequest(title="CR under test", reason="because",
                       status=status, action=action,
                       device_ids=json.dumps(device_ids or []),
                       policies="[]", risk="medium",
                       window_start=datetime.utcnow())
    db.session.add(cr)
    db.session.commit()
    return cr


# --------------------------------------------------------------------------- #
#  1. the two field lists are the same list                                     #
# --------------------------------------------------------------------------- #
def test_the_editable_profile_fields_are_the_documents_profile_fields():
    """A rename on one side does not raise — the override silently stops
    overriding and the editor keeps accepting text nothing reads."""
    from app.services import cr_document, cr_types
    editable = set(cr_types.FIELD_NAMES)
    assert set(cr_document.REQUIRED_PROFILE_KEYS) <= editable, (
        "a profile paragraph the document requires cannot be edited: "
        f"{set(cr_document.REQUIRED_PROFILE_KEYS) - editable}")


def test_the_draft_field_map_targets_the_keys_draft_fields_returns():
    from app.services import cr_document, cr_types
    assert set(cr_types._DRAFT_MAP.values()) == set(cr_document.DRAFT_FIELDS)


def test_every_editable_field_declares_a_known_widget_kind():
    from app.services import cr_types
    assert set(cr_types.FIELD_KINDS.values()) <= {"line", "para", "list"}


# --------------------------------------------------------------------------- #
#  2. executability is DERIVED, never stored                                    #
# --------------------------------------------------------------------------- #
def test_the_row_has_no_executable_column():
    """The whole defect in one assertion: a column here would be a checkbox in
    the editor, and a checkbox there is an outage at fire time."""
    from app.models_cr_types import CrChangeType
    cols = {c.name for c in CrChangeType.__table__.columns}
    for forbidden in ("executable", "runnable", "automated", "spec"):
        assert forbidden not in cols, (
            f"'{forbidden}' makes executability editable; it must be read from "
            f"the action registry every time it is asked")


def test_is_builtin_reads_the_action_registry(app):
    from app.models_cr_types import is_builtin
    with app.app_context():
        assert is_builtin("upgrade") is True
        assert is_builtin("cabling") is False
        assert is_builtin("") is False


def test_a_custom_type_is_reported_as_not_executable(app):
    from app.views.change_requests import cr_type_entries
    with app.app_context():
        _mk_type()
        entries = {e["key"]: e for e in cr_type_entries()}
        assert entries["cabling"]["executable"] is False
        assert entries["upgrade"]["executable"] is True


def test_scheduling_a_documentary_change_is_refused(app):
    """Not a 500 later — a refusal now, while somebody is still looking."""
    from app.services import change_requests as svc
    with app.app_context():
        _mk_type()
        cr = _mk_cr(action="cabling", status="approved")
        with pytest.raises(ValueError) as err:
            svc.schedule_change_request(cr.id, by="tester")
        assert "documentary" in str(err.value).lower()
        assert cr.scheduled_action_id is None


def test_scheduling_a_real_action_still_works(app):
    """The refusal must be about the missing executor, not about change types
    in general — otherwise the guard closes the feature it protects."""
    from app.extensions import db
    from app.models import ScheduledAction
    from app.services import change_requests as svc
    with app.app_context():
        cr = _mk_cr(action="upgrade", status="approved")
        action_id = svc.schedule_change_request(cr.id, by="tester")
        assert db.session.get(ScheduledAction, action_id) is not None


# --------------------------------------------------------------------------- #
#  3. an empty field is not an override                                         #
# --------------------------------------------------------------------------- #
def test_an_empty_field_keeps_the_shipped_paragraph(app):
    from app.services import cr_document, cr_types
    with app.app_context():
        cr_types.upsert("upgrade", source_lang="en", username="tester")
        cr_types.save_texts("upgrade", {name: "" for name in cr_types.FIELD_NAMES},
                            source_lang="en", username="tester")
        resolved = cr_types.profile_text("upgrade", "en")
        shipped = cr_document._profile_text("upgrade", "en")
        for field in cr_document.REQUIRED_PROFILE_KEYS:
            assert resolved[field] == shipped[field], (
                f"{field} was blanked by an empty box")


def test_one_filled_field_overrides_only_itself(app):
    from app.services import cr_document, cr_types
    with app.app_context():
        cr_types.upsert("upgrade", source_lang="en", username="tester")
        cr_types.save_texts("upgrade", {"impact": "Everything stops."},
                            source_lang="en", username="tester")
        resolved = cr_types.profile_text("upgrade", "en")
        shipped = cr_document._profile_text("upgrade", "en")
        assert resolved["impact"] == "Everything stops."
        for field in cr_document.REQUIRED_PROFILE_KEYS:
            if field == "impact":
                continue
            assert resolved[field] == shipped[field]


def test_the_resolved_profile_carries_no_editor_only_fields(app):
    """The resolved profile is what gets photographed onto an approved change.
    Editor-only fields (the proposed title/reason/rollback) belong to the FORM,
    not to the document: carrying them into the snapshot puts strings in an
    audit artifact that nothing on the signed page ever printed."""
    from app.services import cr_document, cr_types
    with app.app_context():
        _mk_type(texts={"draft_title": "T {devices}", "purpose": "Pull cable."})
        resolved = cr_types.profile_text("cabling", "en")
        assert set(resolved) == set(cr_document._profile_text("cabling", "en"))
        for editor_only in cr_types._DRAFT_MAP:
            assert editor_only not in resolved


def test_the_frozen_snapshot_matches_the_documents_field_set(app):
    from app.services import cr_document, cr_types
    with app.app_context():
        _mk_type(texts={"draft_reason": "R {devices}"})
        snap = cr_types.snapshot("cabling")
        assert set(snap) == {code for code, _label in cr_document.LANGS}
        for code in snap:
            assert set(snap[code]) == set(cr_document._profile_text("cabling", code))


def test_the_resolved_profile_never_loses_a_section(app):
    from app.services import cr_document, cr_types
    with app.app_context():
        _mk_type(texts={"purpose": "Pull new cable."})
        resolved = cr_types.profile_text("cabling", "en")
        for field in cr_document.REQUIRED_PROFILE_KEYS:
            assert field in resolved and resolved[field], (
                f"{field} missing from a type that overrode one field")


def test_a_list_field_becomes_lines_not_one_blob(app):
    """Sections 7/9/10 iterate. A single string would print one bullet made of
    the whole plan, which reads as a checklist with one item."""
    from app.services import cr_types
    with app.app_context():
        _mk_type(texts={"work": "Pull the cable.\nLabel both ends.\n\n"})
        resolved = cr_types.profile_text("cabling", "en")
        assert resolved["work"] == ("Pull the cable.", "Label both ends.")


# --------------------------------------------------------------------------- #
#  4. the renderer overlays, it does not replace                                #
# --------------------------------------------------------------------------- #
def test_render_with_a_partial_profile_keeps_every_other_section(app):
    from app.services import cr_document
    with app.app_context():
        cr = _mk_cr(action="upgrade")
        full = cr_document.render(cr, lang="en")
        partial = cr_document.render(cr, lang="en",
                                     profile={"impact": "Everything stops."})
        assert "Everything stops." in partial
        # The shipped downtime line is still printed: a caller handing in one
        # paragraph must not cost the document the other eleven.
        shipped = cr_document._profile_text("upgrade", "en")["downtime"]
        assert shipped in full and shipped in partial


def test_render_ignores_empty_values_in_an_injected_profile(app):
    from app.services import cr_document
    with app.app_context():
        cr = _mk_cr(action="upgrade")
        shipped = cr_document._profile_text("upgrade", "en")["downtime"]
        out = cr_document.render(cr, lang="en", profile={"downtime": ""})
        assert shipped in out, "an empty injected value blanked a section"


def test_render_without_a_profile_is_unchanged(app):
    from app.services import cr_document
    with app.app_context():
        cr = _mk_cr(action="upgrade")
        assert cr_document.render(cr, lang="en") == \
            cr_document.render(cr, lang="en", profile=None)


# --------------------------------------------------------------------------- #
#  5. a signed document keeps its words                                         #
# --------------------------------------------------------------------------- #
def test_approval_freezes_the_wording(app):
    from app.services import change_requests as svc, cr_document
    with app.app_context():
        cr = _mk_cr(action="upgrade", status="draft")
        svc.approve(cr.id, by="approver")
        frozen = cr.doc_profile_dict
        assert set(frozen) == {code for code, _label in cr_document.LANGS}, \
            "the snapshot must cover every language the document prints in"
        assert frozen["en"]["impact"]


def test_editing_a_type_does_not_rewrite_an_approved_document(app, client):
    """The retroactive-rewrite guard. Both documents render fine; only one of
    them is the one somebody signed."""
    from app.services import change_requests as svc, cr_types
    with app.app_context():
        cr = _mk_cr(action="upgrade", status="draft")
        svc.approve(cr.id, by="approver")
        cr_id = cr.id
        cr_types.upsert("upgrade", source_lang="en", username="tester")
        cr_types.save_texts("upgrade", {"impact": "REWRITTEN AFTER SIGNATURE"},
                            source_lang="en", username="tester")
    login(client, admin_user_id(app), product="fortiweb")
    r = client.get(f"/change-requests/{cr_id}/document?lang=en")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "REWRITTEN AFTER SIGNATURE" not in body, (
        "editing the change type rewrote a document that was already approved")


def test_a_draft_renders_the_current_wording(app, client):
    """A draft was signed against nothing, so it must show today's words —
    otherwise the editor's preview lies about what approval will print."""
    from app.services import cr_types
    with app.app_context():
        cr = _mk_cr(action="upgrade", status="draft")
        cr_id = cr.id
        cr_types.upsert("upgrade", source_lang="en", username="tester")
        cr_types.save_texts("upgrade", {"impact": "FRESH WORDING"},
                            source_lang="en", username="tester")
    login(client, admin_user_id(app), product="fortiweb")
    body = client.get(f"/change-requests/{cr_id}/document?lang=en").get_data(as_text=True)
    assert "FRESH WORDING" in body


# --------------------------------------------------------------------------- #
#  6. the picker                                                                #
# --------------------------------------------------------------------------- #
def test_a_custom_type_is_offered(app):
    from app.views.change_requests import cr_action_keys
    with app.app_context():
        _mk_type()
        assert "cabling" in cr_action_keys()


def test_a_disabled_type_is_not_offered(app):
    from app.services import cr_types
    from app.views.change_requests import cr_action_keys
    with app.app_context():
        _mk_type()
        cr_types.upsert("cabling", enabled=False, username="tester")
        assert "cabling" not in cr_action_keys()


def test_hiding_a_builtin_removes_it_from_the_form_only(app):
    """A menu is not a permission: the action stays in the registry and the
    executor still knows it."""
    from app.services import cr_types, scheduled_actions as sa
    from app.views.change_requests import cr_action_keys
    with app.app_context():
        cr_types.upsert("reboot", enabled=False, username="tester")
        assert "reboot" not in cr_action_keys()
        assert sa.get_spec("reboot") is not None


def test_the_catalog_answers_without_an_application_context():
    """``cr_action_keys`` answers "which dangerous actions are change
    controlled" — a property of the product. Needing a database for that would
    make the desync guard in test_cr_action_catalog untestable."""
    from app.services import scheduled_actions as sa
    from app.views.change_requests import cr_action_keys
    keys = cr_action_keys()
    assert "upgrade" in keys
    missing = [s.key for s in sa.ALL_ACTIONS.values()
               if s.needs_targets and (s.danger or s.scope == "user")
               and s.key not in keys]
    assert not missing


def test_a_type_with_no_product_is_offered_everywhere(app):
    from app.services import cr_types
    with app.app_context():
        _mk_type(products=[])
        keys = {r.key for r in cr_types.options_for(("fortianalyzer",))}
        assert "cabling" in keys


def test_a_type_scoped_to_a_product_is_not_offered_elsewhere(app):
    from app.services import cr_types
    with app.app_context():
        _mk_type(products=["fortiweb"])
        assert {r.key for r in cr_types.options_for(("fortiweb",))} == {"cabling"}
        assert not cr_types.options_for(("fortianalyzer",))


def test_a_renamed_builtin_is_offered_under_its_new_name(app):
    from app.services import cr_types
    from app.views.change_requests import cr_actions
    with app.app_context():
        cr_types.upsert("reboot", source_lang="en", username="tester")
        cr_types.save_texts("reboot", {"label": "Controlled restart"},
                            source_lang="en", username="tester")
        assert ("reboot", "Controlled restart") in cr_actions()


# --------------------------------------------------------------------------- #
#  7. the proposed sentences                                                    #
# --------------------------------------------------------------------------- #
def test_an_overridden_draft_sentence_keeps_the_devices_token(app):
    """The page substitutes the live selection into this token. A proposal
    that lost it would name no device at all and still read like a sentence."""
    from app.services import cr_document, cr_types
    with app.app_context():
        _mk_type(texts={"draft_reason": "Cabling on {devices} — approved window."})
        out = cr_types.draft_fields("cabling", "en")
        assert cr_document.DEVICES_TOKEN in out["reason"]
        assert "Cabling on" in out["reason"]


def test_an_overridden_draft_sentence_can_use_the_type_name(app):
    from app.services import cr_types
    with app.app_context():
        _mk_type(label="Structured cabling work",
                 texts={"draft_title": "{action} · {devices}"})
        assert cr_types.draft_fields("cabling", "en")["title"].startswith(
            "Structured cabling work · ")


def test_an_unknown_placeholder_prints_as_typed(app):
    """A typo must print as the typo AND must not cost the sentence its real
    placeholders. Raising loses the whole line; the naive except-and-return-
    the-original loses {devices}, so the change would name no device at all and
    still read like a finished sentence."""
    from app.services import cr_document, cr_types
    with app.app_context():
        # ``{action}`` is the discriminating placeholder: DEVICES_TOKEN is
        # literally "{devices}", so a formatter that gives up and returns the
        # source string unchanged still looks correct against it.
        _mk_type(label="Structured cabling work",
                 texts={"draft_reason": "{action} on {oops} at {devices}."})
        out = cr_types.draft_fields("cabling", "en")["reason"]
        assert "{oops}" in out, "the typo was swallowed"
        assert out.startswith("Structured cabling work on "), (
            "a typo elsewhere in the sentence cost it every real placeholder")
        assert cr_document.DEVICES_TOKEN in out


def test_a_field_left_alone_keeps_the_shipped_sentence(app):
    from app.services import cr_document, cr_types
    with app.app_context():
        cr_types.upsert("upgrade", source_lang="en", username="tester")
        cr_types.save_texts("upgrade", {"draft_title": "My title {devices}"},
                            source_lang="en", username="tester")
        out = cr_types.draft_fields("upgrade", "en")
        shipped = cr_document.draft_fields("upgrade", "en")
        assert out["title"] != shipped["title"]
        assert out["reason"] == shipped["reason"]
        assert out["rollback"] == shipped["rollback"]


# --------------------------------------------------------------------------- #
#  8. language fallback                                                         #
# --------------------------------------------------------------------------- #
def test_untranslated_text_falls_back_to_what_was_authored(app):
    """A German console with no German translation is served the English the
    administrator actually wrote — not the compiled paragraph they replaced.
    The two would otherwise contradict each other on the same page."""
    from app.services import cr_types
    with app.app_context():
        cr_types.upsert("upgrade", source_lang="en", username="tester")
        cr_types.save_texts("upgrade", {"impact": "Everything stops."},
                            source_lang="en", username="tester")
        assert cr_types.profile_text("upgrade", "de")["impact"] == \
            "Everything stops."


def test_a_translation_wins_in_its_own_language(app):
    from app.services import cr_types, translator
    with app.app_context():
        cr_types.upsert("upgrade", source_lang="en", username="tester")
        cr_types.save_texts("upgrade", {"impact": "Everything stops."},
                            source_lang="en", username="tester")
        translator.store_translation(
            cr_types.NAMESPACE, cr_types.text_key("upgrade", "impact"), "de",
            "Alles steht still.", source_text="Everything stops.",
            source_lang="en", model="test-model", username="tester")
        assert cr_types.profile_text("upgrade", "de")["impact"] == \
            "Alles steht still."
        assert cr_types.profile_text("upgrade", "en")["impact"] == \
            "Everything stops."


# --------------------------------------------------------------------------- #
#  9. saving and translating                                                    #
# --------------------------------------------------------------------------- #
def test_save_reports_only_what_changed(app):
    """The fan-out is driven off this list. Reporting unchanged fields would
    re-bill twelve paragraphs because one comma moved."""
    from app.services import cr_types
    with app.app_context():
        _mk_type()
        assert cr_types.save_texts("cabling", {"label": "Structured cabling work"},
                                   source_lang="en", username="t") == []
        assert cr_types.save_texts("cabling", {"label": "Cabling"},
                                   source_lang="en", username="t") == ["label"]


def test_translate_skips_a_field_with_no_source(app, monkeypatch):
    """An empty override means "use the product's text". Translating it would
    write four rows that override the compiled paragraph with nothing."""
    from app.services import cr_types, translator
    calls = []
    monkeypatch.setattr(translator, "fan_out",
                        lambda *a, **k: calls.append(a) or {
                            "ok": 1, "failed": 0, "skipped": 0,
                            "duration_ms": 1, "prompt_tokens": None,
                            "completion_tokens": None, "targets": {}})
    with app.app_context():
        _mk_type()          # only 'label' has text
        report = cr_types.translate_type("cabling", username="t")
        assert report["fields"]["purpose"] == {"status": "empty"}
        assert len(calls) == 1, "a field with no source text was translated"


def test_deleting_a_type_removes_its_text(app):
    from app.models_i18n import TranslationUnit
    from app.services import cr_types
    with app.app_context():
        row = _mk_type()
        assert TranslationUnit.query.filter(
            TranslationUnit.key.like("cabling.%")).count() >= 1
        cr_types.delete(row)
        assert cr_types.get("cabling") is None
        assert TranslationUnit.query.filter(
            TranslationUnit.key.like("cabling.%")).count() == 0


def test_deleting_a_type_leaves_its_change_requests_printable(app):
    """A category removed from the menu must not blank a document somebody
    signed."""
    from app.services import cr_types
    with app.app_context():
        row = _mk_type()
        cr = _mk_cr(action="cabling")
        cr_types.delete(row)
        from app.services import cr_document
        out = cr_document.render(cr, lang="en",
                                 profile=cr_types.profile_text("cabling", "en"))
        assert "cabling" in out


# --------------------------------------------------------------------------- #
#  10. keys                                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("raw,expect", [
    ("Structured cabling", "structured_cabling"),
    ("  DNS cut-over  ", "dns_cut_over"),
    ("///", ""),
])
def test_key_slugs(raw, expect):
    from app.services import cr_types
    assert cr_types.slugify_key(raw) == expect


@pytest.mark.parametrize("key", ["", "a", "9lives", "Bad Key", "x" * 65])
def test_bad_keys_are_refused(key):
    from app.services import cr_types
    assert cr_types.key_error(key)


# --------------------------------------------------------------------------- #
#  11. the editor is reachable, gated, and refuses to shadow a built-in         #
# --------------------------------------------------------------------------- #
def test_the_editor_needs_user_manage(app, client):
    from conftest import make_user, profile_id
    uid = make_user(app, username="ro", role="readonly",
                    profile_id=profile_id(app, "readonly"))
    login(client, uid, product="global")
    r = client.get("/administration/change-types/")
    assert r.status_code in (302, 403), \
        "a read-only user reached the change-type editor"


def test_creating_a_type_that_shadows_a_builtin_is_refused(app, client):
    from app.services import cr_types
    login(client, admin_user_id(app), product="global")
    r = client.post("/administration/change-types/new",
                    data={"key": "reboot", "label": "x", "source_lang": "en"},
                    follow_redirects=True)
    assert r.status_code == 200
    with app.app_context():
        row = cr_types.get("reboot")
        # A row may exist as an OVERRIDE later, but the create path must not be
        # what makes it: two rows disagreeing about executability is exactly the
        # ambiguity the picker cannot resolve.
        assert row is None


def test_the_editor_lists_the_builtin_types(app, client):
    login(client, admin_user_id(app), product="global")
    body = client.get("/administration/change-types/").get_data(as_text=True)
    assert "upgrade" in body and "reboot" in body


def test_a_created_type_lands_in_the_form(app, client):
    login(client, admin_user_id(app), product="global")
    client.post("/administration/change-types/new",
                data={"key": "Structured cabling",
                      "label": "Structured cabling work",
                      "source_lang": "en"}, follow_redirects=True)
    with app.app_context():
        from app.services import cr_types
        assert cr_types.get("structured_cabling") is not None
    body = client.get("/change-requests/new").get_data(as_text=True)
    assert "structured_cabling" in body


# --------------------------------------------------------------------------- #
#  12. navigation and routing — a live-looking entry that goes nowhere          #
# --------------------------------------------------------------------------- #
def _adom_keys():
    from app.services.product_scope import GLOBAL, concrete_products
    return sorted(concrete_products() | {GLOBAL})


HOME = {"global": "/", "fortiweb": "/web/", "fortiadc": "/adc/",
        "fortianalyzer": "/faz/", "fortiauthenticator": "/fac/"}


@pytest.mark.parametrize("adom", _adom_keys())
def test_change_types_is_in_every_admin_sidebar(app, client, adom):
    login(client, admin_user_id(app), product=adom)
    r = client.get(HOME[adom] + "?_adom=" + adom, follow_redirects=True)
    assert r.status_code == 200
    assert "Change Types" in r.get_data(as_text=True), \
        f"the {adom} console cannot navigate to the change-type editor"


@pytest.mark.parametrize("adom", _adom_keys())
def test_the_editor_answers_in_every_adom(app, client, adom):
    """A menu entry that REDIRECTS is worse than a missing one: it looks live."""
    login(client, admin_user_id(app), product=adom)
    r = client.get("/administration/change-types/?_adom=" + adom)
    assert r.status_code == 200, \
        f"{adom} bounced off the change-type editor ({r.status_code})"


def test_the_nav_entry_has_one_author():
    """Five inline copies is how the Automation group spent months existing in
    exactly one ADOM."""
    src = BASE.read_text(encoding="utf-8")
    assert src.count('partials/nav_cr_types.html') == \
        src.count('partials/nav_collection.html'), \
        "the Change Types entry is missing from an Administration block"
    assert 'Change Types' not in src, \
        "the nav entry was inlined into base.html instead of the partial"
