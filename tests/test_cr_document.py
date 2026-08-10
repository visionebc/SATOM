"""Guards for the change-request DOCUMENT renderer.

No Flask app, no database, no fixtures: the CR is a plain object with the
attributes the renderer reads. That is the point — ``cr_document.render`` is a
pure function over the FROZEN snapshot handed to it, and a test that needed an
app context would be proving the opposite of the property under test.

The heavyweight guard here is :func:`test_german_text_is_not_linux_patching`:
the German document must describe a Fortinet firmware image swap + reboot, not
operating-system package patching. A document describing work that does not
happen is worse than no document, because the approver signs the wrong change.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime

import pytest

from app.services import cr_document


# --------------------------------------------------------------------------- #
#  Vocabulary that must NEVER reach the rendered document                       #
# --------------------------------------------------------------------------- #
#: Linux-patching German. Each entry is a phrase (or a distinctive fragment of
#: one) that would describe a completely different piece of work than the one
#: SATOM performs on a Fortinet appliance.
FORBIDDEN_DE = (
    "Installation der neuesten Betriebssystem-Updates",
    "Betriebssystem-Updates",
    "Betriebssystem aktualisieren",
    "Aktualisierung installierter Pakete",
    "installierter Pakete",
    "Softwarepakete",
    "Paketmanager",
    "Paketquellen",
    "Sicherheitspatches einspielen",
    "Patchen des Betriebssystems",
    "Anmeldung am Server",
    "Einloggen auf dem Server",
    "apt-get",
    "yum update",
)

#: The same discipline in English.
FORBIDDEN_EN = (
    "operating-system updates",
    "operating system updates",
    "update installed packages",
    "installed packages",
    "package manager",
    "security patches",
    "log in to the server",
    "apt-get",
    "yum update",
)

ALL_ACTIONS = tuple(cr_document.ACTION_PROFILES)


# --------------------------------------------------------------------------- #
#  Stubs                                                                        #
# --------------------------------------------------------------------------- #
class StubCR:
    """The ChangeRequest fields the renderer is allowed to read."""

    _DEFAULTS = {
        "id": 42,
        "title": "FortiWeb fw08 firmware upgrade",
        "reason": "Security fixes required by the yearly review",
        "status": "approved",
        "action": "upgrade",
        "params": "{}",
        "device_ids": "[7]",
        "policies": json.dumps([{"device": "fw08", "device_id": 7,
                                 "policy": "DECOY-POLICY", "vserver": "vs1",
                                 "service": "HTTPS", "status": "enable"}]),
        "window_start": datetime(2026, 9, 12, 22, 0, 0),
        "window_end": datetime(2026, 9, 13, 2, 0, 0),
        "risk": "high",
        "rollback": "Boot the previous partition",
        "requested_by": "m.keller",
        "owner": "",
        "approved_by": "s.brunner",
        "approved_at": datetime(2026, 9, 1, 9, 30, 0),
        "notify_status": "drafted",
        "notify_to": "ops@example.com, noc@example.com",
        "final_notified_at": None,
        "result_summary": "",
        "crq_ref": "",
        "crq_url": "",
        "created_at": datetime(2026, 2, 3, 8, 0, 0),
        "updated_at": datetime(2026, 9, 1, 9, 30, 0),
    }

    def __init__(self, **kw):
        for key, value in self._DEFAULTS.items():
            setattr(self, key, value)
        for key, value in kw.items():
            setattr(self, key, value)


class StubCRWithProperties(StubCR):
    """Same, but exposing the model's convenience properties, so the renderer
    is proven to work with the real ORM shape as well as the raw columns."""

    @property
    def params_dict(self) -> dict:
        return json.loads(self.params or "{}")

    @property
    def device_ids_list(self) -> list:
        return json.loads(self.device_ids or "[]")


class StubDevice:
    def __init__(self, name, kind, host, **kw):
        self.name = name
        self.kind = kind
        self.host = host
        for key, value in kw.items():
            setattr(self, key, value)


def policy_rows():
    return [
        {"device": "fw08", "device_id": 7, "policy": "shop-prod",
         "vserver": "vs-ext", "service": "HTTPS", "status": "enable"},
        {"device": "fw08", "device_id": 7, "policy": "api-prod",
         "vserver": "vs-ext", "service": "HTTPS", "status": "enable"},
    ]


def prep_dict(**kw):
    base = {
        "appliance": "fw08",
        "generated_at": "2026-09-10T07:15:00",
        "firmware": "FortiWeb-VM 7.6.2,build0451",
        "permission": True,
        "backup": {"ok": True, "name": "fw08-20260910.conf", "stored": True},
        "health": {"ok": True, "text": "all good"},
        "services": {"ok": True, "probes": [
            {"target": {"policy": "shop-prod"}, "result": {"ok": True}},
            {"target": {"policy": "api-prod"}, "result": {"ok": False}},
        ]},
    }
    base.update(kw)
    return base


def section(text: str, number: int) -> str:
    """The body of section ``number`` only."""
    start = re.search(r"^## %d\. " % number, text, re.M)
    assert start, f"section {number} missing"
    nxt = re.search(r"^## %d\. " % (number + 1), text, re.M)
    return text[start.start():nxt.start() if nxt else len(text)]


# --------------------------------------------------------------------------- #
#  Structure                                                                    #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("lang", ["en", "de"])
def test_all_thirteen_sections_in_order(lang):
    out = cr_document.render(StubCR(), lang=lang, devices=[
        StubDevice("fw08", "fortiweb", "192.0.2.8")], policies=policy_rows(),
        prep=prep_dict())
    numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", out, re.M)]
    assert numbers == list(range(1, 14))
    for idx, title in enumerate(cr_document.SECTION_TITLES[lang], start=1):
        assert f"## {idx}. {title}" in out


@pytest.mark.parametrize("lang", ["en", "de"])
@pytest.mark.parametrize("action", ALL_ACTIONS)
def test_every_action_renders_all_sections(lang, action):
    out = cr_document.render(StubCR(action=action), lang=lang)
    numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", out, re.M)]
    assert numbers == list(range(1, 14))


def test_markdown_shape_is_readable_as_plain_text():
    out = cr_document.render(StubCR(), lang="de",
                             devices=[StubDevice("fw08", "fortiweb", "192.0.2.8")],
                             policies=policy_rows())
    assert out.startswith("# CR-2026-0042 — ")
    assert "| Feld | Wert |" in out           # GitHub-style table
    assert "|" in out and "---" in out
    assert "<" not in out.replace("<br>", "")  # no HTML sneaked in


# --------------------------------------------------------------------------- #
#  Rule 3 — the document must describe the work that actually happens           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("action", ALL_ACTIONS)
def test_german_text_is_not_linux_patching(action):
    out = cr_document.render(StubCR(action=action), lang="de",
                             devices=[StubDevice("fw08", "fortiweb", "192.0.2.8")],
                             policies=policy_rows(), prep=prep_dict())
    lowered = out.lower()
    for phrase in FORBIDDEN_DE:
        assert phrase.lower() not in lowered, (
            f"{action}: German document contains Linux-patching vocabulary "
            f"{phrase!r} — it describes work SATOM does not perform")


@pytest.mark.parametrize("action", ALL_ACTIONS)
def test_english_text_is_not_linux_patching(action):
    out = cr_document.render(StubCR(action=action), lang="en",
                             devices=[StubDevice("fw08", "fortiweb", "192.0.2.8")],
                             policies=policy_rows(), prep=prep_dict())
    lowered = out.lower()
    for phrase in FORBIDDEN_EN:
        assert phrase.lower() not in lowered, (
            f"{action}: English document contains OS-patching vocabulary "
            f"{phrase!r}")


def test_upgrade_describes_image_upload_and_reboot():
    de = cr_document.render(StubCR(action="upgrade"), lang="de")
    assert "firmwareupgradedowngrade" in de
    assert "Partition" in de
    assert "Neustart" in de
    en = cr_document.render(StubCR(action="upgrade"), lang="en")
    assert "firmwareupgradedowngrade" in en
    assert "partition" in en.lower()
    assert "reboot" in en.lower()


# --------------------------------------------------------------------------- #
#  Language handling                                                            #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("value,expected", [
    (None, "en"),
    ("", "en"),
    ("   ", "en"),
    ("fr", "en"),
    ("klingon", "en"),
    (0, "en"),
    ("de", "de"),
    ("DE", "de"),
    (" De ", "de"),
    ("de-CH", "de"),
    ("de_DE", "de"),
    ("en", "en"),
    ("EN-GB", "en"),
])
def test_normalize_lang(value, expected):
    assert cr_document.normalize_lang(value) == expected


def test_normalize_lang_never_raises():
    class Exploding:
        def __str__(self):
            raise RuntimeError("boom")

    assert cr_document.normalize_lang(Exploding()) == cr_document.DEFAULT_LANG


def test_render_falls_back_to_default_lang():
    out = cr_document.render(StubCR(), lang="fr")
    assert f"## 1. {cr_document.SECTION_TITLES['en'][0]}" in out


def test_langs_shape():
    # With no catalogue rows (no app context here) the answer is the authored
    # set.  This is a FUNCTION now, not a constant: a module-level tuple could
    # only ever describe the languages written in Python and was therefore
    # blind to the translated catalogue.
    assert cr_document.document_langs() == (("en", "English"), ("de", "Deutsch"))
    assert cr_document.DEFAULT_LANG == "en"
    assert not hasattr(cr_document, "LANGS")


# --------------------------------------------------------------------------- #
#  Identity + filename                                                          #
# --------------------------------------------------------------------------- #
def test_change_ref_derives_from_created_at_and_id():
    assert cr_document.change_ref(StubCR()) == "CR-2026-0042"
    assert cr_document.change_ref(
        StubCR(id=7, created_at=datetime(2025, 1, 1))) == "CR-2025-0007"


def test_change_ref_prefers_explicit_ref():
    assert cr_document.change_ref(StubCR(ref="CR-2019-0001")) == "CR-2019-0001"
    # blank/whitespace ref falls back to the derived one
    assert cr_document.change_ref(StubCR(ref="   ")) == "CR-2026-0042"


def test_change_ref_never_invents_a_year():
    assert cr_document.change_ref(
        StubCR(created_at=None, window_start=None)) == "CR-0000-0042"


@pytest.mark.parametrize("lang", ["en", "de"])
def test_filename_is_safe(lang):
    cr = StubCR(title='Ünsafe: "prod"/DMZ <swap> | 100% * ?',
                ref='CR/2026 #42: Ünsafe\\name *')
    name = cr_document.filename(cr, lang)
    assert name.endswith(".md")
    assert "/" not in name and "\\" not in name
    assert " " not in name
    assert name.isascii()
    assert not re.search(r'[<>:"|?*]', name)
    assert name.endswith(f"-{lang}.md")


def test_filename_default_shape():
    assert cr_document.filename(StubCR(), "de") == "CR-2026-0042-de.md"
    assert cr_document.filename(StubCR(), "bogus") == "CR-2026-0042-en.md"


# --------------------------------------------------------------------------- #
#  Profile completeness (a half-translated profile ships a mixed document)      #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("action", ALL_ACTIONS)
@pytest.mark.parametrize("lang", ["en", "de"])
def test_profile_has_every_required_key_in_both_languages(action, lang):
    block = cr_document.ACTION_PROFILES[action][lang]
    for key in cr_document.REQUIRED_PROFILE_KEYS:
        assert key in block, f"{action}/{lang} is missing {key!r}"
        value = block[key]
        assert value, f"{action}/{lang}/{key} is empty"
        if key in ("rollback", "work", "validation"):
            assert isinstance(value, (list, tuple)) and len(value) >= 2
            assert all(isinstance(v, str) and v.strip() for v in value)
        else:
            assert isinstance(value, str) and value.strip()


def test_profiles_cover_the_registry_actions():
    expected = {"upgrade", "upgrade_prep", "reboot", "policy_set_status",
                "backend_set_status", "backend_set_config", "swap_certificate",
                "cert_lifecycle", "custom_rest", cr_document.GENERIC_ACTION}
    assert expected <= set(cr_document.ACTION_PROFILES)


def test_profile_for_unknown_action_returns_generic():
    generic = cr_document.ACTION_PROFILES[cr_document.GENERIC_ACTION]
    assert cr_document.profile_for("nonexistent") is generic
    assert cr_document.profile_for("") is generic
    assert cr_document.profile_for(None) is generic
    assert cr_document.profile_for(object()) is generic
    assert cr_document.profile_for("upgrade") is cr_document.ACTION_PROFILES["upgrade"]


def test_unknown_action_renders_with_generic_profile():
    out = cr_document.render(StubCR(action="teleport_appliance"), lang="de")
    assert "## 13." in out
    assert "nicht erfasst" in out


@pytest.mark.parametrize("action", [a for a in ALL_ACTIONS if a != "custom_rest"])
@pytest.mark.parametrize("lang", ["en", "de"])
def test_every_profiled_action_states_a_downtime(action, lang):
    out = cr_document.render(StubCR(action=action), lang=lang)
    label = "Geschätzte Ausfallzeit" if lang == "de" else "Estimated downtime"
    assert f"**{label}:**" in out
    line = [ln for ln in out.splitlines() if ln.startswith(f"**{label}:**")][0]
    assert len(line) > len(label) + 8


# --------------------------------------------------------------------------- #
#  Rule 4 — custom_rest promises nothing and prints the real call               #
# --------------------------------------------------------------------------- #
def _custom_rest_cr(**kw):
    params = {"method": "post", "endpoint": "/api/v2.0/cmdb/server-policy/policy",
              "mkey": "shop-prod", "label": "raise the buffer",
              "body": {"http-cache": "enable", "tcp-recv-buffer": 65536}}
    return StubCR(action="custom_rest", params=json.dumps(params),
                  risk="medium", **kw)


@pytest.mark.parametrize("lang", ["en", "de"])
def test_custom_rest_prints_the_literal_call(lang):
    out = cr_document.render(_custom_rest_cr(), lang=lang)
    work = section(out, 9)
    assert "POST" in work
    assert "/api/v2.0/cmdb/server-policy/policy" in work
    assert "shop-prod" in work
    assert '"http-cache": "enable"' in work
    assert '"tcp-recv-buffer": 65536' in work
    assert "```json" in work


@pytest.mark.parametrize("lang", ["en", "de"])
def test_custom_rest_never_estimates_minutes(lang):
    out = cr_document.render(_custom_rest_cr(), lang=lang,
                             devices=[StubDevice("fw08", "fortiweb", "192.0.2.8")],
                             policies=policy_rows(), prep=prep_dict())
    assert "Minuten" not in out
    assert "minutes" not in out.lower()
    assert not re.search(r"\d+\s*(?:-|–|to|bis)?\s*\d*\s*min\b", out, re.I)
    unknown = "unbekannt" if lang == "de" else "unknown"
    assert unknown in section(out, 5).lower()


def test_custom_rest_string_body_is_printed_verbatim():
    raw = '{"status": "disable"}'
    cr = StubCR(action="custom_rest", params=json.dumps(
        {"method": "PUT", "endpoint": "/api/v2.0/cmdb/x", "body": raw}))
    assert raw in section(cr_document.render(cr, lang="de"), 9)


def test_custom_rest_without_a_call_refuses_instead_of_inventing():
    cr = StubCR(action="custom_rest", params="{}")
    work = section(cr_document.render(cr, lang="de"), 9)
    assert "nicht erfasst" in work
    assert "nicht freigegeben" in work


# --------------------------------------------------------------------------- #
#  Rule 1 — the frozen inventory                                                #
# --------------------------------------------------------------------------- #
def test_policies_argument_is_the_only_source_for_section_10():
    rows = policy_rows()
    out = cr_document.render(StubCR(), lang="de", policies=rows)
    sec = section(out, 10)
    assert "shop-prod" in sec and "api-prod" in sec
    # the CR's own stored snapshot must NOT leak in on top of the passed one
    assert "DECOY-POLICY" not in out
    assert sec.count("| fw08 |") == 2


def test_policies_default_to_the_crs_own_frozen_snapshot():
    out = cr_document.render(StubCR(), lang="de")
    assert "DECOY-POLICY" in section(out, 10)


def test_empty_policies_list_is_explicit_not_a_fallback():
    out = cr_document.render(StubCR(), lang="de", policies=[])
    sec = section(out, 10)
    assert "DECOY-POLICY" not in sec
    assert "nicht erfasst" in sec


def test_render_takes_no_live_read(monkeypatch):
    """render() must work with nothing importable/attachable behind it."""
    before = set(sys.modules)
    out = cr_document.render(StubCR(), lang="de", devices=[
        StubDevice("fw08", "fortiweb", "192.0.2.8")], policies=policy_rows())
    new = set(sys.modules) - before
    leaked = [m for m in new
              if m.split(".")[0] in ("flask", "flask_sqlalchemy", "sqlalchemy")
              or m in ("app.models", "app.services.change_requests")]
    assert not leaked, f"render pulled in {leaked}"
    assert out
    # The absolute check ("flask is not in sys.modules") cannot hold in this
    # repo: conftest builds the Flask app for the rest of the suite, so by the
    # time this file runs flask is already imported by SOMEBODY. What matters is
    # that it is not imported by THIS module - asserted on the source below.


def test_the_module_itself_imports_nothing_stateful():
    """The purity claim, asserted where it is actually true: cr_document's own
    import graph. A DB or request-context read here is what would let the
    document describe a fleet the approver never saw."""
    import ast
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "app", "services", "cr_document.py")
    tree = ast.parse(open(path).read())
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
    for mod in names:
        root = (mod or "").split(".")[0]
        assert root not in ("flask", "flask_login", "sqlalchemy",
                            "flask_sqlalchemy"), mod
        assert mod not in ("..models", "app.models"), mod


def test_devices_use_getattr_defaults():
    """Devices without .firmware / .adom must still render."""
    bare = StubDevice("fac01", "fortiauthenticator", "192.0.2.9")
    out = cr_document.render(StubCR(), lang="de", devices=[bare])
    sec = section(out, 3)
    assert "fac01" in sec and "fortiauthenticator" in sec
    assert "nicht erfasst" in sec


def test_devices_render_optional_attributes():
    dev = StubDevice("fw08", "fortiweb", "192.0.2.8",
                     firmware="7.6.2,build0451", adom="prod")
    sec = section(cr_document.render(StubCR(), lang="en", devices=[dev]), 3)
    assert "7.6.2,build0451" in sec and "prod" in sec


# --------------------------------------------------------------------------- #
#  Rule 5 — missing data is explicit                                            #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("lang,placeholder", [("de", "nicht erfasst"),
                                              ("en", "not recorded")])
def test_bare_change_request_still_renders(lang, placeholder):
    cr = StubCR(title="", reason="", rollback="", requested_by="",
                approved_by="", approved_at=None, notify_to="",
                notify_status="", window_start=None, window_end=None,
                risk="", policies="[]", device_ids="[]", params="{}",
                result_summary="", status="draft", created_at=None,
                updated_at=None)
    out = cr_document.render(cr, lang=lang, devices=None, policies=None,
                             prep=None)
    numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", out, re.M)]
    assert numbers == list(range(1, 14))
    assert placeholder in out
    # no table cell is left empty — an empty cell reads as "nothing to report"
    for line in out.splitlines():
        if line.startswith("|") and "---" not in line:
            cells = [c.strip() for c in line.strip("|").split("|")]
            assert all(cells[:-1]), line   # last col = signature space


def test_no_devices_lists_the_recorded_ids():
    sec = section(cr_document.render(StubCR(device_ids="[7, 9]"), lang="de"), 3)
    assert "Erfasste Geräte-IDs: 7, 9" in sec
    assert "| Gerät |" not in sec          # no empty inventory table is drawn


def test_no_device_ids_at_all_says_so():
    sec = section(cr_document.render(StubCR(device_ids="[]"), lang="en"), 3)
    assert "No target devices are recorded" in sec


def test_missing_prep_leaves_every_box_unticked():
    sec = section(cr_document.render(StubCR(), lang="de", prep=None), 8)
    assert "- [x]" not in sec
    assert sec.count("- [ ]") >= 5


def test_prep_drives_the_prerequisites():
    sec = section(cr_document.render(StubCR(), lang="en", prep=prep_dict()), 8)
    assert "- [x]" in sec
    assert "fw08-20260910.conf" in sec
    assert "1 of 2 services reachable" in sec
    assert "FortiWeb-VM 7.6.2,build0451" in sec


def test_failed_prep_prints_the_error_and_leaves_the_box_unticked():
    prep = prep_dict(backup={"ok": False, "error": "SSHException: closed"},
                     health={"ok": False, "error": "timeout"})
    sec = section(cr_document.render(StubCR(), lang="en", prep=prep), 8)
    assert "SSHException: closed" in sec
    assert "timeout" in sec
    for line in sec.splitlines():
        if "SSHException" in line or "timeout" in line:
            assert line.startswith("- [ ]")


# --------------------------------------------------------------------------- #
#  Rule 2 — every timestamp carries a timezone                                  #
# --------------------------------------------------------------------------- #
def test_every_printed_timestamp_names_its_timezone():
    out = cr_document.render(StubCR(), lang="de", prep=prep_dict())
    stamps = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}([^|\n]*)", out)
    assert stamps, "no timestamp rendered at all"
    for tail in stamps:
        assert tail.strip(), "a timestamp was printed without a timezone"
        assert re.match(r"^[A-Za-z+\-0-9:]{2,9}", tail.strip()), tail


def test_window_date_row_carries_a_timezone():
    out = cr_document.render(StubCR(), lang="en")
    line = [ln for ln in out.splitlines()
            if "Maintenance window date" in ln][0]
    assert re.search(r"\d{4}-\d{2}-\d{2} [A-Za-z+\-0-9:]{2,9}", line), line


def test_missing_timestamp_prints_a_placeholder_not_an_epoch():
    out = cr_document.render(StubCR(window_end=None, approved_at=None),
                             lang="en")
    assert "1970" not in out
    assert "not recorded" in out


# --------------------------------------------------------------------------- #
#  Sections 12 + 13                                                             #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("lang", ["en", "de"])
def test_approvals_fill_only_the_row_satom_records(lang):
    sec = section(cr_document.render(StubCR(), lang=lang), 12)
    assert "s.brunner" in sec
    for role in cr_document._T[lang]["ap_roles"]:
        row = [ln for ln in sec.splitlines() if ln.startswith(f"| {role} |")]
        assert row, role
        assert "s.brunner" not in row[0]
    assert sec.count("s.brunner") == 1


def test_approvals_state_that_only_the_first_row_is_attested():
    sec = section(cr_document.render(StubCR(), lang="de"), 12)
    assert "ERSTE Zeile" in sec
    assert "approved_by" in sec


def test_unapproved_cr_does_not_fabricate_an_approver():
    sec = section(cr_document.render(
        StubCR(approved_by="", approved_at=None, status="draft"), lang="de"), 12)
    assert "nicht freigegeben" in sec
    assert "- [x]" not in sec


@pytest.mark.parametrize("status,marker", [
    ("completed", "Erfolgreich abgeschlossen"),
    ("failed", "Nicht erfolgreich"),
    ("cancelled", "Abgebrochen / nicht durchgeführt"),
])
def test_terminal_cr_ticks_exactly_one_outcome_box(status, marker):
    out = cr_document.render(
        StubCR(status=status, result_summary="firmware 7.6.2 active"),
        lang="de")
    sec = section(out, 13)
    ticked = [ln for ln in sec.splitlines() if ln.startswith("- [x]")]
    assert len(ticked) == 1
    assert marker in ticked[0]
    assert "firmware 7.6.2 active" in sec


@pytest.mark.parametrize("status", ["draft", "approved", "scheduled",
                                    "in_progress"])
def test_open_cr_ticks_no_outcome_box(status):
    sec = section(cr_document.render(StubCR(status=status), lang="en"), 13)
    assert "- [x]" not in sec
    assert "not closed yet" in sec


def test_outcome_without_summary_says_so():
    sec = section(cr_document.render(
        StubCR(status="failed", result_summary=""), lang="en"), 13)
    assert "No outcome description recorded" in sec


# --------------------------------------------------------------------------- #
#  Section 11                                                                   #
# --------------------------------------------------------------------------- #
def test_recipients_come_from_notify_to():
    sec = section(cr_document.render(StubCR(), lang="en"), 11)
    assert "ops@example.com" in sec and "noc@example.com" in sec


def test_no_recipients_is_a_refusal_to_guess():
    sec = section(cr_document.render(StubCR(notify_to=""), lang="en"), 11)
    assert "does not guess" in sec
    assert "not recorded" in sec


# --------------------------------------------------------------------------- #
#  Model-shaped input                                                           #
# --------------------------------------------------------------------------- #
def test_renders_with_the_orm_convenience_properties():
    cr = StubCRWithProperties(action="policy_set_status", params=json.dumps(
        {"policy": "shop-prod", "status": "disable"}))
    out = cr_document.render(cr, lang="de")
    work = section(out, 9)
    assert "`policy`" in work and "shop-prod" in work
    assert "`status`" in work and "disable" in work


def test_broken_json_columns_do_not_raise():
    cr = StubCR(params="{not json", device_ids="nope", policies="[[[")
    out = cr_document.render(cr, lang="de")
    assert "## 13." in out


# --------------------------------------------------------------------------- #
#  Owner (Verantwortlicher) — SATOM DOES model it since 2026-08-09             #
# --------------------------------------------------------------------------- #
def test_a_recorded_owner_is_printed_and_carries_no_footnote():
    """The footnote explains an ABSENCE. Printing it beside a filled-in owner
    tells the reader the field is unreliable when it is not."""
    cr = StubCR(owner="Dana Fischer")
    for lang in ("en", "de"):
        out = cr_document.render(cr, lang=lang)
        sec = section(out, 1)
        assert "Dana Fischer" in sec
        assert "filled in by hand" not in sec
        assert "handschriftlich" not in sec


def test_a_missing_owner_prints_the_placeholder_and_the_footnote():
    cr = StubCR(owner="")
    en = section(cr_document.render(cr, lang="en"), 1)
    de = section(cr_document.render(cr, lang="de"), 1)
    assert "filled in by hand" in en
    assert "handschriftlich" in de


def test_the_owner_is_never_derived_from_the_requester():
    """Guessing an accountable person is worse than an empty field: somebody
    signs a change believing a named human agreed to own it."""
    cr = StubCR(owner="", requested_by="alice")
    sec = section(cr_document.render(cr, lang="en"), 1)
    owner_line = [l for l in sec.splitlines() if "Owner" in l]
    assert owner_line, sec
    assert "alice" not in owner_line[0]
