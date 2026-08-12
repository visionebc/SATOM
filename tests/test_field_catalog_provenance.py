"""Guards for what the field-catalog harvest CLAIMS, not just what it extracts.

Four failures this file exists to prevent. None of them raises anything on its
own — each simply makes a true-looking statement false, which is why they all
survived in a repository with a large test suite:

1. The schema payload carried a frozen ``"generated_at": "2026-06-28"``. A harvest
   run today re-asserted a June date, so the one property a rebuild exists to
   deliver — freshness — was the one property the artefact could not report.

2. ``_safe_one()`` returns ``{}`` both for a table the operator never populated
   and for a URN the device rejects outright. The harvest printed the same
   "empty live object" line for both, so a dead registry entry
   (``system/network.interface`` -> errcode -20001) read as "nothing configured"
   and sat in the registry, reachable from the API Explorer, while
   ``interface`` — the object an operator is most likely to configure — silently
   had no field schema at all.

3. The firmware line was taken from the operator's environment variable and
   written into both the folder path and the ``source`` string verbatim; nothing
   asked the device what it actually runs. Pointing an 8.0 line at a 7.6.8 box
   produced a complete, well-formed, confidently-labelled 8.0 catalog built from
   7.6 data, with every artefact agreeing with every other artefact. This estate
   makes that the likely mistake, not an exotic one: there is no 8.0 FortiWeb
   left in it, while ``8.0/`` exists and was harvested from a box (``fw1``) that
   has since gone.

4. A ProvisionSpec may name a registry key the seed YAML does not define, so a
   fresh install carries a provisioning entry that can never harvest.

Pure + filesystem-only: no device contact, no app context.
"""
from __future__ import annotations

import inspect
import json
import os
import re

from scripts import build_field_catalog as h

REPO = os.path.dirname(os.path.dirname(os.path.abspath(h.__file__)))


def _uncommented(src: str) -> str:
    """Source with comments stripped.

    Several guards below assert that a name does NOT appear in a function body.
    The comment explaining the guard names it, so an unstripped search matches
    its own rationale and passes against broken code.
    """
    return "\n".join(ln.split("#", 1)[0] for ln in src.splitlines())


# --------------------------------------------------------------------------- #
#  1. provenance: the stamp comes from the clock                                #
# --------------------------------------------------------------------------- #
def test_the_harvest_stamps_when_it_ran_not_a_literal_date():
    """Asserted against the SOURCE of ``build``, because the value only exists
    inside a live harvest — a test that produced one would need a device."""
    body = _uncommented(inspect.getsource(h.build))
    assert not re.search(r'"generated_at"\s*:\s*["\']\d{4}-\d{2}-\d{2}', body), (
        "build() stamps a hard-coded date — every rebuild re-asserts it, so the "
        "artefact cannot report its own freshness"
    )
    assert '"generated_at": harvested_at' in body


def test_one_run_agrees_with_itself_about_when_it_happened():
    """Computed once per build, not per object: a long harvest whose objects
    disagree about when the pass ran looks like partial staleness that never
    happened."""
    src = inspect.getsource(h.build)
    assert len(re.findall(r"harvested_at\s*=\s*datetime\.now", src)) == 1


# --------------------------------------------------------------------------- #
#  2. an empty harvest explains WHICH kind of empty                             #
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _Client:
    def __init__(self, body=None, exc=None, status=None):
        self._body, self._exc, self._status = body, exc, status
        self.calls = []

    def api_call(self, method, path):
        self.calls.append((method, path))
        if self._exc is not None:
            raise self._exc
        return _Resp(self._body)

    def status_check(self):
        if self._exc is not None:
            raise self._exc
        return self._status


class _Appliance:
    def __init__(self, client):
        self._client = client

    def build_client(self):
        return self._client


def test_a_rejected_urn_is_named_as_a_registry_defect():
    a = _Appliance(_Client({"errcode": -20001, "message": "The REST API has invalid URL."}))
    reason = h.why_empty(a, "/api/v2.0/cmdb/system/network.interface")
    assert "-20001" in reason
    assert "registry" in reason.lower(), (
        "a URN the device rejects must point at the registry entry, not read as "
        "'nothing configured'"
    )


def test_an_unpopulated_table_is_named_as_not_a_defect():
    reason = h.why_empty(_Appliance(_Client({"results": []})), "/api/v2.0/cmdb/user/ldap-user")
    assert "not a defect" in reason.lower()
    assert "-20001" not in reason


def test_the_two_empties_do_not_read_the_same():
    """The entire point of the helper."""
    rejected = h.why_empty(_Appliance(_Client({"errcode": -20001, "message": "bad"})), "/x")
    unpopulated = h.why_empty(_Appliance(_Client({"results": []})), "/y")
    assert rejected != unpopulated


def test_errcode_zero_is_not_treated_as_an_error():
    """FortiWeb sends ``errcode: 0`` on success; reading that as a rejection
    would report a defect for every healthy-but-empty table."""
    reason = h.why_empty(_Appliance(_Client({"errcode": 0, "results": []})), "/z")
    assert "not a defect" in reason.lower()


def test_diagnosis_never_breaks_the_harvest():
    """``why_empty`` runs inside the harvest loop; raising here would abort a run
    over an object that was merely empty."""
    reason = h.why_empty(_Appliance(_Client(exc=RuntimeError("boom"))), "/x")
    assert "transport error" in reason.lower() and "RuntimeError" in reason


def test_diagnosis_issues_only_a_GET():
    """A diagnostic that wrote to the device would be a worse bug than the one it
    explains."""
    client = _Client({"results": []})
    h.why_empty(_Appliance(client), "/api/v2.0/cmdb/user/ldap-user")
    assert client.calls and all(m == "GET" for m, _ in client.calls)


def test_the_harvest_reports_the_reason_not_a_fixed_phrase():
    """build() must call why_empty at the empty-object site. Printing a constant
    string there is exactly the defect: two states, one message."""
    body = _uncommented(inspect.getsource(h.build))
    assert "why_empty(" in body, "build() no longer explains an empty harvest"


# --------------------------------------------------------------------------- #
#  3. the line is verified against the device, not asserted                     #
# --------------------------------------------------------------------------- #
def test_a_patch_release_belongs_to_its_line():
    assert h.line_matches_firmware("7.6", "7.6.8")
    assert h.line_matches_firmware("8.0", "8.0.5")
    assert h.line_matches_firmware("7.6", "7.6")


def test_a_different_line_does_not_match():
    assert not h.line_matches_firmware("8.0", "7.6.8")
    assert not h.line_matches_firmware("7.6", "8.0.5")


def test_a_line_is_not_matched_by_prefix_alone():
    """Naive ``startswith`` makes 7.60 a 7.6 build. Separate lines, and a schema
    filed across them describes fields the device does not have."""
    assert not h.line_matches_firmware("7.6", "7.60.1")


def test_an_unreadable_firmware_does_not_block_the_harvest():
    """Refusing to run against a box whose version cannot be read would turn a
    diagnostic into an outage; the banner says 'firmware unknown' instead."""
    assert h.line_matches_firmware("8.0", "")
    assert h.device_firmware(_Appliance(_Client(exc=RuntimeError("down")))) == ""


def test_the_firmware_is_read_from_the_device():
    a = _Appliance(_Client(status={"results": {"version": "FortiWeb-VM 7.6.8,build0123"}}))
    assert h.device_firmware(a) == "7.6.8"


def _fake_harvest(app, monkeypatch, line, firmware, allow_mismatch=False):
    """Drive build() end-to-end against a device on ``firmware``, writing nothing.

    Behavioural on purpose: an earlier version of this guard asserted that the
    name ``allow_mismatch`` appeared in build()'s source, and deleting the gate
    entirely left that name in the signature — so the guard passed against code
    that harvested a mislabelled catalog anyway. Returns the payloads build()
    tried to write.
    """
    from app.extensions import db
    from app.models import Appliance
    from app.registry import loader

    with app.app_context():
        if Appliance.query.filter_by(name="linefake").first() is None:
            db.session.add(Appliance(
                name="linefake", kind="fortiweb", host="linefake.invalid",
                username="probe", password_enc="x"))
            db.session.commit()

        written = []
        monkeypatch.setattr(h, "SOURCES", {"fortiweb": [(line, "linefake")]})
        monkeypatch.setattr(h, "device_firmware", lambda appliance: firmware)
        monkeypatch.setattr(h, "_live_object",
                            lambda appliance, urn: {"primary": "192.0.2.3"})
        monkeypatch.setattr(loader, "load_registry",
                            lambda: {"dns": "/api/v2.0/cmdb/system/dns"})
        monkeypatch.setattr(
            h, "_write_if",
            lambda path, payload, force: (written.append(payload), True)[1])

        h.build("fortiweb", allow_mismatch=allow_mismatch)
        return written


def test_build_writes_nothing_when_the_device_is_on_another_line(app, monkeypatch):
    """The check must GATE the harvest, not merely print. A warning that still
    writes produces exactly the mislabelled catalog it warned about — and one
    that is undetectable afterwards, because every artefact agrees."""
    written = _fake_harvest(app, monkeypatch, line="8.0", firmware="7.6.8")
    assert written == [], (
        "build() harvested a 7.6.8 device into line 8.0: %s"
        % [p.get("object") for p in written])


def test_a_matching_line_still_harvests(app, monkeypatch):
    """The gate must not be a blanket refusal — a guard that blocks everything
    passes the test above while breaking the tool."""
    written = _fake_harvest(app, monkeypatch, line="7.6", firmware="7.6.8")
    assert written, "build() refused a device that IS on the declared line"
    assert all(p["device_firmware"] == "7.6.8" for p in written)
    assert not any(p["line_mismatch"] for p in written)


def test_the_override_harvests_and_marks_every_artefact(app, monkeypatch):
    """--allow-line-mismatch is legitimate (an early-access build whose version
    string lags its line), but a schema built under protest has to say so, or the
    override is invisible to everyone downstream of the operator who typed it."""
    written = _fake_harvest(app, monkeypatch, line="8.0", firmware="7.6.8",
                            allow_mismatch=True)
    assert written, "the override did not let the harvest through"
    assert all(p["line_mismatch"] is True for p in written)
    assert all(p["device_firmware"] == "7.6.8" for p in written)


def test_the_override_is_recorded_in_the_artefact():
    """A schema built under protest has to say so, or the override is invisible
    to everyone downstream of the operator who typed it."""
    body = _uncommented(inspect.getsource(h.build))
    assert '"line_mismatch"' in body and '"device_firmware"' in body


# --------------------------------------------------------------------------- #
#  4. every provisioning spec names a harvestable endpoint                      #
# --------------------------------------------------------------------------- #
def _yaml_keys(path):
    keys = set()
    for line in open(path, encoding="utf-8"):
        m = re.match(r"^([A-Za-z0-9_.\-]+):\s+\S", line)
        if m:
            keys.add(m.group(1))
    return keys


def test_every_fortiweb_provisioning_spec_names_a_seeded_endpoint():
    from app.services import provisioning as prov

    seeded = _yaml_keys(os.path.join(REPO, "endpoints.yaml"))
    assert seeded, "endpoints.yaml parsed to zero keys — the parser is wrong, not the data"
    missing = sorted({s.endpoint for s in prov.PROVISION_CATALOG
                      if s.endpoint and s.endpoint not in seeded})
    assert not missing, (
        "provisioning specs reference endpoint keys absent from endpoints.yaml: %s"
        % missing)


def test_the_dead_network_interface_urn_is_not_reintroduced():
    """``system/network.interface`` is rejected by FortiWeb 7.6.8 (errcode -20001);
    the working URN is ``system/interface`` under the key ``interface_2``.
    Re-seeding the dead one puts it back in the API Explorer, where clicking it
    fails for a reason no message explains."""
    text = open(os.path.join(REPO, "endpoints.yaml"), encoding="utf-8").read()
    assert "system/network.interface" not in text


def test_the_interface_spec_points_at_the_working_key():
    from app.services import provisioning as prov

    spec = next(s for s in prov.PROVISION_CATALOG if s.key == "interface")
    assert spec.endpoint == "interface_2"


def test_the_provisioning_catalog_declares_no_duplicate_keys():
    """Two specs with one key make the schema filename ambiguous — the later
    harvest overwrites the earlier one's schema with no warning."""
    from app.services import provisioning as prov

    keys = [s.key for s in prov.PROVISION_CATALOG]
    dupes = sorted({k for k in keys if keys.count(k) > 1})
    assert not dupes, "duplicate ProvisionSpec keys: %s" % dupes


# --------------------------------------------------------------------------- #
#  5. the harvested artefacts on disk                                           #
# --------------------------------------------------------------------------- #
def _schema_files():
    from app.services import field_catalog as fc

    root = os.path.join(fc.SCHEMA_ROOT, "fortiweb")
    for line in sorted(os.listdir(root)):
        d = os.path.join(root, line)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if name.endswith(".json"):
                yield line, name, os.path.join(d, name)


def _harvested():
    """Only machine-harvested schemas. Hand-written seeds (``seed:``) legitimately
    carry protocol constants as defaults and a curated provenance string."""
    for line, name, path in _schema_files():
        d = json.load(open(path, encoding="utf-8"))
        if str(d.get("source", "")).startswith(("live:", "default<-")):
            yield line, name, d


def test_no_schema_carries_a_live_device_value_as_a_default():
    """A default harvested from the reference box publishes that estate's
    configuration to every install that reads the catalog."""
    leaked = ["%s/%s:%s=%r" % (line, name, f["name"], f["default"])
              for line, name, d in _harvested()
              for f in d["fields"] if f.get("default") not in ("", None, [], {})]
    assert not leaked, "harvested schemas carry live device values: %s" % leaked[:8]


def test_every_harvested_schema_records_where_and_when_it_came_from():
    """A date, not a guarantee of precision: artefacts harvested BEFORE the frozen
    stamp was fixed legitimately carry a date-only value, and rewriting them would
    invent a precision nobody measured. That the stamp now comes from the clock is
    guarded at the source, which is where the property lives."""
    bad = ["%s/%s -> %r" % (line, name, d.get("generated_at"))
           for line, name, d in _harvested()
           if not re.match(r"^\d{4}-\d{2}-\d{2}", str(d.get("generated_at", "")))]
    assert not bad, "harvested schemas without a usable timestamp: %s" % bad[:8]


def test_a_schema_harvested_after_the_fix_records_the_device_firmware():
    """Anything stamped with a full ISO instant came from the fixed harvester, so
    it must also carry what the box actually ran. Without it, a reader cannot tell
    a verified line from an asserted one."""
    bad = ["%s/%s" % (line, name) for line, name, d in _harvested()
           if "T" in str(d.get("generated_at", "")) and not d.get("device_firmware")]
    assert not bad, "post-fix schemas with no device firmware recorded: %s" % bad[:8]


def test_the_declared_line_matches_the_folder_it_sits_in():
    bad = ["%s/%s declares line %r" % (line, name, d.get("line"))
           for line, name, d in _harvested() if d.get("line") != line]
    assert not bad, bad


def test_no_schema_on_disk_was_harvested_from_the_wrong_firmware():
    """The end state the whole firmware check exists to protect: nothing in the
    catalog was built from a device outside its own line."""
    bad = []
    for line, name, d in _harvested():
        fw = d.get("device_firmware")
        if line == "_default" or not fw:
            continue
        if not h.line_matches_firmware(line, fw):
            bad.append("%s/%s built from %s" % (line, name, fw))
    assert not bad, bad
