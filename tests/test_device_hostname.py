"""Guards for the device's OWN hostname — captured, stamped, and displayed.

The workspace chrome used to print the management address where it identifies
the box. Replacing it with a name is only an improvement if the name is the
DEVICE's; a row's ``name`` is a label an operator typed, and the two can
disagree without anything noticing.

**Why the fixtures below look deliberately awkward.** In this laboratory
``hostName`` == ``Appliance.name`` on both FortiWebs (measured 2026-08-27:
fortiweb12, fortiweb13). An implementation that read the WRONG field — or that
never read the device at all and echoed ``name`` — passes every test built
from the live fleet and fails the first time a customer's box is called
something else. So every fixture here makes the three strings differ:

    Appliance.name  = "edge-a"      (what the operator typed)
    Appliance.host  = "192.0.2.9"    (how SATOM reaches it)
    hostName        = "fwb-cluster-1"  (what the DEVICE calls itself)
"""
from __future__ import annotations

import pathlib
import re

import pytest

from app.extensions import db
from app.models import Appliance, display_host, host_title, hostname_is_shared
from app.services import firmware_probe as fp

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: A FortiWeb status payload with the three identifiers deliberately distinct.
_FWB_STATUS = {"results": {
    "firmwareVersion": "FortiWeb-KVM 7.6.8,build1128(GA.M),260602",
    "hostName": "fwb-cluster-1",
    "platformName": "FortiWeb-KVM",
    "serialNumber": "FVVM00UNLICENSED",
}}

#: FortiAuthenticator, measured on fac01 2026-08-27: a firmware string and NO
#: hostname field anywhere in the payload.
_FAC_STATUS = {"firmware": "FACVMKVM v8.0.3, build0099 (GA)", "sn": "FAC-X"}


class _Client:
    def __init__(self, payload):
        self._p = payload

    def status_check(self):
        return self._p


def _appliance(app, **kw):
    with app.app_context():
        a = Appliance(name=kw.get("name", "edge-a"),
                      kind=kw.get("kind", "fortiweb"),
                      host=kw.get("host", "192.0.2.9"), port=443,
                      username="admin", verify_ssl=False,
                      vdom=kw.get("vdom"))
        a.password = "x" if hasattr(Appliance, "password") else None
        if not hasattr(Appliance, "password"):
            a.password_enc = ""
        db.session.add(a)
        db.session.commit()
        return a.id


# ---------------------------------------------------------------------------
# 1. the probe reads the DEVICE's name, from the call it already makes
# ---------------------------------------------------------------------------
def test_probe_reads_hostname_not_the_operators_label(app, monkeypatch):
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        monkeypatch.setattr(type(a), "build_client",
                            lambda self, **kw: _Client(_FWB_STATUS))
        res = fp.read(a)
    assert res["ok"] is True
    assert res["hostname"] == "fwb-cluster-1"
    # the three strings must not have been confused for one another
    assert res["hostname"] not in ("edge-a", "192.0.2.9")


def test_probe_makes_no_extra_call_for_the_hostname(app, monkeypatch):
    """One status call per appliance is what makes this module safe on /api/v1.

    A hostname fetched from a second endpoint would double the cost of the
    fleet sweep and quietly break that promise.
    """
    calls = []

    class _Counting(_Client):
        def status_check(self):
            calls.append(1)
            return super().status_check()

    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        monkeypatch.setattr(type(a), "build_client",
                            lambda self, **kw: _Counting(_FWB_STATUS))
        fp.read(a)
    assert calls == [1]


def test_a_failed_probe_carries_an_empty_hostname(app, monkeypatch):
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        monkeypatch.setattr(type(a), "build_client",
                            lambda self, **kw: _Client({"results": {}}))
        res = fp.read(a)
    assert res["ok"] is False and res["hostname"] == ""


# ---------------------------------------------------------------------------
# 2. attestation: the timestamp is only written when a name was observed
# ---------------------------------------------------------------------------
def test_refresh_persists_the_hostname_and_stamps_it(app, monkeypatch):
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        monkeypatch.setattr(type(a), "build_client",
                            lambda self, **kw: _Client(_FWB_STATUS))
        res = fp.refresh(a)
        a = db.session.get(Appliance, aid)
        assert a.device_hostname == "fwb-cluster-1"
        assert a.device_hostname_at is not None
        assert res["hostname_changed"] is True
        # the operator's label is untouched — SATOM does not rename rows
        assert a.name == "edge-a" and a.host == "192.0.2.9"


def test_a_payload_without_a_hostname_stamps_nothing(app, monkeypatch):
    """FortiAuthenticator is this case, measured — not hypothetical.

    Its status payload has a firmware string and no hostname key at all. A
    single shared timestamp would say the hostname was checked at 14:02 when
    nothing ever carried one.
    """
    aid = _appliance(app, kind="fortiauthenticator", name="fac-a")
    with app.app_context():
        a = db.session.get(Appliance, aid)
        monkeypatch.setattr(type(a), "build_client",
                            lambda self, **kw: _Client(_FAC_STATUS))
        res = fp.refresh(a)
        a = db.session.get(Appliance, aid)
        assert res["ok"] is True                       # the firmware read fine
        assert a.firmware_checked_at is not None
        assert a.device_hostname is None
        assert a.device_hostname_at is None
        assert res["hostname_changed"] is False


def test_a_hostname_once_known_is_not_erased_by_a_silent_payload(app,
                                                                monkeypatch):
    """An answer without a name means UNKNOWN, not "the device has no name"."""
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        monkeypatch.setattr(type(a), "build_client",
                            lambda self, **kw: _Client(_FWB_STATUS))
        fp.refresh(a)
        stamped = db.session.get(Appliance, aid).device_hostname_at
        quiet = {"results": dict(_FWB_STATUS["results"])}
        quiet["results"].pop("hostName")
        monkeypatch.setattr(type(a), "build_client",
                            lambda self, **kw: _Client(quiet))
        fp.refresh(db.session.get(Appliance, aid))
        a = db.session.get(Appliance, aid)
        assert a.device_hostname == "fwb-cluster-1"
        assert a.device_hostname_at == stamped      # NOT re-stamped


# ---------------------------------------------------------------------------
# 3. what gets printed — one author, and it never invents a name
# ---------------------------------------------------------------------------
def test_display_host_prefers_the_device_name(app):
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        assert display_host(a) == "192.0.2.9"       # never observed -> address
        assert a.display_host == "192.0.2.9"
        a.device_hostname = "fwb-cluster-1"
        assert display_host(a) == "fwb-cluster-1"
        assert a.display_host == "fwb-cluster-1"


def test_display_host_ignores_a_blank_hostname(app):
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        a.device_hostname = "   "
        assert a.display_host == "192.0.2.9"


def test_display_host_never_falls_back_to_the_operator_label(app):
    """``name`` is not an identity the device confirmed."""
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        a.host = ""
        assert a.display_host != "edge-a"


def test_an_adom_row_says_the_hostname_is_the_chassis(app):
    aid = _appliance(app, name="edge-a@adom_prod", vdom="adom_prod")
    with app.app_context():
        a = db.session.get(Appliance, aid)
        a.device_hostname = "fwb-cluster-1"
        assert hostname_is_shared(a) is True
        t = host_title(a)
        assert "chassis" in t and "fwb-cluster-1" in t and "192.0.2.9" in t
        # it must not claim the ADOM itself is named that
        assert "This ADOM is called" not in t


def test_a_plain_device_gets_no_chassis_wording(app):
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        a.device_hostname = "fwb-cluster-1"
        assert hostname_is_shared(a) is False
        assert "chassis" not in host_title(a)


def test_the_default_root_vdom_is_not_an_adom(app):
    """Measured on fortiweb12/13 (2026-08-27): every FortiWeb carries
    ``vdom='root'`` whether or not ADOM mode is in use, so its presence proves
    nothing. Keying the chassis wording on it labelled two ordinary devices as
    shared chassis — a qualification firing where it does not apply, which
    teaches operators to ignore the one that does."""
    aid = _appliance(app, name="edge-a", vdom="root")
    with app.app_context():
        a = db.session.get(Appliance, aid)
        a.device_hostname = "fwb-cluster-1"
        assert hostname_is_shared(a) is False
        assert "chassis" not in host_title(a)


def test_a_mismatched_adom_suffix_is_not_trusted(app):
    """``appliance_name_parts`` refuses to strip a suffix that does not match
    ``vdom``; this must inherit that refusal rather than re-deriving it."""
    aid = _appliance(app, name="edge-a@adom_dev", vdom="adom_prod")
    with app.app_context():
        a = db.session.get(Appliance, aid)
        a.device_hostname = "fwb-cluster-1"
        assert hostname_is_shared(a) is False


def test_no_tooltip_when_there_is_nothing_to_qualify(app):
    aid = _appliance(app)
    with app.app_context():
        a = db.session.get(Appliance, aid)
        assert a.host_title == ""


# ---------------------------------------------------------------------------
# 4. the templates actually stopped printing the address
# ---------------------------------------------------------------------------
_WS = ROOT / "app/templates/workspace"


#: ``index.html`` is included for CONSISTENCY, not as a rendered surface:
#: ``workspace.index`` always redirects (to the current device, or to
#: /architecture/ when none is selected), so the template never reaches a
#: browser today. It is guarded anyway so a revival does not resurrect the
#: address chip — but nothing here proves it renders. ``browse.html`` and
#: ``policies.html`` were both verified over real HTTP against the live node.
@pytest.mark.parametrize("name", ["index.html", "browse.html", "policies.html"])
def test_workspace_chrome_prints_the_hostname(name):
    body = (_WS / name).read_text(encoding="utf-8", errors="replace")
    assert "display_host" in body, (
        f"{name} identifies the appliance; it must print display_host so the "
        "three surfaces cannot drift apart again")
    # a bare address print is the thing being removed
    assert not re.search(r"\{\{\s*(a|appliance)\.host\s*(\}\}|if\b)", body), (
        f"{name} still prints the raw management address as the identifier")


def test_the_tooltip_has_a_single_author():
    """Three templates writing this sentence is how its halves drift."""
    for name in ("index.html", "browse.html", "policies.html"):
        body = (_WS / name).read_text(encoding="utf-8", errors="replace")
        assert "Hostname reported by" not in body, (
            f"{name} inlines the tooltip text instead of calling host_title")


# ---------------------------------------------------------------------------
# 5. the migration reaches installations that predate the columns
# ---------------------------------------------------------------------------
def test_hostname_columns_are_in_the_boot_migration():
    src = (ROOT / "app/__init__.py").read_text()
    block = src.split("def _ensure_columns")[1].split("insp = inspect")[0]
    assert "'appliances'" in block
    assert "('device_hostname'" in block and "('device_hostname_at'" in block


def test_hostname_columns_have_no_default(app):
    """NULL means "never observed". A DEFAULT '' would be the same value the
    probe writes for a device that answered without one — two facts, one
    value, and no way to tell them apart afterwards."""
    src = (ROOT / "app/__init__.py").read_text()
    block = src.split("def _ensure_columns")[1].split("insp = inspect")[0]
    line = [ln for ln in block.splitlines() if "device_hostname" in ln]
    assert line and not any("DEFAULT" in ln.upper() for ln in line)
    cols = {c.name: c for c in Appliance.__table__.columns}
    assert cols["device_hostname"].nullable is True
    assert cols["device_hostname"].default is None
