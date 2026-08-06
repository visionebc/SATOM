"""Guards for the provisioning orchestrator, the two storage roles, the ESXi
shell transport and the ADOM boundary of device provisioning.

Every test here exists because the failure it prevents is SILENT — the page
renders, the request returns 200, and the damage is a half-built machine, a
reserved address and a DNS row nobody will clean up.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from app.extensions import db
from app.models_provision import (MODES, STEPS, HypervisorTarget,
                                  ProvisionRun)
from app.services import provision_runner as pr
from app.services.hypervisors.base import Capabilities, VmRef, VmSpec
from app.services.hypervisors.esxi_shell import (ALLOWED_BINARIES, EsxiShell,
                                                 SAFE_NAME)
from app.services.hypervisors.proxmox import ProxmoxClient
from app.services.hypervisors import HypervisorError

from conftest import admin_user_id, login

ROOT = pathlib.Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# the two Proxmox storage roles
# ---------------------------------------------------------------------------
#: Shape of a real /nodes/<n>/storage response on the fleet host: the stock
#: ``local`` carries ``import`` WITHOUT ``images``, every thin pool the reverse.
_STORAGE_ROWS = [
    {"storage": "local", "type": "dir", "active": 1, "avail": 60 * 1024 ** 3,
     "total": 100 * 1024 ** 3, "content": "backup,import,iso,vztmpl"},
    {"storage": "nvme2-2t", "type": "lvmthin", "active": 1,
     "avail": 1800 * 1024 ** 3, "total": 2000 * 1024 ** 3,
     "content": "images,rootdir"},
    {"storage": "dead", "type": "dir", "active": 0, "avail": 0, "total": 0,
     "content": "images,import"},
]


def _pve(monkeypatch, rows=None, vms=None):
    c = ProxmoxClient(host="pve.invalid", username="root@pam", password="x")

    def fake_call(method, path, **kw):
        if path.endswith("/storage"):
            return _STORAGE_ROWS if rows is None else rows
        if path == "/nodes":
            return [{"node": "n1", "status": "online"}]
        if path.startswith("/nodes/") and path.endswith("/qemu"):
            return vms if vms is not None else []
        if path.startswith("/cluster/resources"):
            return [{"vmid": 9, "name": "stale-cache", "node": "n1",
                     "status": "running", "type": "qemu"}]
        return []

    monkeypatch.setattr(c, "_call", fake_call)
    return c


def test_import_only_storage_survives_the_listing(monkeypatch):
    """The bug: filtering on ``images`` first dropped ``local`` before its
    ``import`` flag was ever read, so a host that CAN accept uploads was told
    to add a content type it already had."""
    c = _pve(monkeypatch)
    ids = [s["id"] for s in c.list_datastores("n1")]
    assert "local" in ids, "an import-capable storage must not be filtered out"
    assert "nvme2-2t" in ids
    assert "dead" not in ids, "inactive storage is not a provisioning target"


def test_the_two_roles_are_asked_separately(monkeypatch):
    c = _pve(monkeypatch)
    assert [s["id"] for s in c.import_datastores("n1")] == ["local"]
    assert [s["id"] for s in c.disk_datastores("n1")] == ["nvme2-2t"]


def test_capabilities_see_the_import_storage(monkeypatch):
    """The visible symptom of the bug was a false capability report."""
    c = _pve(monkeypatch)
    caps = c.capabilities()
    assert caps.upload_image is True
    assert caps.disk_import is True
    assert any("import-ready storage" in n for n in caps.notes)


def test_capabilities_still_say_no_when_no_storage_can_import(monkeypatch):
    """Anti-vacuity: the flag must be able to come out False, and the note has
    to name the fix rather than leaving a disabled button unexplained."""
    c = _pve(monkeypatch, rows=[_STORAGE_ROWS[1]])
    caps = c.capabilities()
    assert caps.upload_image is False
    assert any("'import' content type" in n for n in caps.notes)


def test_existence_is_answered_from_live_node_state_not_the_cache(monkeypatch):
    """``/cluster/resources`` is refreshed on pvestatd's cycle: a machine
    created seconds ago is genuinely absent from it. Answering "does it exist"
    from a cache reports a successful build as a failure."""
    fresh = [{"vmid": 100, "name": "just-created", "status": "stopped"}]
    c = _pve(monkeypatch, vms=fresh)
    names = [v["name"] for v in c.list_vms("n1")]
    assert names == ["just-created"]
    assert "stale-cache" not in names


def test_the_cluster_view_still_exists_for_the_nodeless_case(monkeypatch):
    c = _pve(monkeypatch, vms=[])
    assert [v["name"] for v in c.list_vms()] == ["stale-cache"]


# ---------------------------------------------------------------------------
# capability honesty
# ---------------------------------------------------------------------------
def test_every_capability_flag_defaults_to_false():
    """A backend opts in to what it proved. An unimplemented method must never
    leave a flag optimistically True."""
    caps = Capabilities()
    flags = [f for f in caps.__dataclass_fields__ if f != "notes"]
    assert flags, "anti-vacuity: there must be flags to check"
    for f in flags:
        assert getattr(caps, f) is False, f"{f} defaults to True"


def test_missing_for_full_provision_names_the_serial_console():
    caps = Capabilities(create_vm=True, disk_import=True, serial_console=False)
    gaps = caps.missing_for_full_provision()
    assert any("serial" in g for g in gaps)


# ---------------------------------------------------------------------------
# the shell transport
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("bad", [
    "foo; rm -rf /vmfs", "a b", "../escape", "$(whoami)", "", "-leading",
    "x" * 64, "back`tick`",
])
def test_shell_rejects_unsafe_names(bad):
    assert not SAFE_NAME.match(bad), f"{bad!r} must not be accepted"


@pytest.mark.parametrize("good", ["fortiweb11", "vm-1_a", "A.b-c"])
def test_shell_accepts_ordinary_names(good):
    """Anti-vacuity: a validator that rejects everything proves nothing."""
    assert SAFE_NAME.match(good)


def test_shell_refuses_a_binary_outside_the_allowlist():
    sh = EsxiShell("h", "root", "pw")
    with pytest.raises(HypervisorError) as e:
        sh.run(["curl", "http://evil"])
    assert "not permitted" in str(e.value)
    assert "curl" not in ALLOWED_BINARIES


def test_shell_probe_reports_unconfigured_rather_than_guessing(monkeypatch):
    """A flag set from an open port would promise a pipeline that dies three
    steps later, after an address and a DNS row were committed."""
    from app.services.hypervisors.esxi import EsxiClient
    c = EsxiClient(host="h", username="root", password="pw")
    st = c.shell_state()
    assert st.reachable is False
    assert "no shell credentials" in st.error
    assert st.remedy, "an unavailable path must name its remedy"


def test_capabilities_refuse_to_claim_an_unreachable_shell(monkeypatch):
    """capabilities() must derive the shell flag from the PROBE, not assume it.

    A free-licensed host with an unreachable shell has no write path at all,
    and saying otherwise sends a run off to reserve an address and a DNS row
    before it dies at machine creation.
    """
    from app.services.hypervisors.esxi import EsxiClient
    from app.services.hypervisors.esxi_shell import ShellState

    c = EsxiClient(host="h", username="root", password="pw")
    monkeypatch.setattr(c, "login", lambda: None)
    monkeypatch.setattr(c, "_about", {"apiType": "HostAgent"}, raising=False)
    monkeypatch.setattr(c, "license_info", lambda: {
        "edition_key": "esx.hypervisor.cpuPackageCoreLimited",
        "name": "vSphere 8 Hypervisor", "free": True,
        "evaluation_expired": True, "api_writable": False})
    monkeypatch.setattr(c, "shell_state",
                        lambda: ShellState(reachable=False,
                                           error="ssh refused", remedy="turn it on"))
    caps = c.capabilities()
    assert caps.create_vm is False
    assert caps.power_control is False
    assert any("shell transport unavailable" in n for n in caps.notes)


def test_capabilities_do_claim_a_shell_that_answered(monkeypatch):
    """Anti-vacuity: the refusal above must be about the probe result, not
    about capabilities() never granting the shell."""
    from app.services.hypervisors.esxi import EsxiClient
    from app.services.hypervisors.esxi_shell import ShellState

    c = EsxiClient(host="h", username="root", password="pw")
    monkeypatch.setattr(c, "login", lambda: None)
    monkeypatch.setattr(c, "_about", {"apiType": "HostAgent"}, raising=False)
    monkeypatch.setattr(c, "license_info", lambda: {
        "edition_key": "esx.hypervisor.cpuPackageCoreLimited",
        "name": "vSphere 8 Hypervisor", "free": True,
        "evaluation_expired": True, "api_writable": False})
    monkeypatch.setattr(c, "shell_state",
                        lambda: ShellState(reachable=True, version="VMware ESXi 8.0.3"))
    caps = c.capabilities()
    assert caps.create_vm is True
    assert caps.disk_import is True, "vmkfstools is the shell-only disk path"
    assert caps.ovf_import is False, "ImportVApp stays API-only and licence-gated"
    assert caps.serial_console is False, (
        "the shell does not create a scriptable console — full mode stays "
        "unavailable on ESXi at any licence tier")


def test_the_shell_never_enables_ssh_itself():
    """Turning on TSM-SSH is a durable change to someone else's security
    posture. SATOM prints the line; it does not run it."""
    src = (ROOT / "app" / "services" / "hypervisors" / "esxi_shell.py").read_text()
    exec_lines = [ln for ln in src.splitlines()
                  if not ln.strip().startswith("#")]
    body = "\n".join(exec_lines)
    for forbidden in ("HostServiceSystem", "StartService", "TSM-SSH\"",
                      "service start"):
        assert forbidden not in body, f"{forbidden} would enable SSH remotely"


# ---------------------------------------------------------------------------
# preflight / modes
# ---------------------------------------------------------------------------
def test_every_mode_has_a_plan_and_a_requirement_set():
    assert set(pr.MODE_STEPS) == set(MODES), "a mode without a plan is unrunnable"
    for m in MODES:
        assert m in pr.MODE_REQUIRES, f"{m} declares no capability requirements"
        for step in pr.MODE_STEPS[m]:
            assert step in STEPS, f"{m} plans an unknown step {step!r}"


def test_full_requires_a_serial_console_and_semi_does_not():
    """This is the whole reason modes exist: ESXi has no scriptable console."""
    assert "serial_console" in pr.MODE_REQUIRES["full"]
    assert "serial_console" not in pr.MODE_REQUIRES["semi"]


def test_config_only_needs_no_hypervisor_at_all():
    assert pr.MODE_REQUIRES["config_only"] == ()
    assert "vm_created" not in pr.MODE_STEPS["config_only"]


def test_stopping_modes_declare_why_they_stop():
    for m in ("semi", "vm_only"):
        assert pr.MODE_STOP_REASON.get(m), f"{m} stops without saying why"
        assert pr.MODE_STEPS[m][-1] != "done"


class _Caps:
    def __init__(self, **kw):
        self._c = Capabilities(**kw)

    def capabilities(self):
        return self._c


def _target_row(session, caps, name="t1", backend="proxmox"):
    row = HypervisorTarget(name=name, backend=backend, host="h.invalid",
                           username="u")
    row.password = "pw"
    session.add(row)
    session.commit()
    row.client = lambda timeout=30: _Caps(**caps)  # type: ignore[assignment]
    return row


def test_preflight_refuses_full_without_a_serial_console(app, session):
    with app.app_context():
        row = _target_row(session, dict(create_vm=True, power_control=True,
                                        serial_console=False))
        run = ProvisionRun(product="fortiweb", name="x", mode="full",
                           target_id=row.id)
        session.add(run)
        session.commit()
        import app.services.provision_runner as m
        orig = m._target
        m._target = lambda r: row
        try:
            out = m.preflight(run)
        finally:
            m._target = orig
    assert out["ok"] is False
    assert any("first-boot console" in b for b in out["blockers"])


def test_preflight_passes_semi_on_the_same_host(app, session):
    """Anti-vacuity: the refusal above must be about the capability, not about
    preflight rejecting everything."""
    with app.app_context():
        row = _target_row(session, dict(create_vm=True, power_control=True,
                                        serial_console=False), name="t2")
        run = ProvisionRun(product="fortiweb", name="y", mode="semi",
                           target_id=row.id)
        session.add(run)
        session.commit()
        import app.services.provision_runner as m
        orig = m._target
        m._target = lambda r: row
        try:
            out = m.preflight(run)
        finally:
            m._target = orig
    assert out["ok"] is True
    assert out["blockers"] == []


# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------
def test_rollback_does_not_release_an_address_the_operator_typed(app, session):
    """A hand-typed address is not ours to hand back to a pool."""
    with app.app_context():
        run = ProvisionRun(product="fortiweb", name="z", mode="config_only",
                           mgmt_ip="192.0.2.5", ip_from_ipam=False)
        session.add(run)
        session.commit()
        pr.rollback(run)
        assert run.status == "aborted"
        assert not any(e["step"] == "rollback:ip" for e in run.log())


def test_rollback_deletes_nothing_when_no_machine_was_recorded(app, session):
    """A machine SATOM did not create has no vm_ref and must never be touched.
    Inferring ownership from the current state of the world is how a rollback
    deletes somebody else's VM.

    The run is given a REAL, reachable target on purpose. An earlier version of
    this test used a run with no target at all, so a rollback that ignored
    ``vm_ref`` still could not delete anything — and the test passed for the
    wrong reason. What is asserted is that ``delete_vm`` is never *called*.
    """
    called: list = []

    class _Client:
        def delete_vm(self, ref):
            called.append(ref)

    with app.app_context():
        row = HypervisorTarget(name="rb-target", backend="proxmox",
                               host="h.invalid", username="u")
        row.password = "pw"
        session.add(row)
        session.commit()
        run = ProvisionRun(product="fortiweb", name="w", mode="vm_only",
                           target_id=row.id)
        session.add(run)
        session.commit()

        import app.services.provision_runner as m
        orig_t = m._target
        m._target = lambda r: type("T", (), {
            "name": "rb-target", "client": lambda self=None, timeout=30: _Client()
        })()
        try:
            m.rollback(run)
        finally:
            m._target = orig_t

        assert called == [], "rollback attempted a delete with no recorded machine"
        assert not any(e["step"] == "rollback:vm" for e in run.log())


def test_rollback_does_delete_when_a_machine_was_recorded(app, session):
    """Anti-vacuity: the guard above must be about ``vm_ref``, not about
    rollback being unable to delete anything at all."""
    called: list = []

    class _Client:
        def delete_vm(self, ref):
            called.append(ref)

    with app.app_context():
        run = ProvisionRun(product="fortiweb", name="w2", mode="vm_only")
        run.vm_ref = ('{"backend": "proxmox", "identifier": "100", '
                      '"name": "w2", "node": "n1", "raw": {}}')
        session.add(run)
        session.commit()

        import app.services.provision_runner as m
        orig_t = m._target
        m._target = lambda r: type("T", (), {
            "name": "rb-target", "client": lambda self=None, timeout=30: _Client()
        })()
        try:
            m.rollback(run)
        finally:
            m._target = orig_t

        assert len(called) == 1
        assert any(e["step"] == "rollback:vm" and e["ok"] for e in run.log())


def test_rollback_leaves_an_onboarded_appliance_registered(app, session):
    """By onboarding time the device was answering; deleting the record would
    orphan any harvest or note already attached to it."""
    with app.app_context():
        run = ProvisionRun(product="fortiweb", name="v", mode="config_only",
                           appliance_id=4242)
        session.add(run)
        session.commit()
        pr.rollback(run)
        entry = [e for e in run.log() if e["step"] == "rollback:appliance"]
        assert entry and "left registered" in entry[0]["detail"]


# ---------------------------------------------------------------------------
# settings: the autoflush self-clash
# ---------------------------------------------------------------------------
def test_first_save_of_a_target_is_not_rejected_as_its_own_duplicate(
        app, client):
    """With ``db.session.add()`` before the uniqueness query, autoflush pushes
    the pending INSERT to satisfy the very query looking for a duplicate, so
    every first-time save failed — and left a credential-less row behind."""
    login(client, admin_user_id(app), product="global")
    r = client.post("/settings/hypervisors/save", data={
        "name": "brand-new", "backend": "proxmox", "host": "pve.invalid",
        "username": "root@pam", "password": "s3cret", "enabled": "1"})
    assert r.status_code == 200, r.data[:400]
    assert r.get_json()["ok"] is True


def test_a_real_duplicate_is_still_rejected(app, client, session):
    """Anti-vacuity: the fix must not disable the check it reordered."""
    login(client, admin_user_id(app), product="global")
    for _ in range(2):
        r = client.post("/settings/hypervisors/save", data={
            "name": "dupe", "backend": "proxmox", "host": "h",
            "username": "u", "password": "p", "enabled": "1"})
    assert r.status_code == 400
    assert "already called" in r.get_json()["error"]


def test_secrets_never_cross_back_to_the_browser(app, client):
    login(client, admin_user_id(app), product="global")
    client.post("/settings/hypervisors/save", data={
        "name": "leaky", "backend": "proxmox", "host": "h",
        "username": "u", "password": "TOPSECRET", "enabled": "1"})
    body = client.get("/settings/hypervisors/state").get_data(as_text=True)
    assert "TOPSECRET" not in body


def test_a_blank_secret_on_edit_keeps_the_stored_one(app, client, session):
    """Treating blank as "erase" would silently break a working target every
    time somebody edited its name."""
    login(client, admin_user_id(app), product="global")
    r = client.post("/settings/hypervisors/save", data={
        "name": "keepme", "backend": "proxmox", "host": "h",
        "username": "u", "password": "orig", "enabled": "1"})
    tid = r.get_json()["target"]["id"]
    client.post("/settings/hypervisors/save", data={
        "id": str(tid), "name": "keepme2", "backend": "proxmox", "host": "h",
        "username": "u", "password": "", "enabled": "1"})
    with app.app_context():
        assert HypervisorTarget.query.get(tid).password == "orig"


# ---------------------------------------------------------------------------
# ADOM boundary
# ---------------------------------------------------------------------------
def test_device_provisioning_is_not_a_fortiweb_area():
    """Membership of ``fortiweb_scoped`` means "opening this from Global is an
    ADOM jump into FortiWeb". For a page mirrored into every ADOM that made
    Global silently become FortiWeb."""
    src = (ROOT / "app" / "__init__.py").read_text()
    block = src.split("fortiweb_scoped = {", 1)[1].split("}", 1)[0]
    assert "device_provision" not in block


def test_the_blueprint_is_not_mounted_under_provisioning():
    """The legacy-URL shim rewrites every /provisioning path onto /web/...,
    so a route there is redirected to a URL that does not exist."""
    src = (ROOT / "app" / "views" / "device_provision.py").read_text()
    tree = ast.parse(src)
    prefixes = [kw.value.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                for kw in node.keywords
                if kw.arg == "url_prefix" and isinstance(kw.value, ast.Constant)]
    assert prefixes, "anti-vacuity: the blueprint must declare a prefix"
    for p in prefixes:
        assert not p.startswith("/provisioning"), \
            f"{p} is rewritten by the legacy shim"


@pytest.mark.parametrize("adom", ["fortiweb", "fortiadc", "fortianalyzer",
                                  "fortiauthenticator", "global"])
def test_every_adom_reaches_device_provisioning(app, client, adom):
    login(client, admin_user_id(app), product=adom)
    r = client.get(f"/device-provisioning/data?_adom={adom}",
                   headers={"X-ADOM": adom})
    assert r.status_code == 200, f"{adom} cannot reach the page"
    assert r.get_json()["scope"] == adom


def test_a_run_from_another_adom_is_404_not_403(app, client, session):
    """404 because from this ADOM it does not exist. 403 would confirm that a
    run with that id exists somewhere."""
    with app.app_context():
        run = ProvisionRun(product="fortiadc", name="adc-run", mode="vm_only")
        session.add(run)
        session.commit()
        rid = run.id
    login(client, admin_user_id(app), product="fortiweb")
    r = client.get(f"/device-provisioning/{rid}?_adom=fortiweb",
                   headers={"X-ADOM": "fortiweb"})
    assert r.status_code == 404


def test_the_feed_filters_on_the_query_not_the_template(app, client, session):
    with app.app_context():
        for prod in ("fortiweb", "fortiadc"):
            session.add(ProvisionRun(product=prod, name=f"{prod}-run",
                                     mode="vm_only"))
        session.commit()
    login(client, admin_user_id(app), product="fortiadc")
    j = client.get("/device-provisioning/data?_adom=fortiadc",
                   headers={"X-ADOM": "fortiadc"}).get_json()
    names = [r["name"] for r in j["runs"]]
    assert names == ["fortiadc-run"], names


def test_a_run_cannot_relabel_its_own_adom(app, client, session):
    """The product is stamped from the request scope, never from the form: a
    run that could re-label itself would let a FortiADC session build a
    FortiWeb and file it under FortiWeb."""
    login(client, admin_user_id(app), product="fortiadc")
    r = client.post("/device-provisioning/new?_adom=fortiadc",
                    headers={"X-ADOM": "fortiadc"},
                    data={"name": "sneaky", "mode": "config_only",
                          "product": "fortiweb"})
    assert r.status_code == 200, r.data[:300]
    assert r.get_json()["run"]["product"] == "fortiadc"
