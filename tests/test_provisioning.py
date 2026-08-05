"""Guards for hypervisor provisioning and the firmware install/upgrade split.

Each test here exists because something concrete can go wrong silently:

* a capability record that advertises writes the licence forbids sends a run
  off to reserve an address and a DNS row before it dies;
* a firmware page that lists every product's images leaks across ADOMs while
  looking perfectly normal;
* a client that reaches for a device at import time makes the module
  unimportable on a node whose hypervisor is off — and this codebase has
  already shipped a module that imported fine and failed at runtime.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from app.extensions import db
from app.models_firmware import FirmwareImage
from app.models_provision import MODES, STEPS, HypervisorTarget, ProvisionRun
from app.services.hypervisors import (BACKENDS, HypervisorError, build_client,
                                      is_valid)
from app.services.hypervisors.base import Capabilities
from app.services.hypervisors.esxi import EsxiClient
from app.services.hypervisors.proxmox import ProxmoxClient
from app.views.firmware import IMAGE_KINDS, INSTALL_HYPERVISORS, allowed_ext

SRC = pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "hypervisors"


# ------------------------------------------------------- registry / factory
def test_every_backend_is_a_client_and_the_labels_cover_them():
    from app.services.hypervisors import BACKEND_LABELS, DEFAULT_PORTS, FIELD_SPECS
    from app.services.hypervisors.base import HypervisorClient
    assert set(BACKEND_LABELS) == set(BACKENDS)
    assert set(FIELD_SPECS) == set(BACKENDS)
    assert set(DEFAULT_PORTS) == set(BACKENDS)
    for key, cls in BACKENDS.items():
        assert issubclass(cls, HypervisorClient)
        # The class must know its own registry key, or an error message names
        # a backend the operator cannot find in Settings.
        assert cls.backend == key


def test_unknown_backend_raises_a_sentence_not_a_keyerror(app):
    """A row written by a newer release (restore, replica, hand-edited SQL)
    must fail with something the operator can act on."""
    with app.app_context():
        t = HypervisorTarget(name="x", backend="xenserver", host="h",
                             username="u")
        t.password = "p"
        with pytest.raises(HypervisorError) as exc:
            build_client(t)
        assert "xenserver" in str(exc.value)
        assert "proxmox" in (exc.value.detail or "")  # names the valid ones


@pytest.mark.parametrize("backend,cls", [("proxmox", ProxmoxClient),
                                         ("esxi", EsxiClient)])
def test_factory_builds_the_right_client(app, backend, cls):
    with app.app_context():
        t = HypervisorTarget(name=f"t-{backend}", backend=backend,
                             host="h.example.net", username="u")
        t.password = "secret"
        c = build_client(t)
        assert isinstance(c, cls)
        assert c.password == "secret"


def test_is_valid_rejects_junk():
    assert is_valid("proxmox") and is_valid("ESXi")
    assert not is_valid("") and not is_valid("vsphere")


# ------------------------------------------------------------ capabilities
def test_capabilities_default_to_nothing():
    """A backend must opt IN to every capability. A default of True would let
    an unimplemented method advertise itself."""
    c = Capabilities()
    for field in ("create_vm", "delete_vm", "power_control", "list_networks",
                  "list_datastores", "upload_image", "ovf_import",
                  "disk_import", "serial_console"):
        assert getattr(c, field) is False, field


def test_capability_gaps_name_the_blocker():
    gaps = Capabilities(create_vm=False).missing_for_full_provision()
    assert any("create" in g for g in gaps)
    assert any("image" in g for g in gaps)
    assert any("serial" in g for g in gaps)
    # A fully capable backend reports nothing.
    assert Capabilities(create_vm=True, ovf_import=True,
                        serial_console=True).missing_for_full_provision() == []


def test_esxi_capabilities_refuse_writes_when_the_licence_is_free(monkeypatch):
    """The free vSphere Hypervisor licence makes the API read-only. Verified
    live: CreateVM_Task answers 'Current license or ESXi version prohibits
    execution of the requested operation'."""
    c = EsxiClient(host="h", username="root", password="p")
    monkeypatch.setattr(c, "login", lambda: None)
    monkeypatch.setattr(c, "license_info", lambda: {
        "edition_key": "esx.hypervisor.cpuPackageCoreLimited",
        "name": "vSphere 8 Hypervisor", "free": True,
        "evaluation_expired": True, "api_writable": False})
    caps = c.capabilities()
    assert caps.create_vm is False
    assert caps.ovf_import is False
    assert caps.list_datastores is True      # reads still work
    assert any("READ-ONLY" in n for n in caps.notes)


def test_esxi_unreadable_licence_is_not_permission(monkeypatch):
    """Unknown state must NOT be optimistic: a run that dies at CreateVM_Task
    after reserving an address is worse than one that never started."""
    c = EsxiClient(host="h", username="root", password="p")
    monkeypatch.setattr(c, "login", lambda: None)

    def boom():
        raise HypervisorError("licence query refused")
    monkeypatch.setattr(c, "license_info", boom)
    caps = c.capabilities()
    assert caps.create_vm is False
    assert any("treated as unavailable" in n for n in caps.notes)


# --------------------------------------------------------- import hygiene
@pytest.mark.parametrize("mod", sorted(p.name for p in SRC.glob("*.py")))
def test_no_module_level_network_call(mod):
    """Every network call must live inside a method.

    A module that reaches for a device at import time is unimportable on a
    node whose hypervisor is off, wrong or unreachable — and the failure
    surfaces as a broken app, not as a broken hypervisor."""
    tree = ast.parse((SRC / mod).read_text())
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef, ast.Import, ast.ImportFrom)):
            continue
        for sub in ast.walk(node):
            assert not isinstance(sub, ast.Call) or not _is_net(sub), \
                f"{mod}: network call at module level"


def _is_net(call: ast.Call) -> bool:
    f = call.func
    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
    return name in ("get", "post", "request", "put", "delete", "urlopen")


def test_the_clients_do_not_pull_in_a_vendor_sdk():
    """proxmoxer / pyVmomi would each force a rebuild of three offline
    bundles and an entry in the curated pip allowlist."""
    banned = {"proxmoxer", "pyVmomi", "pyvmomi", "pyVim", "vmware"}
    for path in SRC.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods = [node.module.split(".")[0]]
            assert not (set(mods) & banned), f"{path.name} imports a vendor SDK"


# ------------------------------------------------------------- secrets
def test_target_public_never_carries_a_secret(app):
    with app.app_context():
        t = HypervisorTarget(name="p1", backend="proxmox", host="h",
                             username="root@pam", token_id="root@pam!satom")
        t.password = "super-secret-pw"
        t.token_secret = "super-secret-token"
        pub = t.public()
        blob = repr(pub)
        assert "super-secret-pw" not in blob
        assert "super-secret-token" not in blob
        # ...but the page still needs to know one is stored.
        assert pub["has_password"] is True and pub["has_token"] is True


def test_run_public_never_carries_the_admin_password(app):
    with app.app_context():
        r = ProvisionRun(name="fw-new", product="fortiweb")
        r.admin_password = "Adm1n-Secret"
        assert "Adm1n-Secret" not in repr(r.public())
        assert r.admin_password == "Adm1n-Secret"


# ------------------------------------------------------- state machine
def test_step_order_is_stable_and_progress_is_monotonic(app):
    """Reordering STEPS would make existing rows claim the wrong progress."""
    assert STEPS[0] == "draft" and STEPS[-1] == "done"
    assert len(set(STEPS)) == len(STEPS)
    with app.app_context():
        last = -1
        for s in STEPS:
            r = ProvisionRun(name="x", product="fortiweb", step=s)
            assert r.progress_pct() > last
            last = r.progress_pct()
        assert last == 100


def test_an_unknown_step_does_not_claim_progress(app):
    with app.app_context():
        r = ProvisionRun(name="x", product="fortiweb", step="teleported")
        assert r.progress_pct() == 0


def test_every_mode_is_described():
    for key, text in MODES.items():
        assert text.strip() and len(text) > 20, key
    assert "semi" in MODES and "config_only" in MODES


# ------------------------------------------------- firmware: kind split
def test_upgrade_images_stay_out_only():
    assert allowed_ext("upgrade") == {".out"}


@pytest.mark.parametrize("ext", [".zip", ".qcow2", ".ova", ".ovf", ".out"])
def test_install_images_accept_the_real_fortinet_media(ext):
    assert ext in allowed_ext("install")


def test_an_unknown_kind_falls_back_to_the_strict_set():
    """Fail closed: a junk kind must not widen what the upload accepts."""
    assert allowed_ext("banana") == {".out"}


def test_kind_default_is_upgrade_because_every_old_row_is_one(app):
    with app.app_context():
        fw = FirmwareImage(product="fortiweb", version="7.6.4",
                           filename="x.out", stored_path="/tmp/x")
        db.session.add(fw)
        db.session.flush()
        assert fw.image_kind == "upgrade"
        db.session.rollback()
    assert IMAGE_KINDS[0] == "upgrade"
    assert set(INSTALL_HYPERVISORS) == {"kvm", "vmware"}


# ------------------------------------- firmware: ADOM scoping (the leak)
def _seed(app):
    with app.app_context():
        for prod in ("fortiweb", "fortiadc", "fortianalyzer"):
            db.session.add(FirmwareImage(
                product=prod, version="9.9-scope", filename="s.out",
                stored_path="/tmp/s", image_kind="upgrade"))
        db.session.commit()


def test_the_list_is_filtered_in_the_query_not_the_template(app):
    """A row hidden by a template is still a row the page fetched — and the
    JSON callers would keep leaking it."""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "views" / "firmware.py").read_text()
    body = src.split("def index()", 1)[1].split("\ndef ", 1)[0]
    # Executable lines only: the comment explaining the rule mentions filter().
    code = "\n".join(l for l in body.splitlines()
                     if not l.strip().startswith("#"))
    assert "FirmwareImage.product == _adom" in code
    assert ".filter(" in code


def test_both_upload_paths_take_the_product_from_the_adom(app):
    """Scope comes from the request, never from a field the client controls —
    a hand-crafted POST could otherwise file a FortiWeb image under FortiADC.
    Both endpoints, because they are two independent code paths."""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "views" / "firmware.py").read_text()
    code = "\n".join(l for l in src.splitlines()
                     if not l.strip().startswith("#"))
    # once in the multipart handler, once in the resumable one
    assert code.count('_adom in _PRODUCTS:') == 2, \
        "an upload path is missing the ADOM overrule"
    assert code.count("product = _adom") == 2


def test_firmware_is_reachable_from_every_product_adom():
    """It used to sit in the FortiAnalyzer set alone: FortiADC and
    FortiAuthenticator sessions could not reach the page at all, while a
    FortiAnalyzer session could see FortiWeb images."""
    src = (pathlib.Path(__file__).resolve().parents[1]
           / "app" / "__init__.py").read_text()
    for marker in ("adc_bps", "faz_bps", "fac_bps"):
        block = src.split(marker + " = {", 1)[1].split("}", 1)[0]
        assert "'firmware'" in block, f"{marker} cannot reach the firmware page"
