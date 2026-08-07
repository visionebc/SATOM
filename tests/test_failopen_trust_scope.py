"""Three fail-OPEN defaults that made a security control a no-op.

Each of these looked healthy from the outside: no exception, no log line, a
plausible return value. That is what makes them expensive.

1. ``hypervisors/base._ssl_context`` imported ``trust_store.verify_target`` —
   a symbol that has never existed. The ``ImportError`` was swallowed by a bare
   ``except`` and the fallback ``return True`` became permanent, so a target
   with ``verify_ssl=True`` was ALWAYS checked against certifi's public roots
   and NEVER against the CAs the operator imported. The feature the docstring
   promises has never once run.
2. ``product_scope`` derives its ADOM key set from the registry, but
   ``branding.all_adoms()`` NEVER raises: when the table cannot be read it
   returns a hardcoded five-ADOM list that is indistinguishable from a
   successful read. A sixth ADOM's key was therefore unrecognised, and an
   unrecognised key resolved to '' — the value that legitimately means
   "Global console / background worker, show everything".
3. ``ssh_ops`` loaded ``data/known_hosts`` inside ``except: pass``. A corrupt,
   truncated or unreadable store yields an EMPTY pin set, which AutoAddPolicy
   reads as "first contact — accept whatever key is offered", and the following
   ``save_host_keys`` then overwrote the store with that key. On 2026-08-03,
   when this fleet recycled appliance IPs, host-key verification was the ONLY
   thing that stopped SATOM from presenting Fortinet admin credentials to an
   unrelated Proxmox Backup Server (``admin-lockout-threshold: 3``).

The guards are anchored to artefacts, not to prose: names imported by
``_ssl_context`` are resolved against the LIVE ``trust_store`` module, the
scoping rules are exercised by CALLING them against a real DB, and the AST
checks read ``ast`` nodes (comments and docstrings cannot satisfy them).
"""
from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
_BASE_PY = REPO / "app" / "services" / "hypervisors" / "base.py"
_SSH_PY = REPO / "app" / "services" / "ssh_ops.py"


def _func(path: pathlib.Path, name: str) -> ast.AST:
    """The AST node of a function/method by name (comments already stripped)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = next((n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.name == name), None)
    assert node is not None, f"{name}() not found in {path}"
    return node


# ===========================================================================
# 1. the hypervisor TLS target must be the operator's trust store
# ===========================================================================

def _hv(**kw):
    from app.services.hypervisors.base import HypervisorClient
    return HypervisorClient(host="hv.example.invalid", username="root",
                            password="pw", **kw)


def test_verify_off_stays_off():
    """``verify_ssl=False`` is the operator's explicit choice, not ours."""
    assert _hv(verify_ssl=False)._ssl_context() is False


def test_a_verified_target_uses_the_operator_trust_store(monkeypatch):
    """The whole point of the setting: certifi PLUS the imported private CAs.

    Before the fix this returned ``True`` (public roots only) for every target
    on the node, because the import above it named a function that does not
    exist and the ``except`` ate the ImportError."""
    from app.services import trust_store
    monkeypatch.setattr(trust_store, "verify_param",
                        lambda: "/pki/trust/ca-bundle.pem")
    got = _hv(verify_ssl=True)._ssl_context()
    assert got == "/pki/trust/ca-bundle.pem", (
        "a verified hypervisor target must validate against the SATOM trust "
        f"store; it used {got!r}")


def test_a_broken_trust_store_is_not_silently_downgraded(monkeypatch):
    """A trust store that raises is a fault to surface, not to paper over.

    ``verify_param`` swallows its own transient failures and returns True; if
    it ever raises, the cause is structural (renamed symbol, broken import) and
    silently verifying against the public roots is how this bug survived."""
    from app.services import trust_store

    def _boom():
        raise RuntimeError("trusted_cas table is gone")

    monkeypatch.setattr(trust_store, "verify_param", _boom)
    with pytest.raises(RuntimeError):
        _hv(verify_ssl=True)._ssl_context()


def test_ssl_context_imports_only_symbols_the_trust_store_exports():
    """Anti-rename guard, resolved against the LIVE module.

    ``verify_target`` was imported for months and never existed. Asserting the
    NAME is not enough — the next rename would sail past it. Every name
    ``_ssl_context`` pulls out of ``trust_store`` is looked up on the real
    module object."""
    from app.services import trust_store
    node = _func(_BASE_PY, "_ssl_context")
    imported = [(n.module or "", a.name)
                for n in ast.walk(node) if isinstance(n, ast.ImportFrom)
                for a in n.names]
    assert imported, (
        "_ssl_context no longer imports anything from the trust store — the "
        "per-target verification setting would mean nothing again")
    for mod, name in imported:
        assert mod.endswith("trust_store"), (
            f"_ssl_context imports from {mod!r}; the trust target comes from "
            f"trust_store")
        assert hasattr(trust_store, name), (
            f"_ssl_context imports trust_store.{name}, which does NOT exist. "
            f"That ImportError used to be swallowed and every verified target "
            f"silently fell back to the public roots.")


def test_ssl_context_has_no_handler_that_returns_a_constant():
    """The exact shape of the bug: ``except Exception: return True``.

    Structural, so the explanatory comment beside it cannot satisfy it."""
    node = _func(_BASE_PY, "_ssl_context")
    for handler in [n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)]:
        for ret in [n for n in ast.walk(handler) if isinstance(n, ast.Return)]:
            assert not isinstance(ret.value, ast.Constant), (
                "an except handler in _ssl_context returns a constant — that "
                "is the fallback that made the trust store unreachable")


# ===========================================================================
# 2. ADOM scoping must not reuse '' for "I could not tell"
# ===========================================================================

@pytest.fixture(autouse=True)
def _clean_registry_cache():
    """The branding registry cache is module-global with a 15 s TTL — a test
    that degrades it must not leak that into the next file."""
    import app.branding as branding
    branding.invalidate()
    yield
    branding.invalidate()


@pytest.fixture()
def degraded(app, monkeypatch):
    """Make the ``adoms`` table unreadable → branding serves ``_FALLBACK``."""
    import app.branding as branding
    import app.models_adom as models_adom

    class _Unreadable:
        key = None
        sort_order = None

        class query:
            @staticmethod
            def order_by(*a, **k):
                raise RuntimeError("adoms table unreadable")

    monkeypatch.setattr(models_adom, "Adom", _Unreadable)
    branding.invalidate()
    yield
    monkeypatch.undo()
    branding.invalidate()


@pytest.fixture()
def fleet(app):
    """One appliance per registered product + one product-stamped audit row."""
    from app.models import Appliance, AuditLog, db
    from app.services import product_scope as ps
    with app.app_context():
        kinds = sorted(ps.concrete_products())
        for kind in kinds:
            a = Appliance(name=f"{kind}-box", host=f"{kind}.example.invalid",
                          kind=kind, username="admin")
            a.password = "pw"
            db.session.add(a)
            db.session.add(AuditLog(action="login", username="t", product=kind))
        db.session.commit()
        total = Appliance.query.count()
    assert total >= 4, "anti-vacuity: the fleet fixture built nothing"
    return total


def test_branding_admits_which_answer_it_is_serving(app):
    """A healthy read must report itself as healthy, or the flag is useless."""
    import app.branding as branding
    with app.app_context():
        assert branding.all_adoms(), "precondition: the registry answers"
        assert branding.is_fallback() is False, (
            "the adoms table was read successfully; is_fallback() must say so")


def test_branding_flags_the_degraded_fallback(app, degraded):
    """The trap: the fallback is a COMPLETE-LOOKING five-ADOM answer."""
    import app.branding as branding
    with app.app_context():
        rows = branding.all_adoms()
        assert rows, "the fallback still answers — that is exactly the problem"
        assert branding.is_fallback() is True, (
            "the registry read failed and the hardcoded fallback was served, "
            "but branding reports it as a real answer")


def test_the_unresolved_sentinel_can_never_be_an_adom_key(app):
    from app.services import product_scope as ps
    assert ps.UNRESOLVED != "", (
        "'' legitimately means Global/worker; the undeterminable case must "
        "not reuse it")
    with app.app_context():
        assert ps.UNRESOLVED not in ps.product_keys()
        assert ps.UNRESOLVED not in ps.concrete_products()


def test_a_sixth_adom_is_scoped_while_the_registry_is_healthy(app):
    """The declared-tomorrow ADOM works when the registry can be read."""
    import app.branding as branding
    from app.models import db
    from app.models_adom import Adom
    from app.services import product_scope as ps
    with app.app_context():
        db.session.add(Adom(key="fortimail", name="FortiMail", sort_order=99))
        db.session.commit()
        branding.invalidate()
        assert "fortimail" in ps.product_keys(), "precondition"
    with app.test_request_context("/", headers={"X-ADOM": "fortimail"}):
        assert ps.session_product() == "fortimail"


def test_an_undeterminable_adom_sees_nothing(app, fleet, degraded):
    """THE regression. A session holding a sixth ADOM's key, while the registry
    is degraded, used to resolve to '' and see EVERY product's rows."""
    from app.models import Appliance, AuditLog
    from app.services import product_scope as ps

    with app.test_request_context("/", headers={"X-ADOM": "fortimail"}):
        assert "fortimail" not in ps.product_keys(), (
            "precondition: the degraded fallback does not know this ADOM")
        assert Appliance.query.count() == fleet, "anti-vacuity: rows exist"

        p = ps.session_product()
        assert p != "", (
            "an ADOM that could not be determined resolved to '' — the value "
            "that means 'show everything'")
        assert p == ps.UNRESOLVED

        assert ps.scope_appliance_query(
            Appliance.query, Appliance.kind).count() == 0
        assert ps.scope_query(AuditLog.query, AuditLog.product).count() == 0
        assert ps.visible_product("fortiweb") is False
        assert ps.visible_product("") is False
        assert ps.creatable_kinds() == ()
        assert ps.may_assign_kind("fortiweb") is False
        with pytest.raises(ps.ProductScopeUnresolved):
            ps.stamp()


def test_the_legitimate_permissive_default_survives(app, fleet):
    """'' MUST keep meaning "Global console / background worker: everything"."""
    from app.models import Appliance
    from app.services import product_scope as ps

    with app.app_context():                      # no request = worker thread
        assert ps.session_product() == ""
        assert ps.scope_appliance_query(
            Appliance.query, Appliance.kind).count() == fleet
        assert ps.visible_product("fortiadc") is True
        assert ps.stamp() == ""

    with app.test_request_context("/", headers={"X-ADOM": "global"}):
        assert ps.scope_appliance_query(
            Appliance.query, Appliance.kind).count() == fleet


def test_a_degraded_registry_does_not_blind_global_or_the_workers(
        app, fleet, degraded):
    """Failing closed must not take out the console that is allowed to see all,
    nor the background workers that have no session at all."""
    from app.models import Appliance
    from app.services import product_scope as ps

    with app.app_context():
        assert ps.session_product() == ""
        assert ps.scope_appliance_query(
            Appliance.query, Appliance.kind).count() == fleet

    with app.test_request_context("/"):          # no ADOM chosen at all
        assert ps.session_product() == ""
        assert ps.scope_appliance_query(
            Appliance.query, Appliance.kind).count() == fleet

    with app.test_request_context("/", headers={"X-ADOM": "global"}):
        assert ps.session_product() == ps.GLOBAL
        assert ps.scope_appliance_query(
            Appliance.query, Appliance.kind).count() == fleet


def test_an_unregistered_key_with_a_HEALTHY_registry_is_still_ignored(app):
    """The boundary between the two rules, and a contract another file pins.

    ``tests/test_product_scope_isolation.py`` asserts that an unregistered
    SESSION key resolves to '' while the registry is readable. Failing closed
    is scoped to the DEGRADED registry — the case where "unrecognised" carries
    no information — so that rule must be untouched here."""
    from flask import g, session as flask_session
    from app.services import product_scope as ps
    with app.test_request_context("/"):
        flask_session["product"] = "fortimadeup"
        g.product = None
        assert ps.session_product() == ""


def test_a_known_adom_still_scopes_while_the_registry_is_degraded(
        app, fleet, degraded):
    """Fail-closed applies to the UNKNOWN key only: the shipped ADOMs still
    work off the fallback, exactly as they did before."""
    from app.models import Appliance
    from app.services import product_scope as ps

    with app.test_request_context("/", headers={"X-ADOM": "fortiadc"}):
        assert ps.session_product() == "fortiadc"
        kinds = {a.kind for a in ps.scope_appliance_query(
            Appliance.query, Appliance.kind)}
    assert kinds == {"fortiadc"}, kinds


# ===========================================================================
# 3. SSH host-key pinning must fail closed
# ===========================================================================

_KEY = None


def _hostkey():
    """One real RSA host key for the whole module (generation is not free)."""
    global _KEY
    if _KEY is None:
        import paramiko
        _KEY = paramiko.RSAKey.generate(2048)
    return _KEY


def _line(host: str) -> str:
    k = _hostkey()
    return f"{host} {k.get_name()} {k.get_base64()}\n"


class _Appliance:
    name = "fw01"
    host = "192.0.2.99"
    ssh_port = 22
    username = "admin"
    password = "appliance-admin-secret"


@pytest.fixture()
def ssh_env(monkeypatch, tmp_path):
    """Real paramiko host-key machinery, faked transport.

    ``connect`` mirrors what paramiko does with the missing-host-key policy so
    the TOFU/pin decision under test is the real one."""
    import paramiko
    from app.services import ssh_ops

    calls: list[tuple] = []

    class _Transport:                       # AutoAddPolicy logs through it
        def _log(self, *a, **kw):
            pass

        def close(self):
            pass

    def _connect(self, hostname, port=22, **kw):
        calls.append((hostname, int(port), kw.get("password")))
        self._transport = _Transport()
        key = _hostkey()
        name = hostname if int(port) == 22 else f"[{hostname}]:{int(port)}"
        ours = self._host_keys.get(name)
        if not ours:
            self._policy.missing_host_key(self, name, key)
        elif ours.get(key.get_name()) != key:
            raise paramiko.BadHostKeyException(
                name, key, ours.get(key.get_name()))

    monkeypatch.setattr(paramiko.SSHClient, "connect", _connect)
    monkeypatch.setattr(paramiko.SSHClient, "invoke_shell",
                        lambda self, **kw: object())
    monkeypatch.setattr(ssh_ops.FortiWebReadonlySSH, "_read",
                        lambda self, **kw: "")
    monkeypatch.setattr(ssh_ops.FortiWebReadonlySSH, "_disable_pager",
                        lambda self: None)
    monkeypatch.setattr(ssh_ops, "_data_dir", lambda: tmp_path)
    return calls, tmp_path / "known_hosts"


def test_a_corrupt_host_key_store_refuses_to_connect(ssh_env):
    """An unreadable pin set is indistinguishable from first contact, and the
    connect that follows carries the appliance admin secret."""
    from app.services import ssh_ops
    calls, known = ssh_env
    known.write_text("this is not a known_hosts line at all\n", encoding="utf-8")
    before = known.read_bytes()

    with pytest.raises(ssh_ops.FortiSSHError) as exc:
        ssh_ops.FortiWebReadonlySSH(_Appliance()).connect()

    assert str(known) in str(exc.value), (
        "the operator has to be told WHICH file to fix")
    assert calls == [], (
        "the admin secret was sent to a host whose key was never verified")
    assert known.read_bytes() == before, (
        "the broken store was overwritten — the old pins are gone for good")


def test_a_truncated_host_key_store_refuses_to_connect(ssh_env):
    """A zero-byte file parses 'cleanly' into an EMPTY pin set. Empty-because-
    broken must not look like empty-by-design."""
    from app.services import ssh_ops
    calls, known = ssh_env
    known.write_text("", encoding="utf-8")

    with pytest.raises(ssh_ops.FortiSSHError):
        ssh_ops.FortiWebReadonlySSH(_Appliance()).connect()
    assert calls == []


def test_one_bad_line_among_good_ones_refuses_to_connect(ssh_env):
    """paramiko SKIPS unparseable lines. Four pins silently becoming one is the
    same failure, just slower."""
    from app.services import ssh_ops
    calls, known = ssh_env
    known.write_text(_line("192.0.2.98") + "garbage garbage\n" + _line("192.0.2.99"),
                     encoding="utf-8")

    with pytest.raises(ssh_ops.FortiSSHError):
        ssh_ops.FortiWebReadonlySSH(_Appliance()).connect()
    assert calls == []


def test_genuine_first_contact_still_trusts_on_first_use(ssh_env):
    """No file at all IS the legitimate empty state. TOFU must survive."""
    from app.services import ssh_ops
    calls, known = ssh_env
    assert not known.exists()

    ssh_ops.FortiWebReadonlySSH(_Appliance()).connect()

    assert len(calls) == 1
    assert known.exists(), "the accepted key must be pinned for the next connect"
    assert _hostkey().get_base64() in known.read_text(encoding="utf-8")


def test_a_clean_store_without_this_host_still_tofus(ssh_env):
    """Loaded cleanly + host absent = the one case a new key may be accepted."""
    from app.services import ssh_ops
    calls, known = ssh_env
    known.write_text(_line("192.0.2.77"), encoding="utf-8")

    ssh_ops.FortiWebReadonlySSH(_Appliance()).connect()

    assert len(calls) == 1
    body = known.read_text(encoding="utf-8")
    assert "192.0.2.77" in body, "an existing pin was dropped on save"
    assert "192.0.2.99" in body, "the new pin was not persisted"


def test_a_pinned_host_connects_and_keeps_its_pin(ssh_env):
    from app.services import ssh_ops
    calls, known = ssh_env
    known.write_text(_line("192.0.2.99"), encoding="utf-8")

    ssh_ops.FortiWebReadonlySSH(_Appliance()).connect()

    assert len(calls) == 1
    assert known.read_text(encoding="utf-8").count("192.0.2.99") == 1


def test_a_key_that_cannot_be_persisted_is_fatal(ssh_env, monkeypatch):
    """Accepting a key we cannot store re-TOFUs on every future connect."""
    import paramiko
    from app.services import ssh_ops
    calls, known = ssh_env

    def _no_save(self, filename):
        raise OSError(30, "read-only file system")

    monkeypatch.setattr(paramiko.SSHClient, "save_host_keys", _no_save)
    with pytest.raises(ssh_ops.FortiSSHError):
        ssh_ops.FortiWebReadonlySSH(_Appliance()).connect()


def test_an_unusable_data_dir_is_fatal(monkeypatch):
    """A data dir that cannot be created yields the same empty pin set — for
    every appliance, forever."""
    import pathlib as _pl
    from app.services import ssh_ops

    class _NoMkdir(type(_pl.Path())):
        def mkdir(self, *a, **kw):
            raise OSError(30, "read-only file system")

    monkeypatch.setattr(ssh_ops, "Path", _NoMkdir)
    with pytest.raises(ssh_ops.FortiSSHError):
        ssh_ops._data_dir()


@pytest.mark.parametrize("func", ["connect", "_data_dir"])
def test_the_host_key_path_has_no_silent_swallow(func):
    """Structural: an ``except`` whose whole body is ``pass`` is how both of
    these failed open. Comments cannot satisfy this."""
    node = _func(_SSH_PY, func)
    for handler in [n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)]:
        body = [s for s in handler.body
                if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        assert body and not all(isinstance(s, ast.Pass) for s in body), (
            f"{func}() swallows an exception with a bare pass — that is the "
            f"shape that unpinned the host keys")
