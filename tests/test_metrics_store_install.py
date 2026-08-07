"""Guards: the metrics store is installable, offline included.

VictoriaMetrics was installed by hand on the development pair and never
entered the install path.  Nothing failed loudly: a fresh node got the
analytics pages, the `metrics_scrape` scheduled action, and the
`satom-metrics.service` entry that `diagnose all` checks -- with no store
behind any of them.  Offline was worse: an isolated management network has no
route to GitHub, so the operator could not obtain the binary at all.

That is the same failure class as `sudo` and `openssh-*` missing from the 1.1
bundles (installs died half-way, after the service account existed) and `lego`
missing from the RHEL bundle (ACME silently unusable).  Each time the code was
correct and the *shipping* was not.

Three properties are pinned here:

1. the installer installs it, from the bundle first and the network second;
2. every offline bundle carries it, and the builder FAILS rather than ship
   a bundle without it;
3. the digest is one value, shared by installer and builders -- drift means a
   bundle whose binary the installer would then refuse.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"
RUNNER = ROOT / "deploy" / "self_update_runner.py"
UNIT = ROOT / "deploy" / "satom-metrics.service"
NOTICE = ROOT / "NOTICE"
ENV_FILE = ROOT / "deploy" / "metrics-store.env"
SCRIPT = ROOT / "deploy" / "install-metrics-store.sh"
CHECKS = ROOT / "deploy" / "satom_cli" / "cmd_checks.py"
SCRIPT_NAME = "install-metrics-store.sh"

BUILDERS = sorted(ROOT.glob("installers/build-offline-bundle*.sh"))

SHA_RE = re.compile(r"\b[0-9a-f]{64}\b")


def _text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _exec_lines(p: Path) -> list[str]:
    """Lines that actually run -- comments explain the guards and would match."""
    return [
        ln
        for ln in _text(p).splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]


# --------------------------------------------------------------------------- #
# anti-vacuity
# --------------------------------------------------------------------------- #

def test_there_are_offline_builders_to_check():
    """A glob that matches nothing turns every parametrised rule below green."""
    assert len(BUILDERS) >= 3, (
        f"expected the debian/rhel/suse builders, found {[b.name for b in BUILDERS]}"
    )


def test_the_unit_exists_and_names_the_binary_the_installer_places():
    assert UNIT.is_file(), "deploy/satom-metrics.service is the shipped unit"
    assert "/usr/local/bin/victoria-metrics" in _text(UNIT)
    assert "127.0.0.1:8428" in _text(UNIT), (
        "the store must stay on loopback: it has no authentication of its own, "
        "and queries are meant to go through the app (auth + ADOM scoping)"
    )


# --------------------------------------------------------------------------- #
# 1. the installer installs it
# --------------------------------------------------------------------------- #

def test_installer_installs_the_metrics_binary():
    src = "\n".join(_exec_lines(INSTALLER))
    assert "/usr/local/bin/victoria-metrics" in src, (
        "install-satom.sh never places the metrics binary; a fresh node would "
        "render analytics panels with no store behind them"
    )
    assert "victoria-metrics-linux-amd64" in src, "no download of the OSS artefact"


def test_installer_prefers_the_bundle_over_the_network():
    """Offline is the case that cannot recover; it must be tried first."""
    src = "\n".join(_exec_lines(INSTALLER))
    bundle = src.find("BUNDLE_DIR}/victoria-metrics")
    download = src.find("releases/download/v${VM_VERSION}")
    assert bundle != -1, "installer never looks in the bundle for the binary"
    assert download != -1, "installer never falls back to downloading"
    assert bundle < download, (
        "the network path is tried before the bundle: an air-gapped install "
        "would spend its timeout before finding the copy it already has"
    )


def test_installer_installs_and_enables_the_unit():
    src = "\n".join(_exec_lines(INSTALLER))
    assert "deploy/satom-metrics.service" in src, "unit never installed"
    assert "enable --now satom-metrics.service" in src, "unit never enabled"
    assert "/var/lib/satom-metrics" in src, "data directory never created"


def test_the_store_is_enabled_after_the_service_account_dropin():
    """Ordering, not cosmetics.

    The shipped unit declares a `User=`; an install that adopted a different
    service account gets the right one only from the drop-in that
    `satom_enforce_unit_user` writes.  Enabling before that runs starts the
    store as the template's account, and nothing later restarts it.
    """
    lines = _exec_lines(INSTALLER)
    enable = next(
        (i for i, ln in enumerate(lines) if "enable --now satom-metrics.service" in ln),
        None,
    )
    enforce = next(
        (i for i, ln in enumerate(lines) if ln.strip() == "satom_enforce_unit_user"),
        None,
    )
    assert enable is not None, "the store is never enabled"
    assert enforce is not None, "satom_enforce_unit_user is never called"
    assert enforce < enable, (
        "satom-metrics.service is enabled before satom_enforce_unit_user writes "
        "its drop-in, so a non-default service account would start it as the "
        "wrong user"
    )


def test_the_dropin_and_update_runner_both_cover_the_store_unit():
    """The runner recopies deploy/ templates on every update.

    A unit missing from NONROOT_UNITS loses its User= on the first
    self-update -- that is precisely how the standby reverted to User=root
    in 1.2.

    This asks the runner for the RESOLVED collections instead of parsing a
    tuple out of the source. Both are derived from deploy/ now, so there is
    no literal to parse -- and resolving is stronger anyway, because a name
    cannot satisfy this by appearing in some neighbouring collection.
    """
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_satom_runner_probe_b", str(RUNNER))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert "satom-metrics.service" in set(mod.NONROOT_UNITS)
    # The privileged runner must never be downgraded to the service account.
    assert "satom-updater.service" not in set(mod.NONROOT_UNITS)


# --------------------------------------------------------------------------- #
# 2. every bundle carries it
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("builder", BUILDERS, ids=lambda p: p.name)
def test_every_offline_builder_stages_the_metrics_binary(builder):
    src = "\n".join(_exec_lines(builder))
    assert "bundle/victoria-metrics" in src, (
        f"{builder.name} builds a bundle with no metrics store; an air-gapped "
        "install has no way to obtain one"
    )
    assert "victoria-metrics-prod" in src, (
        f"{builder.name} does not extract the binary from the release tarball"
    )


@pytest.mark.parametrize("builder", BUILDERS, ids=lambda p: p.name)
def test_a_builder_fails_rather_than_ship_an_incomplete_bundle(builder):
    """warn-and-continue is how a component goes missing without anyone noticing."""
    src = _text(builder)
    window = src[src.index("[SATOM-METRICS-BUNDLE]") :]
    window = window[: window.find("\necho ") + 200 if "\necho " in window else 2000]
    assert "exit 1" in window, (
        f"{builder.name} does not abort when the metrics binary cannot be "
        "fetched or does not verify; the bundle would ship silently incomplete"
    )


# --------------------------------------------------------------------------- #
# 3. one digest, and the OSS artefact
# --------------------------------------------------------------------------- #

def test_the_pinned_digest_is_the_same_everywhere():
    """Installer and builders must agree, or the installer rejects its own bundle."""
    digests = {}
    for p in [INSTALLER, ENV_FILE, *BUILDERS]:
        for ln in _exec_lines(p):
            if "VM_SHA256" in ln:
                m = SHA_RE.search(ln)
                if m:
                    digests.setdefault(m.group(0), []).append(p.name)
    assert digests, "no VM_SHA256 pin found anywhere"
    assert len(digests) == 1, (
        "the metrics binary digest differs between files: "
        + "; ".join(f"{d[:12]}... in {sorted(f)}" for d, f in digests.items())
        + ". A bundle built with one pin is refused by an installer holding the "
        "other, and the failure surfaces only on an air-gapped node."
    )
    files = next(iter(digests.values()))
    assert INSTALLER.name in files, "the installer does not pin a digest"
    # deploy/metrics-store.env is the SINGLE HOME the re-assert script reads.
    # The four shell files cannot source it -- the installer runs before the
    # app tree exists and the builders run against a checkout that may predate
    # it -- so it has to be pinned to them here, or it becomes a fifth literal
    # that drifts in the one direction nothing else would catch.
    assert ENV_FILE.name in files, "deploy/metrics-store.env does not pin the digest"
    for b in BUILDERS:
        assert b.name in files, f"{b.name} does not pin the digest"


@pytest.mark.parametrize("path", [INSTALLER, *BUILDERS], ids=lambda p: p.name)
def test_only_the_apache_licensed_artefact_is_fetched(path):
    """The same release tag publishes -enterprise builds that are NOT Apache-2.0.

    A loosened URL (a glob, a variable, a copied line) would pull a
    differently-licensed binary into a product that redistributes it.
    """
    src = "\n".join(_exec_lines(path))
    for bad in ("-enterprise", "-cluster"):
        assert bad not in src, (
            f"{path.name} references a '{bad}' VictoriaMetrics artefact. Only the "
            "plain OSS build is Apache-2.0 and may be redistributed here."
        )
    if "victoria-metrics-linux-amd64" in src:
        assert "victoria-metrics-linux-amd64-v${VM_VERSION}.tar.gz" in src, (
            f"{path.name} does not pin the exact OSS artefact name"
        )


# --------------------------------------------------------------------------- #
# attribution
# --------------------------------------------------------------------------- #

def test_notice_attributes_the_binaries_the_product_redistributes():
    """Both are third-party binaries shipped inside the bundles.

    SATOM is ELv2; these are not. Saying so is where a reader looks.
    """
    txt = _text(NOTICE)
    assert "VictoriaMetrics" in txt, "NOTICE does not mention the redistributed store"
    assert "Apache License 2.0" in txt, "NOTICE does not state its license"
    assert "lego" in txt, "NOTICE does not mention the redistributed ACME client"


# --------------------------------------------------------------------------- #
# 4. every node re-asserts its own store
#
# The store is node-local BY DESIGN: it sits outside the app tree because the
# datasync replicates data/ with rsync --delete and a TSDB cannot be rsynced
# under a live process. The price is that NOTHING carries it between nodes --
# not git, not the datasync, not a pg_dump. Installed once, then never again.
#
# That is how the standby ended up running the analytics code, the
# metrics_scrape action and the satom-metrics unit entry with no store behind
# any of them, while every other signal called the pair healthy: its panels
# returned a query error, which reads as a UI bug, not a missing subsystem.
#
# The operator CLI and the /usr/local/sbin helpers already had the cure -- the
# update runner reinstalls them after every code update. These hold the store
# to the same contract.
# --------------------------------------------------------------------------- #

def _reassert_loops():
    """For-loops whose iterable is the (script, label) node-local re-assert tuple."""
    import ast
    found = []
    for node in ast.walk(ast.parse(_text(RUNNER))):
        if not isinstance(node, ast.For) or not isinstance(node.iter, ast.Tuple):
            continue
        names = [e.elts[0].value for e in node.iter.elts
                 if isinstance(e, ast.Tuple) and e.elts
                 and isinstance(e.elts[0], ast.Constant)
                 and isinstance(e.elts[0].value, str)]
        if "install-cli.sh" in names:
            found.append(names)
    return found


def test_the_runner_reasserts_the_store_at_every_call_site():
    """Both update paths -- git update and uploaded package -- or it drifts on one.

    Asserted on the AST, not the source text: a substring check is satisfied by
    the comment that describes the call site, which is how several guards in
    this repo have quietly measured nothing.
    """
    loops = _reassert_loops()
    assert len(loops) == 2, (
        "expected 2 node-local re-assert loops in self_update_runner.py, found %d"
        % len(loops))
    for names in loops:
        assert SCRIPT_NAME in names, (
            "a re-assert loop refreshes %s but not the metrics store" % names)


def test_the_reassert_cannot_raise():
    """A failed refresh is recorded as a step; it never fails the update."""
    import ast
    for node in ast.walk(ast.parse(_text(RUNNER))):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple):
            names = [e.elts[0].value for e in node.iter.elts
                     if isinstance(e, ast.Tuple) and e.elts
                     and isinstance(e.elts[0], ast.Constant)]
            if SCRIPT_NAME in names:
                assert not [n for n in ast.walk(node) if isinstance(n, ast.Raise)], (
                    "the node-local re-assert must not raise")


def test_the_script_does_not_carry_its_own_copy_of_the_digest():
    body = "\n".join(_exec_lines(SCRIPT))
    assert not SHA_RE.search(body), (
        "install-metrics-store.sh must source deploy/metrics-store.env, not "
        "hardcode the digest -- that would be a fifth divergent literal")
    assert "metrics-store.env" in body


def test_the_script_verifies_the_digest_and_takes_only_the_apache_artefact():
    body = "\n".join(_exec_lines(SCRIPT))
    assert "sha256sum" in body and "sha_ok" in body
    assert "victoria-metrics-linux-amd64" in body
    # The same upstream tag also publishes a build that is NOT Apache-2.0.
    assert "-enterprise" not in body and "-cluster" not in body


def test_the_script_never_aborts_a_code_update():
    """On an isolated management network the download always fails.

    If that were fatal, every code update on every air-gapped node would fail
    forever -- trading a missing optional subsystem for an un-updatable product.
    """
    body = "\n".join(_exec_lines(SCRIPT))
    assert "set -uo pipefail" in body, (
        "must NOT use 'set -e' here: a failed curl would abort the re-assert")
    assert body.rstrip().endswith("exit 0")
    assert "--max-time" in body, "an unbounded curl would stall the update runner"


def test_the_script_arms_the_unit_only_when_the_capability_was_absent():
    """Re-enabling on every update would silently undo a deliberate stop.

    Settings -> General can stop this exact unit. Runtime state belongs to the
    operator; the re-assert may only arm a node that could not have had it.
    """
    body = "\n".join(_exec_lines(SCRIPT))
    m = re.search(r'if \[ "\$INSTALLED_NOW" -eq 1 \] \|\| \[ "\$UNIT_WAS_MISSING" -eq 1 \]',
                  body)
    assert m, "the enable step must be guarded by INSTALLED_NOW/UNIT_WAS_MISSING"
    assert "enable --now" not in body[:m.start()], "the unit is armed outside the guard"


def test_the_script_derives_the_service_account_from_the_tree():
    """A hardcoded account name already broke the datasync once after a rename."""
    body = "\n".join(_exec_lines(SCRIPT))
    assert "stat -c %U" in body
    assert "satom:satom" not in body


# --------------------------------------------------------------------------- #
# 5. absence is visible
# --------------------------------------------------------------------------- #

def _fn(path, name):
    import ast
    for node in ast.walk(ast.parse(_text(path))):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def test_diagnose_grades_an_absent_store():
    import ast
    fn = _fn(CHECKS, "_metrics_store_rows")
    assert fn is not None, "diagnose has no metrics-store probe"
    assert _fn(CHECKS, "_metrics_store_anchor") is not None
    absent = None
    for node in ast.walk(fn):
        if isinstance(node, ast.If) and any(
                isinstance(n, ast.Attribute) and n.attr == "exists"
                for n in ast.walk(node.test)):
            absent = node
            break
    assert absent is not None, "the probe never tests for an absent binary"
    # absent.body ONLY: an ast.If carries its elif/else in .orelse, so walking
    # the whole node is satisfied by the grading done in the sha-mismatch
    # branch and passes with this branch gutted. (Found by mutation.)
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "worst"
               for stmt in absent.body for n in ast.walk(stmt)), (
        "an ABSENT metrics store must grade the result -- that is the drift "
        "this whole re-assert exists to surface")


def test_diagnose_does_not_grade_the_units_runtime_state():
    """The permanent-amber trap, burned three times on this node already.

    satom-ha-datasync is inert on the primary BY DESIGN; status words were once
    coloured red merely for saying 'inactive'; the :8443 peer probe warned
    forever on a standalone. A stopped store is an operator decision -- print
    it, do not grade it, or this becomes the check people skip.
    """
    import ast
    fn = _fn(CHECKS, "_metrics_store_rows")
    body = [st for st in fn.body
            if not (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant))]
    idx = next((i for i, st in enumerate(body)
                if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                       and n.func.attr == "unit_state" for n in ast.walk(st))), None)
    assert idx is not None, "the probe never reads the unit state"
    for st in body[idx:]:
        for n in ast.walk(st):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
                assert n.func.attr not in ("worst", "_pass"), (
                    "the unit's runtime state must be reported, not graded")
            assert not (isinstance(n, ast.Attribute) and n.attr == "status"), (
                "the unit's runtime state must not set the overall status")
