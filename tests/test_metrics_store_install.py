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
    for p in [INSTALLER, *BUILDERS]:
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
