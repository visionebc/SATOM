"""No shipped default may name this company's infrastructure.

The public mirror once carried the internal network map, and the publication
pipeline now redacts it (docs/safeguards.md 7e). That pipeline is a net, not a
licence: a redacted default is still a *wrong* default. Seven values here were
internal infrastructure the application actually USED when unconfigured, so a
third-party installation shipped with somebody else's network as its factory
settings -- and in one case handed an unrelated host on any overlapping 10/8
the right to forge the client address used for rate limiting and audit.

These guards fail at the source, before publication has anything to hide.
"""
from __future__ import annotations

import importlib
import pathlib
import re

import pytest

from app.services import doc_publication as pubdoc

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _findings(text: str) -> list[str]:
    """Internal identifiers in `text`, named by class."""
    return [name for name, pattern in pubdoc.FORBIDDEN if pattern.search(text)]


# --------------------------------------------------------------------------- #
#  Runtime defaults                                                            #
# --------------------------------------------------------------------------- #

def test_trusted_proxy_default_is_loopback_only():
    """The most dangerous of the set.

    X-Forwarded-For is honoured only when the direct peer is in this list, and
    the result keys rate limiting and audit. A shipped address means every user
    collapses into one bucket on a normal install -- and on any site whose LAN
    overlaps that range, an unrelated host inherits the right to forge it.
    """
    src = (ROOT / "app/extensions.py").read_text(encoding="utf-8")
    default = re.search(r'os\.environ\.get\(\s*"TRUSTED_PROXIES"\s*,\s*"([^"]*)"', src)
    assert default, "TRUSTED_PROXIES default not found -- did the lookup move?"
    hosts = {h.strip() for h in default.group(1).split(",") if h.strip()}
    assert hosts <= {"127.0.0.1", "::1"}, (
        "TRUSTED_PROXIES ships a non-loopback default: %s" % sorted(hosts))


def test_dns_tool_ships_no_resolvers():
    """The module docstring promises the list is never hardcoded."""
    from app.services import dns_tool
    assert dns_tool.DEFAULT_SERVERS == [], (
        "DEFAULT_SERVERS ships resolvers: %r" % (dns_tool.DEFAULT_SERVERS,))


def test_release_notes_ships_no_fetch_endpoint():
    """The endpoint is unauthenticated; a default aims it at the operator's LAN."""
    from app.services import release_notes
    assert release_notes.FIRECRAWL_LAN_DEFAULT == ""


def test_node_certificate_hostname_appends_no_domain_by_default(monkeypatch):
    """A certificate for a namespace the installation does not own is wrong.

    Only the SUFFIX is configurable, and it is resolved per node: a stored FQDN
    would make an HA standby -- which replicates the primary's settings row --
    issue a certificate naming the primary.
    """
    from app.services import cert_service, settings_store
    monkeypatch.setattr(cert_service.su, "this_node_name", lambda: "node-a")
    monkeypatch.setattr(settings_store, "get_str",
                        lambda key, default=None: default)
    assert cert_service.node_hostname() == "node-a"


@pytest.mark.parametrize("module_path", [
    "app/extensions.py",
    "app/services/dns_tool.py",
    "app/services/release_notes.py",
    "app/services/cert_service.py",
    "scripts/build_field_catalog.py",
])
def test_default_bearing_modules_name_no_internal_host(module_path):
    text = (ROOT / module_path).read_text(encoding="utf-8")
    assert not _findings(text), (
        "%s names internal infrastructure: %s" % (module_path, _findings(text)))


# --------------------------------------------------------------------------- #
#  Artefacts a third party actually runs                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("artefact", [
    "deploy/nginx-vhost.conf",
    "installers/install-satom.sh",
    "app/templates/auth/profile.html",
])
def test_shipped_artefacts_are_generic(artefact):
    """These are executed or served verbatim on somebody else's machine.

    The installer's clone URL is the sharp one: it pointed at a private Git
    server, so an unattended install anywhere else hung on a clone it could
    never complete.
    """
    text = (ROOT / artefact).read_text(encoding="utf-8")
    assert not _findings(text), (
        "%s names internal infrastructure: %s" % (artefact, _findings(text)))


# --------------------------------------------------------------------------- #
#  The corpus that cannot be published                                         #
# --------------------------------------------------------------------------- #

def test_leak_corpus_is_the_only_test_data_that_may_carry_identifiers():
    """It has to: a detector proved against sanitised input proves nothing.

    Which is exactly why it is the one file the publisher drops by path, and
    why every OTHER fixture was moved to the documentation range instead.
    """
    import leak_samples
    assert leak_samples.SAMPLES is not None, "corpus missing from a dev checkout"
    for name, _pattern in pubdoc.FORBIDDEN:
        assert name in leak_samples.SAMPLES["by_class"], f"no sample for {name}"
        sample = leak_samples.SAMPLES["by_class"][name]
        assert any(name in f for f in pubdoc.scan(sample, "corpus")), name


def test_absent_corpus_skips_instead_of_failing(monkeypatch):
    """On a published mirror the corpus is gone and its tests must SKIP.

    Failing there would be a suite that goes red because sanitisation worked,
    which teaches the next reader to ignore a red suite.
    """
    import leak_samples
    monkeypatch.setattr(leak_samples.pathlib.Path, "read_text",
                        lambda self, **kw: (_ for _ in ()).throw(FileNotFoundError()))
    assert leak_samples.load() is None


# --------------------------------------------------------------------------- #
#  The redaction overlay                                                       #
# --------------------------------------------------------------------------- #

def test_the_rule_table_names_nothing_it_protects():
    """The sanitiser was the last file naming the estate.

    And it hid behind its own escaping: a rule written with a \\b anchor
    contains, as TEXT, the letter b immediately before the name -- so neither a
    \\b-anchored rewrite nor a \\b-anchored scanner could see it. Redaction and
    detection were self-consistent and both wrong, which is why a round-trip
    test alone never proved anything, and why the check below is on the source
    text rather than on redact()/scan() agreeing with each other.

    The invariant: every site-specific rule now lives in the untracked overlay,
    so none of its pattern strings may appear in the module.
    """
    text = (ROOT / "app/services/doc_publication.py").read_text(encoding="utf-8")
    overlay = pubdoc._load_overlay()
    patterns = [e["pattern"] for e in overlay.get("redactions", [])] + \
               [e["pattern"] for e in overlay.get("forbidden", [])]
    assert patterns, "overlay carries no site rules -- is it present?"
    for pattern in patterns:
        assert pattern not in text, (
            "doc_publication.py still carries the site rule %r -- it belongs "
            "in publication-rules.local.json" % pattern)


def test_overlay_is_present_on_a_real_deployment():
    """Absent, redaction silently weakens AND the scanner stops flagging the
    same class -- a fail-open pair. A node that loses this file has to say so.
    """
    assert pubdoc.OVERLAY_PATH.exists(), (
        "publication-rules.local.json is missing: documentation redaction is "
        "running with generic rules only. Restore it before publishing.")
    assert pubdoc._load_overlay().get("redactions"), "overlay is empty"
