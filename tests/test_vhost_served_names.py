"""Guards for SATOM-VHOST-HOST and SATOM-SERVED-NAMES.

Both defects have the same root cause: the installer never learned which names
the node is actually reached by.

  * `proxy_set_header Host $host` DROPS the port. Flask-WTF builds the expected
    CSRF origin from the host the app believes it is on and compares it to the
    browser's Referer INCLUDING the port, so behind a NAT or a proxy on a
    non-standard port every POST -- the login included -- is rejected with a
    message about the session, not the header. It points at the wrong layer.
  * `server_name` and the node certificate's SAN list were both minted from
    `hostname`, the SHORT name. A node reached at node.example.tld therefore had
    a vhost that only answered by accident (it also claimed default_server) and
    a certificate with no matching SAN -- a browser warning on a certificate the
    installer had just reported as good.

See docs/safeguards.md 10e.
"""
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installers" / "install-satom.sh"
SAMPLE = ROOT / "deploy" / "nginx-vhost.conf"
sys.path.insert(0, str(ROOT / "deploy"))

from satom_cli import cmd_checks  # noqa: E402


def _executed(text):
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.strip().startswith("#")]


# ---------------------------------------------------------------------------
# A. Nothing we ship may pass a port-stripping Host header.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("path", [INSTALLER, SAMPLE], ids=["installer", "sample-vhost"])
def test_no_shipped_vhost_passes_a_port_stripping_host_header(path):
    offenders = [ln for ln in _executed(path.read_text())
                 if re.search(r"proxy_set_header\s+Host\s+\\?\$host\s*;", ln)]
    assert offenders == [], (
        "%s emits `Host $host`, which drops the port. Every POST behind a "
        "non-standard port then fails CSRF and blames the session. Use "
        "$http_host -- identical on :443, where browsers omit the default "
        "port anyway. Offending line(s): %r" % (path.name, offenders))


@pytest.mark.parametrize("path", [INSTALLER, SAMPLE], ids=["installer", "sample-vhost"])
def test_the_shipped_vhost_actually_sets_http_host(path):
    """The negative test above is also satisfied by deleting the header."""
    assert re.search(r"proxy_set_header\s+Host\s+\\?\$http_host\s*;", path.read_text()), (
        "%s no longer sets the proxied Host header at all. Removing it is not "
        "a fix: gunicorn then sees nginx's own Host." % path.name)


# ---------------------------------------------------------------------------
# B. The served names must be asked for, and both consumers must use them.
# ---------------------------------------------------------------------------
def test_installer_asks_for_the_served_dns_names():
    txt = INSTALLER.read_text()
    # Anclado al ARTEFACTO exacto, no a una subcadena. El nombre de la variable
    # aparece TAMBIEN en la asignacion de dentro del if, asi que un `in txt`
    # seguia pasando con la condicion mutada -- el quinto falso positivo de esta
    # clase en este repo. Un guardia se ata a lo que se inserta, nunca a la prosa.
    assert 'if [ -n "${SATOM_SERVED_NAMES:-}" ]; then' in txt, (
        "There is no non-interactive override for the served names, so an "
        "unattended install cannot set them.")
    assert 'SERVED_NAMES="$SATOM_SERVED_NAMES"' in txt, (
        "The override is tested for but never assigned.")
    # Lo que este guardia promete es que PREGUNTA, no con que primitiva. Desde
    # [SATOM-LOUD-READ] todo prompt pasa por ask/ask_secret para no morir mudo
    # al agotarse la entrada, asi que se aceptan ambas formas -- atarlo a
    # `read -rp` convertia una mejora del mecanismo en un fallo de la suite.
    assert re.search(r"(read -rp .*SERVED_NAMES|^\s*ask SERVED_NAMES )", txt, re.M), (
        "The installer never prompts for the names it is about to mint into "
        "the vhost and the certificate.")
    assert "hostname -f" in txt, (
        "The default should come from the FQDN. It was available all along and "
        "the installer used the short name instead -- that IS the defect.")


def test_certificate_san_is_built_from_the_served_names():
    txt = INSTALLER.read_text()
    assert "subjectAltName=${SAN_LIST}" in txt, (
        "The node certificate's SAN is not built from the served names.")
    assert "subjectAltName=IP:${NODE_IP},DNS:${HOSTN}" not in txt, (
        "The SAN is still minted from the SHORT hostname. A node reached by "
        "FQDN gets a name-mismatch warning on a freshly issued certificate.")
    assert re.search(r"for _sn in \$SERVED_NAMES; do SAN_LIST=", txt), (
        "SAN_LIST is not accumulated over every served name.")


def test_vhost_server_name_is_built_from_the_served_names():
    txt = INSTALLER.read_text()
    assert "server_name ${SERVED_NAMES} ${NODE_IP};" in txt
    assert "server_name ${HOSTN} ${NODE_IP};" not in txt, (
        "server_name is still the short hostname. It only answered because the "
        "vhost also claimed default_server -- i.e. by accident.")


def test_redirect_omits_the_port_when_it_is_the_default():
    txt = INSTALLER.read_text()
    assert "https://\\$host${REDIR_PORT}\\$request_uri" in txt
    assert 'if [ "$WEB_PORT" != "443" ]; then REDIR_PORT=":${WEB_PORT}"; fi' in txt, (
        "REDIR_PORT must stay empty on :443; an explicit :443 in a redirect "
        "propagates to the address bar and to anything proxying in front.")


# ---------------------------------------------------------------------------
# C. RFC 6125 wildcard matching -- the 'CNAMEs' question, decided in code.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name,sans,expected", [
    ("node.example.tld", ["*.example.tld"], True),
    ("NODE.example.tld", ["*.example.tld"], True),          # case-insensitive
    ("node.example.tld.", ["*.example.tld"], True),         # trailing dot
    ("a.b.example.tld", ["*.example.tld"], False),          # ONE label only
    ("example.tld", ["*.example.tld"], False),              # not the bare apex
    ("node", ["*.example.tld"], False),                     # short name never
    ("example.tld", ["*.example.tld", "example.tld"], True),
    ("node.example.tld", [], False),
    ("node.other.tld", ["*.example.tld"], False),
])
def test_wildcard_matching_follows_rfc6125(name, sans, expected):
    assert cmd_checks.cert_covers(name, sans) is expected


def test_uncovered_names_never_grades_a_single_label_name():
    """A bare hostname cannot be in a public certificate. Grading it would put
    every node that imports a wildcard in a permanent warn."""
    served = ["node", "node.example.tld"]
    assert cmd_checks.uncovered_names(served, ["*.example.tld"]) == []
    assert cmd_checks.uncovered_names(served, ["*.other.tld"]) == ["node.example.tld"]


# ---------------------------------------------------------------------------
# D. The live check must see a bad vhost and forgive a good one.
# ---------------------------------------------------------------------------
PROXY_BAD = "server { server_name a.example.tld; location / { proxy_pass http://127.0.0.1:8000; proxy_set_header Host $host; } }"
PROXY_OK = PROXY_BAD.replace("Host $host;", "Host $http_host;")
STATIC = "server { server_name s.example.tld; root /srv/site; }"


def test_the_check_names_the_offending_vhost():
    assert cmd_checks.bare_host_vhosts([("bad.conf", PROXY_BAD)]) == ["bad.conf"]


def test_the_check_clears_a_corrected_vhost():
    assert cmd_checks.bare_host_vhosts([("ok.conf", PROXY_OK)]) == []


def test_a_static_vhost_is_not_a_finding():
    """The static site vhost has no proxy_pass; `Host` is meaningless there and
    flagging it would train the operator to ignore this check."""
    assert cmd_checks.bare_host_vhosts([("pages.conf", STATIC + " proxy_set_header Host $host;")]) == []


# ---------------------------------------------------------------------------
# E. server_name parsing.
# ---------------------------------------------------------------------------
def test_server_names_drop_the_catch_all_and_bare_ips():
    txt = "server {\n  server_name node.example.tld node 192.0.2.7 _;\n}"
    assert cmd_checks.vhost_server_names(txt) == ["node.example.tld", "node"]


def test_server_names_are_collected_from_every_block():
    txt = "server {\n server_name a.example.tld;\n}\nserver {\n server_name b.example.tld;\n}"
    assert cmd_checks.vhost_server_names(txt) == ["a.example.tld", "b.example.tld"]
