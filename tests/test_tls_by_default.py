"""Every way to install SATOM must serve HTTPS from its first boot.

WHAT THIS GUARDS, AND WHY NOTHING ELSE DOES
-------------------------------------------
There are five install paths in this repository and they were not equal. The
turnkey installer (installers/install-satom.sh) has always issued an internal
CA and put nginx in front of gunicorn. Three others did not:

  scripts/install.sh   the README's own quick start -- gunicorn on 0.0.0.0:8000
  deploy/install.sh    legacy bootstrap, same shape
  deploy/docker/       published :80 and DELEGATED TLS to a proxy the operator
                       had to supply

Nothing failed. Each of those installs came up, answered /healthz 200 and
reported success. What they could not do is accept a password: the app runs
FLASK_ENV=production, which sets SESSION_COOKIE_SECURE=True, and a browser will
not return a Secure cookie to a plain-HTTP origin -- so the login POST arrives
with no session, therefore no CSRF token, and is rejected BEFORE the password is
compared. On 2026-08-31 that made a freshly installed node reject every correct
credential while every health signal was green.

So this file asserts two things a reader might expect to be obvious:

  1. Each install path provisions TLS at all.
  2. They provision the SAME TLS -- the proxy headers below are not stylistic.
     `Host $http_host` (never `$host`) is what keeps Flask-WTF's CSRF referer
     check working behind a non-standard port. `X-Forwarded-Proto https` is what
     tells the app it is reached over TLS across a hop that speaks plain HTTP.
     `client_max_body_size 400M` must stay >= MAX_UPLOAD_BYTES or a valid update
     package dies with an nginx 413 the app never sees. Each was learned once,
     in production, and a second install path is exactly where they get
     re-learned.

Two rules this repository has paid for twice, applied here:

  * Assert against the ARTEFACTS, never against a copy of the fact restated in
    the test -- a guard carrying its own expected vhost is a third author of it.
  * Every pattern carries a MINIMUM count. A regex that silently matches
    nothing reports a perfect file while having inspected none of it.
"""
from __future__ import annotations

import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
BOOTSTRAP = DEPLOY / "tls-bootstrap.sh"
TURNKEY = ROOT / "installers" / "install-satom.sh"
COMPOSE = DEPLOY / "docker" / "compose.yaml"

#: Every script that installs SATOM onto a host. Each one must end with the
#: application behind TLS. A new installer added here without TLS fails.
HOST_INSTALLERS = (
    ROOT / "scripts" / "install.sh",
    DEPLOY / "install.sh",
    TURNKEY,
)

#: Directives that must appear identically wherever a SATOM vhost is authored.
#: Kept as fragments rather than a whole block because the turnkey installer
#: interpolates shell variables into its copy and the shared script does not.
#
#: `\\?` before every `$` is not noise: both authors emit their vhost from a
#: shell heredoc, where an nginx variable is written `\$http_host` so the shell
#: does not expand it. A pattern without it matches nothing in EITHER file --
#: which the first run of this guard demonstrated, by failing against two
#: correct scripts.
VHOST_INVARIANTS = (
    r"proxy_set_header\s+Host\s+\\?\$http_host",
    r"proxy_set_header\s+X-Forwarded-Proto\s+https",
    r"proxy_set_header\s+X-Forwarded-For\s+\\?\$proxy_add_x_forwarded_for",
    r"client_max_body_size\s+400M",
    r"ssl_protocols\s+TLSv1\.2\s+TLSv1\.3",
    r"ssl_certificate_key",
    r"return\s+301\s+https://",
)

#: The files that AUTHOR a vhost. Any new one has to satisfy the invariants.
VHOST_AUTHORS = (BOOTSTRAP, TURNKEY)


def read(p: pathlib.Path) -> str:
    assert p.exists(), "%s is missing" % p
    return p.read_text(encoding="utf-8")


def code_only(text: str) -> str:
    """Strip full-line comments.

    Essential, and learned the hard way: several of these scripts EXPLAIN in
    prose why `$host` is wrong, naming it. A guard that forbids `$host` while
    matching its own explanatory comment proves nothing -- and the inverse, a
    guard satisfied by a comment, is worse.
    """
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def _function_body(text: str, name: str) -> str:
    """The body of shell function *name*, bounded by its own closing brace.

    Bounding by the next column-0 `}` rather than by a character count: a
    window measured in characters silently shrinks when a comment is added
    above it, and then the guard inspects the wrong region while still passing.
    """
    start = re.search(r"^%s\(\)\s*\{" % re.escape(name), text, re.MULTILINE)
    assert start, "no function %s() in the script — guard inspected nothing" % name
    rest = text[start.end():]
    end = re.search(r"^\}", rest, re.MULTILINE)
    assert end, "function %s() is never closed at column 0" % name
    body = rest[:end.start()]
    assert len(body.splitlines()) >= 5, (
        "%s() body is %d lines — too short to be the real function"
        % (name, len(body.splitlines()))
    )
    return body


# ---------------------------------------------------------------------------
# 1. Every install path provisions TLS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("script", HOST_INSTALLERS, ids=lambda p: p.name)
def test_every_host_installer_provisions_tls(script: pathlib.Path):
    body = code_only(read(script))
    assert "nginx" in body, (
        "%s installs SATOM but never mentions nginx in its code, so it leaves "
        "gunicorn serving plain HTTP -- a node that answers /healthz 200 and "
        "rejects every correct password" % script.name
    )
    assert re.search(r"openssl|tls-bootstrap\.sh", body), (
        "%s never issues a certificate: it either calls deploy/tls-bootstrap.sh "
        "or runs openssl itself" % script.name
    )


@pytest.mark.parametrize("script", (ROOT / "scripts" / "install.sh", DEPLOY / "install.sh"),
                         ids=lambda p: str(p.relative_to(ROOT)))
def test_the_simple_installers_delegate_to_the_shared_provisioner(script: pathlib.Path):
    """Not 'they do TLS somehow' -- they do it through the ONE implementation.

    The turnkey installer is exempt: it is 2000 lines of battle-tested product
    with its own SAN prompt, PostgreSQL TLS copy and SELinux handling, and
    rewriting it to call this script would be a refactor of the shipped path
    for no behavioural gain. It is held to the same OUTPUT instead, by
    test_every_vhost_author_agrees_on_the_proxy_contract below.
    """
    body = code_only(read(script))
    # A regex, not a substring: the call is written with the path quoted
    # ("$APP_DIR/deploy/tls-bootstrap.sh" ensure-pki), so a literal
    # "tls-bootstrap.sh ensure-pki" matches nothing.
    assert re.search(r"tls-bootstrap\.sh\"?\s+ensure-pki", body), (
        "%s does not call the shared provisioner, so its certificate handling "
        "is a second implementation that will drift" % script.name
    )
    assert re.search(r"tls-bootstrap\.sh\"?\s+write-vhost", body), (
        "%s issues a certificate but never writes a vhost" % script.name
    )


def test_the_simple_installer_does_not_publish_gunicorn_to_the_network():
    """A loopback bind is what makes the TLS hop unavoidable.

    With gunicorn on 0.0.0.0 the plain-HTTP door stays open beside the HTTPS
    one, and an operator who reaches it gets the exact failure this whole
    change exists to remove.
    """
    body = code_only(read(ROOT / "scripts" / "install.sh"))
    binds = re.findall(r"--bind\s+(\S+)", body)
    assert binds, "scripts/install.sh no longer binds gunicorn — guard inspected nothing"
    bad = [b for b in binds if b.startswith("0.0.0.0") or b.startswith("[::]")]
    assert not bad, (
        "scripts/install.sh publishes gunicorn on %s. nginx terminates TLS in "
        "front of it, so the application port must be loopback-only." % bad
    )


# ---------------------------------------------------------------------------
# 2. They provision the SAME TLS
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("author", VHOST_AUTHORS, ids=lambda p: p.name)
@pytest.mark.parametrize("directive", VHOST_INVARIANTS)
def test_every_vhost_author_agrees_on_the_proxy_contract(author: pathlib.Path, directive: str):
    body = code_only(read(author))
    assert re.search(directive, body), (
        "%s authors a SATOM vhost without `%s`. These are not style: each one "
        "was added after it broke something in production, and a second author "
        "of the vhost is how they get lost." % (author.name, directive)
    )


@pytest.mark.parametrize("author", VHOST_AUTHORS, ids=lambda p: p.name)
def test_no_vhost_author_uses_dollar_host_for_the_proxied_host_header(author: pathlib.Path):
    """`Host $host` drops the port and every POST dies on the CSRF referer check.

    Comments are stripped first: these files legitimately NAME `$host` while
    explaining why they do not use it.
    """
    body = code_only(read(author))
    offenders = [l for l in body.splitlines()
                 if re.search(r"proxy_set_header\s+Host\s+\$host\b", l)]
    assert not offenders, (
        "%s sets `Host $host`. It discards the port, so behind a NAT or a proxy "
        "on a non-standard port every POST -- the login included -- fails with a "
        "message about an expired session. Use $http_host. Offending: %r"
        % (author.name, offenders)
    )


def test_the_shared_provisioner_refuses_to_overwrite_an_operator_certificate():
    """The other half of the promise: the install ships TLS, the operator
    replaces it. If a re-run reissued over an imported certificate, an installer
    upgrade would silently swap a trusted certificate for a self-signed one --
    which is how CT 346 lost its wildcard on 2026-08-04."""
    body = code_only(read(BOOTSTRAP))

    # Scoped to ensure_pki's OWN body. A whole-file check for `"imported"`
    # passes with the guard clause gutted, because import_cert() writes that
    # very string into meta.json a hundred lines below -- which a mutation of
    # this guard demonstrated by surviving.
    reissue = _function_body(body, "ensure_pki")
    assert re.search(r'"source".*"imported"', reissue), (
        "ensure_pki() no longer checks for source=imported, so re-running an "
        "installer reissues over an operator's certificate and replaces a "
        "trusted one with a self-signed one, silently"
    )
    assert re.search(r"return 0", reissue), (
        "ensure_pki() recognises an imported certificate but does not return "
        "early, so it reissues anyway"
    )

    # The DISPATCH line, not the word. The word also appears in this
    # subcommand's own usage error, so a whole-file check passed with the
    # subcommand unreachable.
    assert re.search(r"^\s*import-cert\)", body, re.MULTILINE), (
        "deploy/tls-bootstrap.sh no longer dispatches `import-cert`, so the "
        "documented certificate-replacement path does not exist"
    )


# ---------------------------------------------------------------------------
# 3. The container stack
# ---------------------------------------------------------------------------

def _compose() -> dict:
    return yaml.safe_load(read(COMPOSE))


def test_the_container_stack_ships_its_own_terminator():
    services = _compose()["services"]
    assert "proxy" in services, (
        "compose.yaml has no `proxy` service. The stack would publish the app "
        "over plain HTTP, and FLASK_ENV=production makes that unusable rather "
        "than merely insecure."
    )
    assert "tls-init" in services, (
        "compose.yaml has no `tls-init` service, so nothing issues the "
        "certificate the proxy is configured to read"
    )


def test_the_proxy_waits_for_the_certificate_to_exist():
    """Ordering, not taste: nginx exits at startup if ssl_certificate names a
    file that is not there, and `restart: unless-stopped` turns that into a
    crash loop with no obvious cause."""
    dep = _compose()["services"]["proxy"]["depends_on"]
    assert dep.get("tls-init", {}).get("condition") == "service_completed_successfully", (
        "proxy does not wait for tls-init to COMPLETE: %r" % dep
    )


def test_the_application_container_publishes_no_port():
    """Publishing gunicorn beside the proxy re-opens the plain-HTTP door this
    change closes, and it is the door an operator finds first."""
    for name in ("web", "scheduler", "cron"):
        svc = _compose()["services"].get(name, {})
        assert not svc.get("ports"), (
            "service `%s` publishes %r. Only `proxy` may publish; the "
            "application is reached through it." % (name, svc.get("ports"))
        )


def test_the_proxy_publishes_https():
    ports = _compose()["services"]["proxy"]["ports"]
    assert any(str(p).rstrip('"').endswith(":443") for p in ports), (
        "the proxy publishes %r but nothing maps to container port 443" % ports
    )


def test_the_trusted_proxy_default_is_the_proxy_and_lives_in_the_network():
    """Three defaults are one fact spread over three lines of YAML.

    TRUSTED_PROXIES matches EXACT addresses (app/extensions.py), and
    container-to-container traffic arrives from the proxy's own address, not
    from the bridge gateway. If these drift apart the app stops recognising its
    own proxy: X-Forwarded-For is ignored, every user shares one rate-limit
    bucket and every audit entry records the proxy as the actor -- silently.
    """
    text = read(COMPOSE)
    proxy_ip = re.search(r"\$\{SATOM_PROXY_IP:-([0-9.]+)\}", text)
    trusted = re.search(r"TRUSTED_PROXIES:\s*\$\{TRUSTED_PROXIES:-([0-9.,]*)\}", text)
    subnet = re.search(r"subnet:\s*\$\{SATOM_NETWORK_SUBNET:-([0-9./]+)\}", text)
    assert proxy_ip and trusted and subnet, (
        "compose.yaml no longer carries all three defaults (proxy ip=%r, "
        "trusted=%r, subnet=%r) — this guard inspected nothing"
        % (proxy_ip, trusted, subnet)
    )
    assert trusted.group(1) == proxy_ip.group(1), (
        "TRUSTED_PROXIES defaults to %r but the proxy's address defaults to %r"
        % (trusted.group(1), proxy_ip.group(1))
    )
    import ipaddress
    net = ipaddress.ip_network(subnet.group(1))
    assert ipaddress.ip_address(proxy_ip.group(1)) in net, (
        "the proxy's static address %s is outside the compose network %s, so "
        "`up` fails with an address-not-in-pool error" % (proxy_ip.group(1), net)
    )


def test_the_retired_bind_variable_is_not_silently_ignored():
    """SATOM_HTTP_BIND used to publish the APPLICATION. Reusing the name for the
    redirect listener would mean an operator who wrote 127.0.0.1:8080 to keep
    the app off the network now has a redirect there and the app publicly
    served -- the opposite of what their file says. So the name is gone from
    compose and satom-docker.sh stops rather than ignoring it."""
    assert "SATOM_HTTP_BIND" not in read(COMPOSE), (
        "compose.yaml still uses SATOM_HTTP_BIND; the name changed meaning"
    )
    # The exact TEST, not the name. The name also appears in the error message
    # this guard is meant to prove exists, so a substring check passed with the
    # condition itself renamed -- caught by mutating this guard.
    wrapper = code_only(read(DEPLOY / "docker" / "satom-docker.sh"))
    assert re.search(r'\[\s*-n\s+"\$\{SATOM_HTTP_BIND:-\}"\s*\]', wrapper), (
        "satom-docker.sh no longer TESTS for SATOM_HTTP_BIND, so an operator "
        "whose .env still sets it has the value ignored in silence — and they "
        "believe they bound the console to loopback"
    )


def test_the_proxy_init_runs_the_shared_provisioner():
    body = code_only(read(DEPLOY / "docker" / "proxy-init.sh"))
    assert re.search(r"tls-bootstrap\.sh\"?\s+ensure-pki", body) and "write-vhost" in body, (
        "deploy/docker/proxy-init.sh does not use the shared provisioner, so "
        "the container vhost is a second author of the proxy contract"
    )


def test_the_pki_is_a_volume_so_a_new_image_tag_keeps_the_certificate():
    compose = _compose()
    assert "satom-pki" in compose["volumes"], (
        "there is no satom-pki volume: the certificate would live in the "
        "container and an image upgrade would silently discard the one the "
        "operator installed"
    )
    mounts = compose["services"]["proxy"]["volumes"]
    assert any(str(m).startswith("satom-pki:") for m in mounts), (
        "the proxy does not mount satom-pki: %r" % mounts
    )
