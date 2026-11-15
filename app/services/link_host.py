"""Absolute links that leave the request: mailed, exported or notified.

``url_for(_external=True)`` takes its host from the request's Host header,
which the shipped nginx vhost (a ``default_server``) forwards verbatim. A
request with ``Host: attacker.example`` would then put the attacker's server
into a password-reset mail or a Wiki notification sent to someone else. The
request's host (and its port, for a NAT on a non-standard port) is kept only
when it is one of this node's own names or listed in ``LINK_HOSTS``; any other
host is replaced by the node's FQDN.

``LINK_HOSTS`` and not Flask's ``TRUSTED_HOSTS``: the latter answers 400 to
every other Host, which would break the by-IP health and peer probes.
"""
from __future__ import annotations

import socket
from urllib.parse import urlsplit, urlunsplit

from flask import current_app, url_for


def pin_host(link: str) -> str:
    """``link`` unchanged when its host is this node's, else on the node's FQDN."""
    parts = urlsplit(link)
    fqdn = socket.getfqdn()
    own = {n.lower() for n in (socket.gethostname(), fqdn) if n}
    own |= {h.lower() for h in current_app.config.get("LINK_HOSTS") or ()}
    if (parts.hostname or "").lower() in own:
        return link
    return urlunsplit((parts.scheme, fqdn, parts.path, parts.query, parts.fragment))


def external_url(endpoint: str, **values) -> str:
    """``url_for(endpoint, _external=True, **values)`` with :func:`pin_host`."""
    return pin_host(url_for(endpoint, _external=True, **values))
