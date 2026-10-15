"""Fetch a WSDL / XML Schema from the application it describes, with its imports.

XML Schema and WSDL cannot be read back off a FortiWeb one object at a time
(``-20005`` on every read shape), and the device's Entire backup carries them
only inside a block the firmware encrypts. So for a FortiWeb that is already in
production, the file has to come from somewhere else — and for these two types
the natural source is the protected application itself: a SOAP service usually
publishes its own WSDL (``…?wsdl``), and the WSDL names the XSD files it
imports. This module fetches that document, follows its ``import`` /
``include`` / ``redefine`` references, and hands back each document with the
artifact kind and object name it would be stored under.

It never writes to an appliance and never writes to the store: the caller
(``views.artifacts.fetch``) decides what to keep.

**Reaching out from SATOM is the risk, so the rules are strict:**

* ``http``/``https`` only, no credentials in the URL, no redirects followed (a
  redirect is reported with its target, for the operator to fetch on purpose).
* The destination address is checked twice with the same rule the script
  sandbox's egress proxy uses (:func:`services.sandbox.egress_verdict`):
  loopback, link-local, multicast and this node's own address are refused —
  on a1 those carry an unauthenticated VictoriaMetrics, Redis and Postgres.
  Once before connecting (every resolved address), and once on the CONNECTED
  socket before a byte of the body is read, so a name that re-resolves between
  the two (DNS rebinding) is still caught.
* References are followed only to the SAME origin (scheme, host, port) as the
  first URL. Anything else is listed as skipped: a WSDL is a document an
  outsider can write, and following it elsewhere turns SATOM into a crawler
  that the document steers.
* No DTD, no entity declaration: WSDL and XSD do not need one, and refusing them
  closes the XML entity attacks without depending on parser defaults.
* Bounded: :data:`MAX_DOCS` documents, :data:`MAX_DEPTH` levels, the artifact
  store's own size limit per document, and :data:`DEADLINE` seconds overall.
"""
from __future__ import annotations

import posixpath
import re
import socket
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qsl, unquote, urldefrag, urljoin, urlsplit

from .artifact_files import MAX_BYTES

MAX_DOCS = 25
MAX_DEPTH = 5
TIMEOUT = 15.0
DEADLINE = 60.0

NS_XSD = "http://www.w3.org/2001/XMLSchema"
NS_WSDL11 = "http://schemas.xmlsoap.org/wsdl/"
NS_WSDL20 = "http://www.w3.org/ns/wsdl"

#: (namespace, local name) of a root element -> artifact kind
ROOT_KINDS = {
    (NS_WSDL11, "definitions"): "wsdl",
    (NS_WSDL20, "description"): "wsdl",
    (NS_XSD, "schema"): "xml_schema",
}
#: (namespace, local name) -> attribute that names another document
REFERENCES = {
    (NS_XSD, "import"): "schemaLocation",
    (NS_XSD, "include"): "schemaLocation",
    (NS_XSD, "redefine"): "schemaLocation",
    (NS_XSD, "override"): "schemaLocation",
    (NS_WSDL11, "import"): "location",
    (NS_WSDL20, "import"): "location",
    (NS_WSDL20, "include"): "location",
}
_EXT = {"wsdl": ".wsdl", "xml_schema": ".xsd"}
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
_DTD = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.I)


class FetchRefused(Exception):
    """The URL or the address behind it is not one SATOM may fetch."""


@dataclass
class Doc:
    url: str
    kind: str
    name: str
    blob: bytes
    depth: int
    referenced_by: str = ""


@dataclass
class Report:
    docs: list[Doc] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    renamed: list[tuple[str, str]] = field(default_factory=list)
    error: str = ""


# --------------------------------------------------------------------------- #
#  names                                                                       #
# --------------------------------------------------------------------------- #
def _clean(name: str) -> str:
    return _UNSAFE.sub("-", name).strip("-.")[:63]


def suggest_name(url: str, kind: str = "") -> str:
    """The object name a fetched document is stored under by default.

    ``…/OrderService?wsdl`` -> ``OrderService.wsdl``; the JAX-WS style
    ``…/OrderService?xsd=2`` -> ``OrderService-xsd2.xsd``; ``…/types/order.xsd``
    -> ``order.xsd``. The extension follows the KIND, so a schema served as
    ``schema.php`` is not stored as a ``.php``.
    """
    parts = urlsplit(url)
    base = unquote(posixpath.basename(parts.path.rstrip("/")))
    # No file name in the path: the host is the name, and its dots are not an
    # extension (``svc.example.internal`` must not become ``svc.example``).
    stem, ext = posixpath.splitext(base) if base else (parts.hostname or "document", "")
    q = dict((k.lower(), v) for k, v in parse_qsl(parts.query, keep_blank_values=True))
    if q.get("xsd"):
        stem = "%s-xsd%s" % (stem, q["xsd"])
    elif q.get("wsdl"):
        stem = "%s-wsdl%s" % (stem, q["wsdl"])
    suffix = _EXT.get(kind) or (ext if ext.lower() in (".wsdl", ".xsd", ".xml") else ".xml")
    return _clean(stem + suffix) or "document" + suffix


# --------------------------------------------------------------------------- #
#  the network door                                                            #
# --------------------------------------------------------------------------- #
def _origin(url: str) -> tuple[str, str, int]:
    p = urlsplit(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.scheme, (p.hostname or "").lower(), port)


def check_url(url: str) -> None:
    """Refuse anything that is not a plain http(s) URL to a named host."""
    p = urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise FetchRefused("only http:// and https:// URLs can be fetched")
    if not p.hostname:
        raise FetchRefused("the URL names no host")
    if p.username or p.password:
        raise FetchRefused("credentials in the URL are not accepted")


def _route_local(ip: str, port: int) -> str:
    """The local address the kernel would use to reach ``ip`` (no packet sent)."""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.connect((ip, port))
        return s.getsockname()[0]
    finally:
        s.close()


def check_address(peer_ip: str, local_ip: str) -> None:
    from .sandbox import egress_verdict
    why = egress_verdict(peer_ip, local_ip)
    if why:
        raise FetchRefused("%s is %s — SATOM does not fetch from it" % (peer_ip, why))


def _precheck(url: str) -> None:
    _scheme, host, port = _origin(url)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchRefused("the host does not resolve (%s)" % exc) from exc
    for info in infos:
        ip = info[4][0]
        check_address(ip, _route_local(ip, port))


def http_get(url: str, *, verify_tls: bool = True) -> tuple[int, dict, bytes]:
    """GET one URL under the rules above. ``(status, headers, body)``."""
    import httpx

    check_url(url)
    _precheck(url)
    with httpx.Client(verify=verify_tls, timeout=TIMEOUT, follow_redirects=False,
                      trust_env=False) as client:
        with client.stream("GET", url, headers={
                "Accept": "application/wsdl+xml, application/xml, text/xml, */*",
                "User-Agent": "SATOM artifact fetch"}) as resp:
            stream = resp.extensions.get("network_stream")
            server = stream.get_extra_info("server_addr") if stream else None
            local = stream.get_extra_info("client_addr") if stream else None
            if not server or not local:
                raise FetchRefused("could not confirm which address was connected")
            check_address(server[0], local[0])
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > MAX_BYTES:
                    break
            return resp.status_code, dict(resp.headers), body


# --------------------------------------------------------------------------- #
#  parsing                                                                     #
# --------------------------------------------------------------------------- #
def _split(tag: str) -> tuple[str, str]:
    if tag.startswith("{"):
        ns, _, local = tag[1:].partition("}")
        return ns, local
    return "", tag


def parse(blob: bytes) -> tuple[str, list[str]]:
    """``(kind, references)`` of one document, or ValueError saying why not."""
    if _DTD.search(blob):
        raise ValueError("the document declares a DTD or entities — refused "
                         "(a WSDL or XML Schema needs neither)")
    try:
        root = ET.fromstring(blob)
    except ET.ParseError as exc:
        raise ValueError("not well-formed XML (%s)" % exc) from exc
    kind = ROOT_KINDS.get(_split(root.tag))
    if not kind:
        raise ValueError("not a WSDL or an XML Schema (root element <%s>)"
                         % _split(root.tag)[1])
    refs: list[str] = []
    for el in root.iter():
        attr = REFERENCES.get(_split(el.tag))
        if attr:
            loc = (el.get(attr) or "").strip()
            if loc and loc not in refs:
                refs.append(loc)
    return kind, refs


# --------------------------------------------------------------------------- #
#  the walk                                                                    #
# --------------------------------------------------------------------------- #
def fetch_tree(url: str, *, root_name: str = "", verify_tls: bool = True,
               get: Callable[..., tuple[int, dict, bytes]] | None = None,
               clock: Callable[[], float] = time.monotonic) -> Report:
    """Fetch ``url`` and every same-origin document it references.

    Never raises for a network or document problem: the first document's
    failure is ``Report.error``; a referenced document's failure is a row in
    ``Report.skipped`` and the rest still arrive.
    """
    rep = Report()
    getter = get or (lambda u: http_get(u, verify_tls=verify_tls))
    url = urldefrag((url or "").strip())[0]
    try:
        check_url(url)
    except FetchRefused as exc:
        rep.error = str(exc)
        return rep
    origin = _origin(url)
    started = clock()
    queue: list[tuple[str, int, str]] = [(url, 0, "")]
    seen = {url}
    names: set[str] = set()

    while queue:
        doc_url, depth, parent = queue.pop(0)
        first = not parent
        if clock() - started > DEADLINE:
            rep.skipped.append((doc_url, "not fetched: the %d s budget ran out" % DEADLINE))
            continue
        try:
            status, headers, blob = getter(doc_url)
        except FetchRefused as exc:
            why = "refused: %s" % exc
            if first:
                rep.error = why
                return rep
            rep.skipped.append((doc_url, why))
            continue
        except Exception as exc:  # noqa: BLE001 — a dead backend is a result
            why = "%s: %s" % (type(exc).__name__, exc)
            if first:
                rep.error = why
                return rep
            rep.skipped.append((doc_url, why))
            continue
        why = ""
        if 300 <= status < 400:
            loc = (headers or {}).get("location") or (headers or {}).get("Location") or "?"
            why = "redirected to %s — fetch that URL instead" % urljoin(doc_url, loc)
        elif status != 200:
            why = "HTTP %s" % status
        elif len(blob) > MAX_BYTES:
            why = "larger than %d KB" % (MAX_BYTES // 1024)
        elif not blob.strip():
            why = "the answer was empty"
        kind, refs = "", []
        if not why:
            try:
                kind, refs = parse(blob)
            except ValueError as exc:
                why = str(exc)
        if why:
            if first:
                rep.error = why
                return rep
            rep.skipped.append((doc_url, why))
            continue

        name = _clean(root_name) if (first and root_name.strip()) else suggest_name(doc_url, kind)
        if name in names:
            n = 2
            stem, ext = posixpath.splitext(name)
            while "%s-%d%s" % (stem, n, ext) in names:
                n += 1
            new = "%s-%d%s" % (stem, n, ext)
            rep.renamed.append((name, new))
            name = new
        names.add(name)
        rep.docs.append(Doc(url=doc_url, kind=kind, name=name, blob=blob,
                            depth=depth, referenced_by=parent))

        for ref in refs:
            target = urldefrag(urljoin(doc_url, ref))[0]
            if target in seen:
                continue
            seen.add(target)
            if urlsplit(target).scheme not in ("http", "https") or _origin(target) != origin:
                rep.skipped.append((target, "other host — not followed; fetch it "
                                            "separately if it belongs to this service"))
                continue
            if depth + 1 > MAX_DEPTH:
                rep.skipped.append((target, "deeper than %d levels" % MAX_DEPTH))
                continue
            if len(rep.docs) + len(queue) >= MAX_DOCS:
                rep.skipped.append((target, "over the %d-document limit" % MAX_DOCS))
                continue
            queue.append((target, depth + 1, doc_url))
    return rep
