"""Operations › Wiki — publish an article to Confluence, one way.

SATOM writes the page; Confluence never writes back. The first publication
creates a page in the target's space (under its parent page when one is set)
and remembers its id (``WikiConfluenceLink``); later publications UPDATE that
page id with the next Confluence version number, whatever its title became.
An edit made in Confluence is replaced by the next publication, and the page
says so in its last line.

Before anything leaves SATOM:

* only a PUBLISHED article, its released version — never a draft;
* only its author or a moderator (``wiki_access.can_manage``) — the people
  who decide who reads it;
* an article that is not for everyone (ADOMs or profiles/groups) needs an
  explicit acknowledgement: the Confluence space's readers are not the
  SATOM audience;
* the text is scanned for credentials (services/secret_scan.py). A finding
  stops the publication; a moderator may publish anyway after reading the
  findings (kinds and lines, never values), and that is audited.

The wire goes through services/studio_http.py, the same core as Studio
connections: the destination is resolved once and checked (no loopback,
link-local, this node, the HA peer), the request goes to that checked IP,
redirects are never followed, the credential is redacted out of every error.

Two API flavours: ``cloud`` = REST API v2 (``/api/v2/pages``, numeric space
id resolved from the space key), ``datacenter`` = Server / Data Center
(``/rest/api/content``). Both take the body in the storage format, built here
from the same sanitised HTML the article page shows.
"""
from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlsplit, urlunsplit

from ..extensions import db
from ..models_wiki import WikiArticle, WikiConfluenceLink, WikiConfluenceTarget
from . import prefixed_secret as PS
from . import secret_scan, studio_http, wiki_access
from . import wiki_markdown as wmd
from .wiki_export import _Node, _parse, _text, version_of

SECRET_PREFIX = "wiki.confluence.secret."
TIMEOUT = 30
#: Test seam: an ``httpx.MockTransport`` in tests, ``None`` (the network) here.
_transport = None


class ConfluenceError(ValueError):
    """Refused or failed; the message is safe to show. ``needs_ack`` /
    ``findings`` tell the page what to ask for."""

    def __init__(self, msg, *, needs_ack=False, findings=None):
        super().__init__(msg)
        self.needs_ack = needs_ack
        self.findings = findings or []


# ── targets ──────────────────────────────────────────────────────────────────

def _key(tid: int) -> str:
    return SECRET_PREFIX + str(tid)


def vault_path(tid: int) -> str:
    return "wiki/confluence/%d" % tid


def has_secret(t: WikiConfluenceTarget) -> bool:
    return PS.present(_key(t.id))


def clean_base_url(raw: str, flavor: str) -> str:
    url = str(raw or "").strip()
    parts = urlsplit(url)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ConfluenceError("The Confluence address must start with https:// "
                              "(the credential travels with every call).")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ConfluenceError("The Confluence address takes no user, query or fragment.")
    path = parts.path.rstrip("/")
    if flavor == "cloud" and parts.hostname.endswith(".atlassian.net") and not path:
        path = "/wiki"
    return urlunsplit(("https", parts.netloc.lower(), path, "", ""))


def destination(t: WikiConfluenceTarget) -> tuple:
    """What the credential is sent to. Changing any of it drops the stored
    secret: a secret is never re-aimed at a new place by an edit."""
    return (t.flavor, t.base_url, t.auth, t.username)


def save_target(t: WikiConfluenceTarget | None, form: dict, by: str) -> tuple:
    """``(target, secret_dropped)``."""
    name = " ".join(str(form.get("name") or "").split())[:80]
    if not name:
        raise ConfluenceError("A target needs a name.")
    flavor = form.get("flavor") or "cloud"
    if flavor not in WikiConfluenceTarget.FLAVORS:
        raise ConfluenceError("Unknown Confluence flavour.")
    auth = form.get("auth") or "basic"
    if auth not in WikiConfluenceTarget.AUTHS:
        raise ConfluenceError("Unknown authentication.")
    space = str(form.get("space_key") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9~_-]{1,64}", space):
        raise ConfluenceError("The space key is letters, digits, ~, _ or -.")
    parent = str(form.get("parent_page_id") or "").strip()
    if parent and not parent.isdigit():
        raise ConfluenceError("The parent page id is a number (it is in the page's URL).")
    clash = WikiConfluenceTarget.query.filter(db.func.lower(WikiConfluenceTarget.name)
                                              == name.lower())
    if t is not None:
        clash = clash.filter(WikiConfluenceTarget.id != t.id)
    if clash.first() is not None:
        raise ConfluenceError("A target with that name already exists.")
    base = clean_base_url(form.get("base_url"), flavor)
    before = destination(t) if t is not None else None
    if t is None:
        t = WikiConfluenceTarget(created_by=by, created_at=datetime.utcnow())
        db.session.add(t)
    t.name, t.flavor, t.auth, t.base_url = name, flavor, auth, base
    t.space_key, t.parent_page_id = space, parent
    t.username = str(form.get("username") or "").strip()[:255]
    t.verify_tls = bool(form.get("verify_tls"))
    t.enabled = bool(form.get("enabled"))
    t.updated_at = datetime.utcnow()
    db.session.flush()
    dropped = False
    if before is not None and before != destination(t) and has_secret(t):
        PS.store(_key(t.id), vault_path(t.id), "")
        dropped = True
    db.session.commit()
    return t, dropped


def set_secret(t: WikiConfluenceTarget, value: str) -> None:
    try:
        PS.store(_key(t.id), vault_path(t.id), value or "")
    except PS.SecretStoreError as exc:
        raise ConfluenceError(str(exc)) from None


def delete_target(t: WikiConfluenceTarget) -> None:
    """The pages in Confluence stay; SATOM forgets them (links cascade)."""
    PS.store(_key(t.id), vault_path(t.id), "")
    db.session.delete(t)
    db.session.commit()


# ── the wire ─────────────────────────────────────────────────────────────────

def _definition(t: WikiConfluenceTarget) -> dict:
    return {"slug": "confluence-%d" % t.id, "kind": "http", "base_url": t.base_url,
            "auth": t.auth, "username": t.username, "verify_tls": bool(t.verify_tls),
            "timeout": TIMEOUT}


def _verify(t: WikiConfluenceTarget):
    if not t.verify_tls:
        return False
    from . import trust_store
    return trust_store.verify_param()


def _why(res: dict) -> str:
    j = res.get("json")
    msg = ""
    if isinstance(j, dict):
        msg = j.get("message") or ""
        errs = j.get("errors")
        if not msg and isinstance(errs, list) and errs and isinstance(errs[0], dict):
            msg = errs[0].get("title") or errs[0].get("detail") or ""
        data = j.get("data")
        if not msg and isinstance(data, dict):
            msg = "; ".join(str(e.get("message", {}).get("translation") or e)
                            for e in data.get("errors") or [])[:300]
    if not msg:
        msg = (res.get("text") or "")[:300]
    return " ".join(str(msg).split())[:300]


def _call(t: WikiConfluenceTarget, method: str, path: str, *, query=None, body=None) -> dict:
    secret, problem = PS.state(_key(t.id), vault_path(t.id))
    if problem:
        raise ConfluenceError(problem)
    if not secret:
        raise ConfluenceError("No credential is stored for %s." % t.name)
    try:
        res = studio_http.http_request(
            _definition(t), secret, method, path, query=query, body=body,
            headers={"X-Atlassian-Token": "no-check"}, verify=_verify(t),
            transport=_transport)
    except studio_http.ConnectionError_ as exc:
        raise ConfluenceError("Confluence could not be reached: %s" % exc) from None
    if res.get("location") and 300 <= res["status"] < 400:
        raise ConfluenceError("Confluence answered with a redirect to %s; set the target's "
                              "address to where it points." % res["location"])
    if res["status"] in (401, 403):
        raise ConfluenceError("Confluence refused the credential (HTTP %d). %s"
                              % (res["status"], _why(res)))
    return res


def space(t: WikiConfluenceTarget) -> dict:
    """``{"id", "name"}`` of the target's space; the Test button."""
    if t.flavor == "cloud":
        res = _call(t, "GET", "/api/v2/spaces", query={"keys": t.space_key})
        results = (res.get("json") or {}).get("results") if res["ok"] else None
        if not results:
            raise ConfluenceError("Space %s not found (HTTP %d). %s"
                                  % (t.space_key, res["status"], _why(res)))
        return {"id": str(results[0].get("id")), "name": results[0].get("name") or t.space_key}
    res = _call(t, "GET", "/rest/api/space/%s" % t.space_key)
    if not res["ok"] or not isinstance(res.get("json"), dict):
        raise ConfluenceError("Space %s not found (HTTP %d). %s"
                              % (t.space_key, res["status"], _why(res)))
    return {"id": str(res["json"].get("id") or ""), "name": res["json"].get("name") or t.space_key}


# ── storage format ───────────────────────────────────────────────────────────

def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _attr(s: str) -> str:
    return _esc(s).replace('"', "&quot;")


def _cdata(s: str) -> str:
    return "<![CDATA[" + str(s).replace("]]>", "]]]]><![CDATA[>") + "]]>"


_PLAIN = {"p", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "strong", "em", "code",
          "blockquote", "table", "thead", "tbody", "tr", "th", "td"}
_ALIAS = {"b": "strong", "i": "em"}


def _xhtml(node: _Node) -> str:
    out = []
    for ch in node.children:
        if isinstance(ch, str):
            out.append(_esc(ch))
            continue
        tag = _ALIAS.get(ch.tag, ch.tag)
        if tag in _PLAIN:
            out.append("<%s>%s</%s>" % (tag, _xhtml(ch), tag))
        elif tag == "del":
            out.append('<span style="text-decoration: line-through;">%s</span>' % _xhtml(ch))
        elif tag in ("br", "hr"):
            out.append("<%s/>" % tag)
        elif tag == "a":
            href = wmd.safe_url(ch.attrs.get("href"))
            if href and re.match(r"^(https?:|mailto:)", href, re.I):
                out.append('<a href="%s">%s</a>' % (_attr(href), _xhtml(ch)))
            else:
                out.append(_xhtml(ch))       # SATOM-relative links mean nothing there
        elif tag == "img":
            src = wmd.safe_url(ch.attrs.get("src"), image=True)
            if src and re.match(r"^https?:", src, re.I):
                out.append('<ac:image ac:alt="%s"><ri:url ri:value="%s"/></ac:image>'
                           % (_attr(ch.attrs.get("alt") or ""), _attr(src)))
        elif tag == "pre":
            code = next((c for c in ch.children if not isinstance(c, str) and c.tag == "code"),
                        None)
            lang = ""
            if code is not None:
                m = re.search(r"language-([A-Za-z0-9_+-]{1,30})", code.attrs.get("class") or "")
                lang = m.group(1).lower() if m else ""
            param = ('<ac:parameter ac:name="language">%s</ac:parameter>' % _esc(lang)
                     if lang else "")
            out.append('<ac:structured-macro ac:name="code">%s<ac:plain-text-body>%s'
                       '</ac:plain-text-body></ac:structured-macro>'
                       % (param, _cdata(_text(ch).rstrip("\n"))))
        else:
            out.append(_xhtml(ch))
    return "".join(out)


def storage(article: WikiArticle, rev, *, source_url: str = "") -> str:
    """The page body: the released text in the storage format, then a line
    saying where it comes from and that edits here are overwritten."""
    body = _xhtml(_parse(str(wmd.render(rev.body))))
    if rev.summary:
        body = "<p><em>%s</em></p>" % _esc(rev.summary) + body
    note = _esc("Published from the SATOM Wiki, version %d, on %s UTC. This page is replaced "
                "every time the article is published again: edit it in SATOM."
                % (rev.number, datetime.utcnow().strftime("%Y-%m-%d %H:%M")))
    if source_url:
        note += ' Source: <a href="%s">%s</a>' % (_attr(source_url), _esc(source_url))
    return body + "<hr/><p><sub>%s</sub></p>" % note


# ── publishing ───────────────────────────────────────────────────────────────

def can_publish(user, article: WikiArticle) -> bool:
    return (article is not None and article.status == "published" and article.revision > 0
            and wiki_access.can_manage(user, article))


def is_narrow(article: WikiArticle) -> bool:
    """Not for everyone in SATOM: ADOMs named, or profiles/groups."""
    return bool(article.adoms) or bool(article.audience_restricted)


def scan(article: WikiArticle) -> list[dict]:
    rev = version_of(article)
    text = "\n".join([rev.title, rev.summary or "", rev.body or ""])
    return secret_scan.scan(text)


def _page_url(t: WikiConfluenceTarget, j: dict) -> str:
    links = (j or {}).get("_links") or {}
    webui = str(links.get("webui") or "")
    base = str(links.get("base") or t.base_url)
    url = (base.rstrip("/") + webui) if webui.startswith("/") else base
    return url if url.lower().startswith("https://") else t.base_url


def _current_version(t: WikiConfluenceTarget, page_id: str) -> int | None:
    """The page's version number, or None when it no longer exists."""
    path = ("/api/v2/pages/%s" if t.flavor == "cloud" else "/rest/api/content/%s") % page_id
    res = _call(t, "GET", path, query=None if t.flavor == "cloud" else {"expand": "version"})
    if res["status"] == 404:
        return None
    if not res["ok"]:
        raise ConfluenceError("Confluence answered HTTP %d reading page %s. %s"
                              % (res["status"], page_id, _why(res)))
    return int(((res.get("json") or {}).get("version") or {}).get("number") or 1)


def publish(t: WikiConfluenceTarget, article: WikiArticle, user, *, acknowledged=False,
            override_scan=False, source_url: str = "") -> tuple:
    """``(link, created)``. Raises :class:`ConfluenceError`."""
    if not t.enabled:
        raise ConfluenceError("The target %s is disabled." % t.name)
    if not can_publish(user, article):
        raise ConfluenceError("Only the author or a moderator publishes a published article "
                              "to Confluence.")
    if is_narrow(article) and not acknowledged:
        raise ConfluenceError("This article is not for everyone in SATOM. Confirm that the "
                              "readers of the Confluence space %s may read it." % t.space_key,
                              needs_ack=True)
    findings = scan(article)
    if findings and not (override_scan and wiki_access.is_moderator(user)):
        raise ConfluenceError("The article looks like it holds credentials: %s. Remove them "
                              "and publish again." % secret_scan.summary(findings),
                              findings=findings)
    rev = version_of(article)
    body = storage(article, rev, source_url=source_url)
    link = WikiConfluenceLink.query.filter_by(article_id=article.id, target_id=t.id).first()
    number = _current_version(t, link.page_id) if link is not None else None
    if link is not None and number is None:
        db.session.delete(link)          # deleted in Confluence: publish a new page
        db.session.flush()
        link = None
    created = link is None
    if created:
        if t.flavor == "cloud":
            payload = {"spaceId": space(t)["id"], "status": "current", "title": rev.title,
                       "body": {"representation": "storage", "value": body}}
            if t.parent_page_id:
                payload["parentId"] = t.parent_page_id
            res = _call(t, "POST", "/api/v2/pages", body=payload)
        else:
            payload = {"type": "page", "title": rev.title, "space": {"key": t.space_key},
                       "body": {"storage": {"value": body, "representation": "storage"}}}
            if t.parent_page_id:
                payload["ancestors"] = [{"id": t.parent_page_id}]
            res = _call(t, "POST", "/rest/api/content", body=payload)
    else:
        message = "SATOM Wiki version %d" % rev.number
        if t.flavor == "cloud":
            payload = {"id": link.page_id, "status": "current", "title": rev.title,
                       "body": {"representation": "storage", "value": body},
                       "version": {"number": number + 1, "message": message}}
            res = _call(t, "PUT", "/api/v2/pages/%s" % link.page_id, body=payload)
        else:
            payload = {"id": link.page_id, "type": "page", "title": rev.title,
                       "space": {"key": t.space_key},
                       "body": {"storage": {"value": body, "representation": "storage"}},
                       "version": {"number": number + 1, "message": message}}
            res = _call(t, "PUT", "/rest/api/content/%s" % link.page_id, body=payload)
    if not res["ok"]:
        hint = (" A page with this title may already exist in the space."
                if res["status"] in (400, 409) and created else "")
        raise ConfluenceError("Confluence answered HTTP %d. %s%s"
                              % (res["status"], _why(res), hint))
    j = res.get("json") or {}
    page_id = str(j.get("id") or (link.page_id if link else ""))
    if not page_id.isdigit():
        raise ConfluenceError("Confluence did not say which page it wrote.")
    if link is None:
        link = WikiConfluenceLink(article_id=article.id, target_id=t.id, page_id=page_id)
        db.session.add(link)
    link.page_url = _page_url(t, j)[:1000]
    link.published_revision = rev.number
    link.published_at = datetime.utcnow()
    link.published_by = getattr(user, "username", "") or ""
    db.session.commit()
    return link, created


def links(article: WikiArticle) -> list[WikiConfluenceLink]:
    return (WikiConfluenceLink.query.filter_by(article_id=article.id)
            .order_by(WikiConfluenceLink.id).all())


def targets(enabled_only: bool = False) -> list[WikiConfluenceTarget]:
    q = WikiConfluenceTarget.query
    if enabled_only:
        q = q.filter(WikiConfluenceTarget.enabled.is_(True))
    return q.order_by(WikiConfluenceTarget.name).all()
