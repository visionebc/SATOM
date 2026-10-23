"""Operations › Wiki — comments, subscriptions and the notices they send.

Reading is still decided by services/wiki_access.py alone, and every path here
asks it:

* a comment is written only by someone who can READ the article and holds
  ``wiki.write`` (:func:`can_comment`), and only under a published article —
  a draft is its author's, an archived article is closed for discussion;
* a subscription may name anything, but a notice is sent only to users who
  can open the article NOW (:func:`recipients`, one ``can_view`` per user);
* the bell asks again when it shows a notice (:func:`bell_gate`, registered
  with services/notifications.py): an article whose audience was narrowed
  after the notice was sent, or a reader who lost a group, a profile or an
  ADOM, no longer sees its title in the bell. Opening the link answers 404
  in that case anyway (views/wiki._article_or_404).

E-mail is the one copy that cannot be taken back: it is decided at send time
and carries only the title, the description or a short excerpt and the link,
never the article text. It goes to the user's recovery address, one message
per person (no shared ``To:``), in a background thread so publishing never
waits on SMTP.

Which bell: notifications are scoped by ADOM (services/product_scope.py). A
notice lands in an ADOM where both the article and the reader are: the
article's ADOM the reader may enter, or for a Global article the reader's own
ADOM (unscoped = Global and FortiWeb for an unconfined reader).
"""
from __future__ import annotations

import logging
import re
import threading
from datetime import datetime

from ..extensions import db
from ..models import User
from ..models_wiki import (SUBSCRIPTION_KINDS, WikiArticle, WikiComment, WikiSubscription,
                           WikiTopic)
from . import wiki, wiki_access
from . import wiki_markdown as wmd

logger = logging.getLogger(__name__)

MAX_COMMENT = 20_000
#: Replies nest this deep on screen; a reply to a deeper one sits at this depth.
MAX_DEPTH = 5
#: Characters of a comment quoted in its notice.
EXCERPT = 300
LINK_RE = re.compile(r"/wiki/a/(\d+)(?:[/#?]|$)")


class SocialError(ValueError):
    """Refused; the message is shown to the user."""


# ── comments ─────────────────────────────────────────────────────────────────

def can_comment(user, article: WikiArticle) -> bool:
    return (article is not None and article.status == "published"
            and wiki_access.can_write(user) and wiki_access.can_view(user, article))


def can_change_comment(user, comment: WikiComment) -> bool:
    """Edit: the comment's author only — nobody puts words in someone else's
    name. Deleting is :func:`can_delete_comment`."""
    return (not comment.deleted and comment.author_id is not None
            and comment.author_id == getattr(user, "id", None)
            and wiki_access.can_write(user))


def can_delete_comment(user, comment: WikiComment, article: WikiArticle) -> bool:
    """Its author, the article's author and the moderators (can_manage)."""
    if comment.deleted:
        return False
    if comment.author_id is not None and comment.author_id == getattr(user, "id", None):
        return True
    return wiki_access.can_manage(user, article)


def _clean_body(body) -> str:
    text = str(body or "").strip()
    if not text:
        raise SocialError("A comment needs some text.")
    if len(text) > MAX_COMMENT:
        raise SocialError("A comment is at most %d characters." % MAX_COMMENT)
    return text


def add_comment(user, article: WikiArticle, body, parent_id=None) -> WikiComment:
    if not can_comment(user, article):
        raise SocialError("You cannot comment on this article.")
    text = _clean_body(body)
    parent = None
    if parent_id not in (None, ""):
        try:
            parent = db.session.get(WikiComment, int(parent_id))
        except (TypeError, ValueError):
            parent = None
        if parent is None or parent.article_id != article.id or parent.deleted:
            raise SocialError("The comment you replied to no longer exists.")
    c = WikiComment(article_id=article.id, parent_id=parent.id if parent else None,
                    author_id=getattr(user, "id", None), body=text,
                    created_at=datetime.utcnow())
    db.session.add(c)
    _ensure(user, "article", str(article.id))
    db.session.commit()
    return c


def edit_comment(user, comment: WikiComment, body) -> WikiComment:
    if not can_change_comment(user, comment):
        raise SocialError("Only its author can edit a comment.")
    comment.body = _clean_body(body)
    comment.edited_at = datetime.utcnow()
    db.session.commit()
    return comment


def delete_comment(comment: WikiComment) -> None:
    """A comment with replies is blanked (the thread under it stays
    readable); one without is removed, and so is a blanked parent left with
    no reply."""
    has_replies = WikiComment.query.filter_by(parent_id=comment.id).first() is not None
    parent_id = comment.parent_id
    if has_replies:
        comment.deleted = True
        comment.body = ""
    else:
        db.session.delete(comment)
    db.session.flush()
    while parent_id:
        parent = db.session.get(WikiComment, parent_id)
        if parent is None or not parent.deleted or \
                WikiComment.query.filter_by(parent_id=parent.id).first() is not None:
            break
        parent_id = parent.parent_id
        db.session.delete(parent)
        db.session.flush()
    db.session.commit()


def thread(article: WikiArticle) -> list[dict]:
    """The article's comments depth-first, oldest first at each level:
    ``{"comment", "depth", "html"}``. A reply under a missing parent (it
    cannot happen through this module) is shown at the top level."""
    rows = (WikiComment.query.filter_by(article_id=article.id)
            .order_by(WikiComment.created_at, WikiComment.id).all())
    ids = {c.id for c in rows}
    kids: dict = {}
    for c in rows:
        kids.setdefault(c.parent_id if c.parent_id in ids else None, []).append(c)
    out: list[dict] = []

    def walk(parent, depth, seen):
        for c in kids.get(parent, []):
            if c.id in seen:
                continue
            out.append({"comment": c, "depth": min(depth, MAX_DEPTH),
                        "html": wmd.render(c.body) if not c.deleted else ""})
            walk(c.id, depth + 1, seen | {c.id})
    walk(None, 0, frozenset())
    return out


def comment_count(article_id: int) -> int:
    return WikiComment.query.filter_by(article_id=article_id, deleted=False).count()


# ── subscriptions ────────────────────────────────────────────────────────────

def _adom_keys() -> list[str]:
    from ..branding import PRODUCTS
    return [k for k in PRODUCTS.keys() if k != "global"]


def normalise_ref(kind: str, ref) -> str:
    """``ref`` for ``kind`` in the stored form, or :class:`SocialError`."""
    if kind not in SUBSCRIPTION_KINDS:
        raise SocialError("Unknown subscription.")
    raw = str(ref or "").strip()
    if kind == "all":
        return ""
    if kind in ("article", "topic"):
        if not raw.isdigit():
            raise SocialError("That %s no longer exists." % kind)
        return str(int(raw))
    if kind == "tag":
        tag = wiki.normalise_tag(raw)
        if not tag:
            raise SocialError("Name a tag.")
        return tag
    key = raw.lower()
    if key != "global" and key not in _adom_keys():
        raise SocialError("Unknown ADOM.")
    return key


def _ensure(user, kind: str, ref: str) -> None:
    uid = getattr(user, "id", None)
    if uid and WikiSubscription.query.filter_by(user_id=uid, kind=kind, ref=ref).first() is None:
        db.session.add(WikiSubscription(user_id=uid, kind=kind, ref=ref,
                                        created_at=datetime.utcnow()))


def subscription(user, kind: str, ref) -> WikiSubscription | None:
    try:
        ref = normalise_ref(kind, ref)
    except SocialError:
        return None
    return WikiSubscription.query.filter_by(user_id=getattr(user, "id", None),
                                            kind=kind, ref=ref).first()


def set_subscription(user, kind: str, ref, *, on: bool, email: bool = False):
    """Follow (``on``) or stop following. Following an article needs being
    able to read it; a topic must exist. Returns the row or ``None``."""
    ref = normalise_ref(kind, ref)
    uid = getattr(user, "id", None)
    row = WikiSubscription.query.filter_by(user_id=uid, kind=kind, ref=ref).first()
    if not on:
        if row is not None:
            db.session.delete(row)
            db.session.commit()
        return None
    if kind == "article":
        art = db.session.get(WikiArticle, int(ref))
        if art is None or not wiki_access.can_view(user, art):
            raise SocialError("That article no longer exists.")
    elif kind == "topic" and db.session.get(WikiTopic, int(ref)) is None:
        raise SocialError("That topic no longer exists.")
    if row is None:
        row = WikiSubscription(user_id=uid, kind=kind, ref=ref, created_at=datetime.utcnow())
        db.session.add(row)
    row.email = bool(email)
    db.session.commit()
    return row


def scope_follows(user) -> set[str]:
    """What the list page's Follow menu shows ticked: ``"all"`` for
    everything, ``"global"`` and the ADOM keys the user follows."""
    rows = (WikiSubscription.query.filter_by(user_id=getattr(user, "id", None))
            .filter(WikiSubscription.kind.in_(("all", "adom"))).all())
    return {"all" if r.kind == "all" else r.ref for r in rows}


def set_scope_follows(user, picked) -> tuple[int, int]:
    """The list page's Follow menu: follow exactly ``picked`` (``"all"``,
    ``"global"``, ADOM keys) among everything and the ADOMs. A row that
    stays keeps its e-mail choice; articles, topics and tags are not
    touched. ``(added, removed)``."""
    want = set()
    for raw in picked or ():
        key = str(raw or "").strip().lower()
        want.add("all" if key == "all" else normalise_ref("adom", key))
    uid = getattr(user, "id", None)
    added = removed = 0
    rows = (WikiSubscription.query.filter_by(user_id=uid)
            .filter(WikiSubscription.kind.in_(("all", "adom"))).all())
    have = set()
    for r in rows:
        key = "all" if r.kind == "all" else r.ref
        if key in want:
            have.add(key)
        else:
            db.session.delete(r)
            removed += 1
    for key in sorted(want - have):
        kind, ref = ("all", "") if key == "all" else ("adom", key)
        db.session.add(WikiSubscription(user_id=uid, kind=kind, ref=ref,
                                        created_at=datetime.utcnow()))
        added += 1
    db.session.commit()
    return added, removed


def article_follows(user, article_ids) -> dict[int, WikiSubscription]:
    """``{article_id: subscription}`` for the articles of a list page."""
    refs = [str(int(i)) for i in article_ids]
    if not refs:
        return {}
    rows = WikiSubscription.query.filter(WikiSubscription.user_id == getattr(user, "id", None),
                                         WikiSubscription.kind == "article",
                                         WikiSubscription.ref.in_(refs)).all()
    return {int(r.ref): r for r in rows}


def my_subscriptions(user) -> list[dict]:
    """The user's subscriptions with a label each. An article they can no
    longer read is labelled as such, never by its title."""
    out = []
    names = {k: n for k, n in _adom_names().items()}
    for s in (WikiSubscription.query.filter_by(user_id=getattr(user, "id", None))
              .order_by(WikiSubscription.kind, WikiSubscription.ref).all()):
        label, url = s.ref, None
        if s.kind == "article":
            art = db.session.get(WikiArticle, int(s.ref)) if s.ref.isdigit() else None
            if art is not None and wiki_access.can_view(user, art):
                label, url = art.title, ("article", art)
            else:
                label = None
        elif s.kind == "topic":
            t = db.session.get(WikiTopic, int(s.ref)) if s.ref.isdigit() else None
            label, url = (t.label, ("topic", t)) if t else (None, None)
        elif s.kind == "tag":
            label = "#" + s.ref
            url = ("tag", s.ref)
        elif s.kind == "adom":
            label = "Global" if s.ref == "global" else names.get(s.ref, s.ref)
        else:
            label = "Every article"
        out.append({"sub": s, "label": label, "target": url})
    return out


def _adom_names() -> dict:
    from ..branding import PRODUCTS
    return {k: PRODUCTS[k].get("name", k) for k in _adom_keys()}


def forget_article(article_id: int) -> None:
    """An article was deleted: its subscriptions and the notices that point
    at it go too (the bell would otherwise keep its title)."""
    from ..models_notifications import Notification
    WikiSubscription.query.filter_by(kind="article", ref=str(article_id)).delete(
        synchronize_session=False)
    for n in Notification.query.filter(Notification.link.like("%%/wiki/a/%d%%" % article_id)).all():
        m = LINK_RE.search(n.link or "")
        if m and int(m.group(1)) == article_id:
            db.session.delete(n)
    db.session.commit()


def forget_topics(topic_ids) -> None:
    refs = [str(t) for t in topic_ids]
    if refs:
        WikiSubscription.query.filter(WikiSubscription.kind == "topic",
                                      WikiSubscription.ref.in_(refs)).delete(
            synchronize_session=False)
        db.session.commit()


# ── who is told ──────────────────────────────────────────────────────────────

def _matching(article: WikiArticle, *, event: str) -> dict[int, bool]:
    """``{user_id: wants_email}`` of the subscriptions an event on
    ``article`` concerns. A new version concerns the article, its topic and
    every topic above it, its tags, its ADOMs (a Global article: "global"
    and every ADOM, since it shows in each) and "all". A comment concerns
    only the people following the article."""
    conds = [db.and_(WikiSubscription.kind == "article",
                     WikiSubscription.ref == str(article.id))]
    if event == "publish":
        conds.append(WikiSubscription.kind == "all")
        if article.topic is not None:
            conds.append(db.and_(WikiSubscription.kind == "topic",
                                 WikiSubscription.ref.in_([str(t.id) for t in article.topic.path])))
        tags = [t.name for t in article.tags]
        if tags:
            conds.append(db.and_(WikiSubscription.kind == "tag", WikiSubscription.ref.in_(tags)))
        adoms = article.adoms or ["global"] + _adom_keys()
        conds.append(db.and_(WikiSubscription.kind == "adom", WikiSubscription.ref.in_(adoms)))
    out: dict[int, bool] = {}
    for s in WikiSubscription.query.filter(db.or_(*conds)).all():
        out[s.user_id] = out.get(s.user_id, False) or bool(s.email)
    return out


def recipients(article: WikiArticle, user_ids, *, actor_id=None) -> list[User]:
    """``user_ids`` narrowed to active users, not the actor, who can open
    ``article`` right now."""
    out = []
    for uid in sorted(set(user_ids)):
        if uid == actor_id:
            continue
        u = db.session.get(User, uid)
        if u is None or not u.is_active:
            continue
        if wiki_access.can_view(u, article):
            out.append(u)
    return out


def bell_product(user, article: WikiArticle) -> str:
    """The ADOM whose bell shows the notice (module docstring)."""
    allowed = wiki_access._adoms_of(user)
    adoms = article.adoms
    if adoms:
        cands = adoms if allowed is None else [a for a in adoms if a in allowed]
    else:
        cands = [] if allowed is None else sorted(allowed)
    if not cands or "fortiweb" in cands:
        return ""
    return cands[0]


def _notify(article: WikiArticle, users: list[User], wants_email: dict, *, title: str,
            body: str, link: str, external: str, mail_subject: str, mail_body: str) -> int:
    from . import notifications as notify
    n = 0
    mails = []
    for u in users:
        if notify.push(u.id, title, kind="info", body=body, link=link,
                       product=bell_product(u, article)) is not None:
            n += 1
        if wants_email.get(u.id) and (u.recovery_email or "").strip():
            mails.append(u.recovery_email.strip())
    if mails:
        _mail_later(mails, mail_subject, mail_body + "\n\n" + external + "\n")
    return n


def _mail_later(addresses: list[str], subject: str, body: str) -> None:
    """One message per address, off the request thread."""
    from flask import current_app
    from . import email_service
    try:
        if not email_service.is_configured():
            return
        app = current_app._get_current_object()
    except Exception:  # noqa: BLE001 — no app, no mail; the bell has it
        return

    def run():
        with app.app_context():
            for addr in addresses:
                try:
                    res = email_service.send_email([addr], subject, body)
                    if not res.get("ok"):
                        logger.info("wiki mail to %s not sent: %s", addr, res.get("detail"))
                except Exception:  # noqa: BLE001
                    logger.exception("wiki mail to %s failed", addr)
    if SEND_INLINE:
        run()
    else:
        threading.Thread(target=run, name="wiki-mail", daemon=True).start()


#: Tests set this so the mail is sent before the request returns.
SEND_INLINE = False


def _links(article: WikiArticle, anchor: str = "") -> tuple[str, str]:
    from flask import url_for

    from .link_host import external_url
    path = url_for("wiki.article", article_id=article.id, slug=article.slug) + anchor
    try:   # mailed to other users: never on a host the request made up
        ext = external_url("wiki.article", article_id=article.id,
                           slug=article.slug) + anchor
    except Exception:  # noqa: BLE001
        ext = path
    return path, ext


def notify_published(article: WikiArticle, actor, *, first: bool) -> int:
    """A new version was published. The author follows their article from
    its first publication on (they can stop)."""
    if first and article.author_id:
        author = db.session.get(User, article.author_id)
        if author is not None:
            _ensure(author, "article", str(article.id))
            db.session.commit()
    who = getattr(actor, "username", "") or "someone"
    wants = _matching(article, event="publish")
    users = recipients(article, wants, actor_id=getattr(actor, "id", None))
    if not users:
        return 0
    link, ext = _links(article)
    if first:
        title = "New Wiki article: %s" % article.title
        mail_subject = "[SATOM Wiki] New article: %s" % article.title
    else:
        title = "Wiki article updated: %s (version %d)" % (article.title, article.revision)
        mail_subject = "[SATOM Wiki] Updated: %s (version %d)" % (article.title, article.revision)
    body = "%s published version %d." % (who, article.revision)
    if article.summary:
        body += "\n" + article.summary
    return _notify(article, users, wants, title=title, body=body, link=link, external=ext,
                   mail_subject=mail_subject, mail_body=body)


def notify_comment(article: WikiArticle, comment: WikiComment, actor) -> int:
    """A comment: everyone following the article, and the author of the
    comment it answers ("replied to you") even if they stopped following."""
    who = getattr(actor, "username", "") or "someone"
    wants = _matching(article, event="comment")
    parent_author = None
    if comment.parent_id:
        parent = db.session.get(WikiComment, comment.parent_id)
        parent_author = parent.author_id if parent is not None else None
        if parent_author and parent_author not in wants:
            wants[parent_author] = False
    users = recipients(article, wants, actor_id=getattr(actor, "id", None))
    if not users:
        return 0
    link, ext = _links(article, "#c%d" % comment.id)
    excerpt = wmd.plain_excerpt(comment.body, EXCERPT)
    n = 0
    for group, verb in (([u for u in users if u.id == parent_author], "replied to you on"),
                        ([u for u in users if u.id != parent_author], "commented on")):
        if not group:
            continue
        title = "%s %s %s" % (who, verb, article.title)
        n += _notify(article, group, wants, title=title[:200], body=excerpt, link=link,
                     external=ext, mail_subject="[SATOM Wiki] " + title,
                     mail_body=excerpt)
    return n


# ── the bell asks again ──────────────────────────────────────────────────────

def bell_gate(user_id: int, link: str) -> bool:
    """False hides a Wiki notice the user can no longer act on: the article
    is gone or they may not open it any more."""
    m = LINK_RE.search(link or "")
    if not m:
        return True
    art = db.session.get(WikiArticle, int(m.group(1)))
    user = db.session.get(User, user_id)
    return art is not None and user is not None and wiki_access.can_view(user, art)
