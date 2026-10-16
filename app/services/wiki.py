"""Operations › Wiki — writing articles, topics, tags and groups.

Reading is decided in services/wiki_access.py, never here. This module only
validates what is written: the article form (title, body, topic, tags,
audience) and the moderator's topic tree and groups.
"""
from __future__ import annotations

import re
import unicodedata
from datetime import datetime

from ..extensions import db
from ..models import Profile, User
from ..models_wiki import (STATUSES, WikiArticle, WikiGroup, WikiRevision, WikiTag,
                           WikiTopic, wiki_article_adoms)
from . import wiki_access

MAX_TAGS = 12
MAX_BODY = 200_000
_TAG_OK = re.compile(r"[^\w.+#-]+", re.U)


class WikiError(ValueError):
    """A form value the Wiki refuses; the message is shown to the user."""


def normalise_tag(raw: str | None) -> str:
    """``"  TLS  Certificates "`` → ``"tls-certificates"``. Case and spacing
    never make two tags."""
    s = unicodedata.normalize("NFKC", str(raw or "")).strip().casefold()
    s = re.sub(r"\s+", "-", s)
    s = _TAG_OK.sub("", s).strip("-.")
    return s[:40]


def parse_tags(raw) -> list[str]:
    items = raw if isinstance(raw, (list, tuple)) else re.split(r"[,;\n]", str(raw or ""))
    out: list[str] = []
    for item in items:
        tag = normalise_tag(item)
        if tag and tag not in out:
            out.append(tag)
    if len(out) > MAX_TAGS:
        raise WikiError("An article takes at most %d tags." % MAX_TAGS)
    return out


def slugify(title: str) -> str:
    s = unicodedata.normalize("NFKD", title or "")
    s = "".join(c for c in s if not unicodedata.combining(c)).lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    return (s or "article")[:100]


def _unique_slug(title: str, article_id: int | None) -> str:
    base = slugify(title)
    slug, n = base, 2
    while True:
        hit = WikiArticle.query.filter(WikiArticle.slug == slug)
        if article_id:
            hit = hit.filter(WikiArticle.id != article_id)
        if hit.first() is None:
            return slug
        slug = "%s-%d" % (base[:94], n)
        n += 1


def _tag_rows(names: list[str]) -> list[WikiTag]:
    rows = []
    for name in names:
        row = WikiTag.query.filter_by(name=name).first()
        if row is None:
            row = WikiTag(name=name)
            db.session.add(row)
        rows.append(row)
    return rows


def set_adoms(article: WikiArticle, keys) -> None:
    db.session.execute(wiki_article_adoms.delete()
                       .where(wiki_article_adoms.c.article_id == article.id))
    for key in sorted(set(keys or ())):
        db.session.execute(wiki_article_adoms.insert().values(article_id=article.id, adom=key))


def save_article(user, form: dict, article: WikiArticle | None = None, *,
                 adom_keys=()) -> WikiArticle:
    """Create or update an article from ``form`` (already a plain dict).

    ``adom_keys`` = the registry's ADOM keys; the user may publish only to
    :func:`wiki_access.assignable_adoms`. A new revision is kept whenever
    the title or the body changes.
    """
    title = str(form.get("title") or "").strip()
    body = str(form.get("body") or "")
    if not title:
        raise WikiError("The title is required.")
    if len(title) > 200:
        raise WikiError("The title is longer than 200 characters.")
    if len(body) > MAX_BODY:
        raise WikiError("The article is longer than %d characters." % MAX_BODY)
    status = str(form.get("status") or "draft")
    if status not in STATUSES:
        raise WikiError("Unknown status.")

    topic = None
    if form.get("topic_id"):
        topic = db.session.get(WikiTopic, int(form["topic_id"]))
        if topic is None:
            raise WikiError("That topic no longer exists.")

    may = set(wiki_access.assignable_adoms(user, adom_keys))
    adoms = [str(k) for k in (form.get("adoms") or []) if str(k)]
    bad = [k for k in adoms if k not in may]
    if bad:
        raise WikiError("You cannot publish to the %s ADOM." % ", ".join(sorted(bad)))

    profile_ids = sorted({int(p) for p in (form.get("profiles") or []) if str(p).isdigit()})
    group_ids = sorted({int(g) for g in (form.get("groups") or []) if str(g).isdigit()})
    profiles = Profile.query.filter(Profile.id.in_(profile_ids)).all() if profile_ids else []
    groups = WikiGroup.query.filter(WikiGroup.id.in_(group_ids)).all() if group_ids else []
    if len(profiles) != len(profile_ids) or len(groups) != len(group_ids):
        raise WikiError("A selected profile or group no longer exists.")

    tags = parse_tags(form.get("tags"))
    now = datetime.utcnow()
    who = getattr(user, "username", "") or ""

    # The slug query must not autoflush a new article whose slug is still
    # NULL (IntegrityError), so it is computed before the row joins the session.
    with db.session.no_autoflush:
        slug = _unique_slug(title, article.id if article is not None else None)
    if article is None:
        article = WikiArticle(author_id=getattr(user, "id", None), created_at=now,
                              revision=0, body="", title=title, slug=slug)
        db.session.add(article)
        changed = True
    else:
        changed = article.title != title or article.body != body

    article.title = title
    article.body = body
    article.slug = slug
    article.topic = topic
    article.tags = _tag_rows(tags)
    article.profiles = profiles
    article.groups = groups
    article.audience_restricted = bool(profiles or groups)
    if status == "published" and article.published_at is None:
        article.published_at = now
    article.status = status
    article.updated_at = now
    db.session.flush()
    set_adoms(article, adoms)

    if changed:
        article.revision = (article.revision or 0) + 1
        db.session.add(WikiRevision(article_id=article.id, number=article.revision,
                                    title=title, body=body, edited_by=who, edited_at=now,
                                    note=str(form.get("note") or "")[:200]))
    db.session.commit()
    return article


def delete_article(article: WikiArticle) -> None:
    db.session.delete(article)
    db.session.commit()
    prune_tags()


def prune_tags() -> int:
    """Drop tags no article uses any more, so the autocomplete stays honest."""
    from ..models_wiki import wiki_article_tags
    used = db.select(wiki_article_tags.c.tag_id)
    n = WikiTag.query.filter(~WikiTag.id.in_(used)).delete(synchronize_session=False)
    db.session.commit()
    return n


# ── topics ───────────────────────────────────────────────────────────────────

def topic_tree() -> list[dict]:
    """Every topic, depth-first, as ``{"topic", "depth"}``."""
    rows = WikiTopic.query.order_by(WikiTopic.name).all()
    kids: dict[int | None, list[WikiTopic]] = {}
    for t in rows:
        kids.setdefault(t.parent_id, []).append(t)
    out: list[dict] = []

    def walk(parent, depth):
        for t in kids.get(parent, []):
            out.append({"topic": t, "depth": depth})
            if depth < 16:
                walk(t.id, depth + 1)
    walk(None, 0)
    return out


def descendant_ids(topic_id: int) -> list[int]:
    """``topic_id`` and every topic below it (filtering by a topic includes
    its sub-topics)."""
    ids, frontier = [topic_id], [topic_id]
    while frontier:
        frontier = [t.id for t in WikiTopic.query.filter(WikiTopic.parent_id.in_(frontier))
                    if t.id not in ids]
        ids.extend(frontier)
    return ids


def save_topic(form: dict, topic: WikiTopic | None = None) -> WikiTopic:
    name = str(form.get("name") or "").strip()
    if not name or len(name) > 80:
        raise WikiError("A topic needs a name of at most 80 characters.")
    parent = None
    if form.get("parent_id"):
        parent = db.session.get(WikiTopic, int(form["parent_id"]))
        if parent is None:
            raise WikiError("The parent topic no longer exists.")
        if topic is not None and topic.id is not None and \
                parent.id in descendant_ids(topic.id):
            raise WikiError("A topic cannot be moved under itself.")
    clash = WikiTopic.query.filter(WikiTopic.name == name,
                                   WikiTopic.parent_id == (parent.id if parent else None))
    if topic is not None:
        clash = clash.filter(WikiTopic.id != topic.id)
    if clash.first() is not None:
        raise WikiError("That topic already exists there.")
    if topic is None:
        topic = WikiTopic()
        db.session.add(topic)
    topic.name = name
    topic.description = str(form.get("description") or "").strip()[:2000]
    topic.parent = parent
    db.session.commit()
    return topic


def delete_topic(topic: WikiTopic) -> None:
    """Sub-topics go with it (CASCADE); its articles keep existing, without
    a topic (SET NULL)."""
    ids = descendant_ids(topic.id)
    WikiArticle.query.filter(WikiArticle.topic_id.in_(ids)).update(
        {WikiArticle.topic_id: None}, synchronize_session=False)
    for t in WikiTopic.query.filter(WikiTopic.id.in_(ids)).order_by(WikiTopic.id.desc()):
        db.session.delete(t)
    db.session.commit()


# ── groups ───────────────────────────────────────────────────────────────────

def save_group(form: dict, group: WikiGroup | None = None) -> WikiGroup:
    name = str(form.get("name") or "").strip()
    if not name or len(name) > 64:
        raise WikiError("A group needs a name of at most 64 characters.")
    clash = WikiGroup.query.filter(db.func.lower(WikiGroup.name) == name.lower())
    if group is not None:
        clash = clash.filter(WikiGroup.id != group.id)
    if clash.first() is not None:
        raise WikiError("A group with that name already exists.")
    ids = sorted({int(u) for u in (form.get("members") or []) if str(u).isdigit()})
    members = User.query.filter(User.id.in_(ids)).all() if ids else []
    if len(members) != len(ids):
        raise WikiError("A selected user no longer exists.")
    if group is None:
        group = WikiGroup(created_at=datetime.utcnow())
        db.session.add(group)
    group.name = name
    group.description = str(form.get("description") or "").strip()[:2000]
    group.members = members
    db.session.commit()
    return group


def delete_group(group: WikiGroup) -> None:
    """Articles restricted to this group stay restricted
    (``audience_restricted``): without it they are visible to nobody but
    their author and the moderators, never to everybody."""
    db.session.delete(group)
    db.session.commit()
