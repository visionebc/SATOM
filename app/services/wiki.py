"""Operations › Wiki — writing articles, topics, tags and groups.

Reading is decided in services/wiki_access.py, never here. This module only
validates what is written: the article form (title, body, topic, tags,
audience) and the moderator's topic tree. Groups are Administrator › Access ›
Groups (views/user_groups.py), shared with Python Studio apps.

Writing an article is two steps. :func:`save_draft` (autosaved by the
editor) keeps a shared working draft — readers of a published article keep
seeing the released text. :func:`publish` releases the draft as a new
numbered version (``WikiRevision``).
"""
from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime

from ..extensions import db
from ..models import Profile, User
from ..models_wiki import (STATUSES, UserGroup, WikiArticle, WikiRevision, WikiTag,
                           WikiTopic, wiki_article_adoms, wiki_article_groups)
from . import wiki_access

MAX_TAGS = 12
MAX_BODY = 200_000
MAX_SUMMARY = 300
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


class WikiConflict(WikiError):
    """Someone else saved the draft after this editor loaded it."""


def _values(user, form: dict, article: WikiArticle | None, *, adom_keys,
            may_set_audience: bool, draft: bool) -> dict:
    """``form`` validated into the values an article holds. ``draft``
    accepts an empty title (shown as "Untitled") — only publishing needs one.
    Without ``may_set_audience`` the article's current ADOMs, profiles and
    groups are kept whatever the form says."""
    title = " ".join(str(form.get("title") or "").split())
    body = str(form.get("body") or "")
    if not title:
        if not draft:
            raise WikiError("The title is required.")
        title = "Untitled"
    if len(title) > 200:
        raise WikiError("The title is longer than 200 characters.")
    if len(body) > MAX_BODY:
        raise WikiError("The article is longer than %d characters." % MAX_BODY)
    summary = " ".join(str(form.get("summary") or "").split())
    if len(summary) > MAX_SUMMARY:
        raise WikiError("The description is longer than %d characters." % MAX_SUMMARY)

    topic_id = None
    if form.get("topic_id"):
        try:
            topic_id = int(form["topic_id"])
        except (TypeError, ValueError):
            raise WikiError("That topic no longer exists.") from None
        if db.session.get(WikiTopic, topic_id) is None:
            raise WikiError("That topic no longer exists.")

    if not may_set_audience and article is not None:
        adoms = list(article.adoms)
        profile_ids = sorted(p.id for p in article.profiles)
        group_ids = sorted(g.id for g in article.groups)
        restricted = bool(article.audience_restricted)
    else:
        # The editor sends "global" as its own checkbox. Ticked ADOMs win over
        # it (the narrower audience) if both arrive. ADOMs the editor could
        # not list (inactive, or outside the editor's profile) are kept
        # unless Global was ticked on its own: an unchanged save must never
        # widen the audience.
        may = set(wiki_access.assignable_adoms(user, adom_keys))
        raw = [str(k) for k in (form.get("adoms") or []) if str(k)]
        adoms = [k for k in raw if k != "global"]
        bad = [k for k in adoms if k not in may]
        if bad:
            raise WikiError("You cannot publish to the %s ADOM." % ", ".join(sorted(bad)))
        if article is not None and (adoms or "global" not in raw):
            adoms += [k for k in article.adoms if k not in may and k not in adoms]
        profile_ids = sorted({int(p) for p in (form.get("profiles") or []) if str(p).isdigit()})
        group_ids = sorted({int(g) for g in (form.get("groups") or []) if str(g).isdigit()})
        found_p = Profile.query.filter(Profile.id.in_(profile_ids)).count() if profile_ids else 0
        found_g = UserGroup.query.filter(UserGroup.id.in_(group_ids)).count() if group_ids else 0
        if found_p != len(profile_ids) or found_g != len(group_ids):
            raise WikiError("A selected profile or group no longer exists.")
        restricted = bool(profile_ids or group_ids)
    return {"title": title, "summary": summary, "body": body, "topic_id": topic_id,
            "tags": sorted(parse_tags(form.get("tags"))), "adoms": sorted(set(adoms)),
            "profiles": profile_ids, "groups": group_ids, "restricted": restricted}


def snapshot(article: WikiArticle) -> dict:
    """The released values of ``article``, in the shape of :func:`_values`."""
    return {"title": article.title, "summary": article.summary or "", "body": article.body,
            "topic_id": article.topic_id, "tags": sorted(t.name for t in article.tags),
            "adoms": article.adoms, "profiles": sorted(p.id for p in article.profiles),
            "groups": sorted(g.id for g in article.groups),
            "restricted": bool(article.audience_restricted)}


def _apply(article: WikiArticle, v: dict) -> None:
    with db.session.no_autoflush:
        article.slug = _unique_slug(v["title"], article.id)
    article.title = v["title"]
    article.summary = v["summary"]
    article.body = v["body"]
    article.topic_id = v["topic_id"]
    article.tags = _tag_rows(v["tags"])
    article.profiles = (Profile.query.filter(Profile.id.in_(v["profiles"])).all()
                        if v["profiles"] else [])
    article.groups = (UserGroup.query.filter(UserGroup.id.in_(v["groups"])).all()
                      if v["groups"] else [])
    article.audience_restricted = v["restricted"]
    db.session.flush()
    set_adoms(article, v["adoms"])


def _new_article(user, v: dict) -> WikiArticle:
    now = datetime.utcnow()
    with db.session.no_autoflush:
        slug = _unique_slug(v["title"], None)
    art = WikiArticle(author_id=getattr(user, "id", None), created_at=now, updated_at=now,
                      revision=0, body="", title=v["title"], slug=slug, status="draft")
    db.session.add(art)
    db.session.flush()
    return art


def _check_rev(article: WikiArticle, base_rev) -> None:
    if base_rev is None or article is None:
        return
    try:
        base = int(base_rev)
    except (TypeError, ValueError):
        return
    if base != (article.draft_rev or 0):
        who = article.draft_user.username if article.draft_user else "someone"
        when = article.draft_saved_at.strftime("%H:%M UTC") if article.draft_saved_at else ""
        raise WikiConflict("%s saved this draft at %s after you opened it. Reload to see "
                           "their changes; your text is still in the editor." % (who, when))


def has_draft(article: WikiArticle) -> bool:
    """A published (or archived) article with unpublished changes."""
    return article.status != "draft" and article.draft_data is not None


def draft_values(article: WikiArticle) -> dict:
    """What the editor shows: the pending draft if there is one, else the
    released text."""
    if has_draft(article):
        try:
            return json.loads(article.draft_data)
        except ValueError:
            pass
    return snapshot(article)


def form_from_values(v: dict, note: str = "") -> dict:
    """:func:`_values` output in the shape of the posted form."""
    return {"title": "" if v.get("title") == "Untitled" else v.get("title", ""),
            "summary": v.get("summary", ""), "body": v.get("body", ""),
            "topic_id": str(v["topic_id"]) if v.get("topic_id") else "",
            "tags": ", ".join(v.get("tags") or []),
            "adoms": list(v.get("adoms") or []) or ["global"],
            "profiles": [str(p) for p in v.get("profiles") or []],
            "groups": [str(g) for g in v.get("groups") or []], "note": note,
            "status": "draft"}


def save_draft(user, form: dict, article: WikiArticle | None = None, *, adom_keys=(),
               base_rev=None, may_set_audience: bool = True) -> WikiArticle:
    """Autosave. A never-published article IS its draft: its fields are
    written (only its author and the moderators can read it). A published
    one keeps its released text for readers; the draft goes to
    ``draft_data`` until :func:`publish`. No version is made here."""
    _check_rev(article, base_rev)
    v = _values(user, form, article, adom_keys=adom_keys,
                may_set_audience=may_set_audience, draft=True)
    now = datetime.utcnow()
    if article is None:
        article = _new_article(user, v)
    if article.status == "draft":
        _apply(article, v)
        article.draft_data = None
    else:
        article.draft_data = json.dumps(v, sort_keys=True)
    article.draft_rev = (article.draft_rev or 0) + 1
    article.draft_saved_at = now
    article.draft_user_id = getattr(user, "id", None)
    article.updated_at = now
    db.session.commit()
    return article


def publish(user, form: dict, article: WikiArticle | None = None, *, adom_keys=(),
            base_rev=None, may_set_audience: bool = True, note: str = "") -> WikiArticle:
    """Release the draft: the article takes the form's values and gets a new
    numbered version. Publishing with nothing changed makes no version."""
    _check_rev(article, base_rev)
    v = _values(user, form, article, adom_keys=adom_keys,
                may_set_audience=may_set_audience, draft=False)
    now = datetime.utcnow()
    if article is None:
        article = _new_article(user, v)
    changed = article.status != "published" or article.revision == 0 \
        or snapshot(article) != v
    _apply(article, v)
    article.draft_data = None
    article.draft_rev = (article.draft_rev or 0) + 1
    article.draft_saved_at = None
    article.draft_user_id = None
    if changed:
        article.status = "published"
        if article.published_at is None:
            article.published_at = now
        article.updated_at = now
        article.revision = (article.revision or 0) + 1
        db.session.add(WikiRevision(article_id=article.id, number=article.revision,
                                    title=v["title"], summary=v["summary"], body=v["body"],
                                    edited_by=getattr(user, "username", "") or "",
                                    edited_at=now, note=str(note or "")[:200]))
    db.session.commit()
    prune_tags()
    return article


def discard_draft(article: WikiArticle) -> None:
    """Drop a published article's pending changes (readers saw none)."""
    article.draft_data = None
    article.draft_rev = (article.draft_rev or 0) + 1
    article.draft_saved_at = None
    article.draft_user_id = None
    db.session.commit()


def set_status(article: WikiArticle, status: str) -> None:
    """Archive / restore a released article. Not a version: the text does
    not change."""
    if status not in ("published", "archived") or article.revision == 0:
        raise WikiError("Only a published article can be archived or restored.")
    article.status = status
    article.updated_at = datetime.utcnow()
    db.session.commit()


def save_article(user, form: dict, article: WikiArticle | None = None, *,
                 adom_keys=()) -> WikiArticle:
    """One-shot write by ``form["status"]``: ``published`` publishes (a new
    version), ``draft`` saves the draft, ``archived`` publishes then
    archives. The editor pages call :func:`save_draft` / :func:`publish`."""
    status = str(form.get("status") or "draft")
    if status not in STATUSES:
        raise WikiError("Unknown status.")
    if status == "draft":
        return save_draft(user, form, article, adom_keys=adom_keys)
    art = publish(user, form, article, adom_keys=adom_keys, note=form.get("note") or "")
    if status == "archived":
        set_status(art, "archived")
    return art


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


def topic_nav(counts: dict) -> list[dict]:
    """The topic tree as nested ``{"topic", "count", "children"}`` for the
    Wiki's topic menu. ``counts`` = readable articles per ``topic_id``
    (the caller counts them after visibility); a node's count includes its
    sub-topics, like filtering by it does."""
    rows = WikiTopic.query.order_by(WikiTopic.name).all()
    kids: dict[int | None, list[WikiTopic]] = {}
    for t in rows:
        kids.setdefault(t.parent_id, []).append(t)

    def build(parent, depth, seen):
        out = []
        for t in kids.get(parent, []):
            if t.id in seen or depth > 16:
                continue
            children = build(t.id, depth + 1, seen | {t.id})
            out.append({"topic": t, "children": children,
                        "count": int(counts.get(t.id, 0))
                        + sum(c["count"] for c in children)})
        return out
    return build(None, 0, frozenset())


def _like(text: str) -> str:
    """``%text%`` for ILIKE with ``%`` / ``_`` / ``\\`` taken literally."""
    esc = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + esc + "%"


def search_clause(text: str):
    """SQL condition for the Wiki search box, or ``None`` for no words.

    Every word must appear SOMEWHERE in the article: title, description,
    text, a tag, the author's user name, or the name or description of its
    topic or of any topic above it (a word naming "FortiWeb" finds the
    articles under FortiWeb › Certificates). The caller applies it on top
    of :func:`wiki_access.visible_query`, never instead of it.
    """
    words = [w for w in str(text or "").split() if w][:8]
    if not words:
        return None
    conds = []
    for w in words:
        pat = _like(w[:100])
        topic_ids: set[int] = set()
        for t in WikiTopic.query.filter(db.or_(
                WikiTopic.name.ilike(pat, escape="\\"),
                WikiTopic.description.ilike(pat, escape="\\"))).all():
            topic_ids.update(descendant_ids(t.id))
        authors = db.select(User.id).where(User.username.ilike(pat, escape="\\"))
        one = [WikiArticle.title.ilike(pat, escape="\\"),
               WikiArticle.summary.ilike(pat, escape="\\"),
               WikiArticle.body.ilike(pat, escape="\\"),
               WikiArticle.tags.any(WikiTag.name.ilike(pat, escape="\\")),
               WikiArticle.author_id.in_(authors)]
        if topic_ids:
            one.append(WikiArticle.topic_id.in_(sorted(topic_ids)))
        conds.append(db.or_(*one))
    return db.and_(*conds)


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

def articles_using_group(group_id: int) -> list[str]:
    """Titles of the articles whose audience names ``group_id``. Deleting the
    group does not open them: they stay ``audience_restricted`` and, with no
    profile or group left, only their author and the moderators read them
    (services/wiki_access.py)."""
    rows = (db.session.query(WikiArticle.title)
            .join(wiki_article_groups, wiki_article_groups.c.article_id == WikiArticle.id)
            .filter(wiki_article_groups.c.group_id == group_id)
            .order_by(WikiArticle.title).all())
    return [r[0] for r in rows]
