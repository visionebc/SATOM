"""Who may read, edit and moderate a Wiki article — the ONLY place that decides.

Every surface that shows an article, a title or a count asks here: the list
and its counters (:func:`visible_query`), the article page and every by-id
route (:func:`can_view`), and from stage 1b on the notifications, comments
and exports. A second, hand-kept copy of this rule is how a restricted title
would leak through one of them.

An article is visible to a user when ALL of these hold:

1. the user has ``wiki.view``;
2. it is ``published`` or ``archived`` (a draft is its author's only);
3. ADOMs: the article names none (Global), or the user is not confined to
   ADOMs, or one of the article's ADOMs is in the user's set;
4. Who: the article is not ``audience_restricted``, or the user's profile
   is named, or the user belongs to a named group.

Editing follows reading: :func:`can_edit` is "can read it + ``wiki.write``";
the audience, archiving and deleting stay with the author and the
moderators (:func:`can_manage`).

Bypasses: the author always sees their own article (they still need
``wiki.view`` to open the Wiki at all), and ``wiki.moderate`` sees every
article — moderation has to reach what it moderates.

Fail closed: "who" is the ``audience_restricted`` flag, NOT "some profile or
group row exists". Deleting a profile or a group removes its rows (ON DELETE
CASCADE); with the flag, an article whose only listed profile is gone is
visible to nobody but its author and the moderators. Reading "no row" as
"everybody" would have opened it to the whole console.
"""
from __future__ import annotations

from sqlalchemy import and_, exists, false, or_, select, true

from ..extensions import db
from ..models_wiki import (WikiArticle, user_group_members, wiki_article_adoms,
                           wiki_article_groups, wiki_article_profiles)

READABLE = ("published", "archived")


def _can(user, key: str) -> bool:
    can = getattr(user, "can", None)
    return bool(getattr(user, "is_authenticated", False) and callable(can) and can(key))


def is_moderator(user) -> bool:
    return _can(user, "wiki.moderate")


def effective_profile_id(user) -> int | None:
    """The profile the user acts under. A user with no profile row (legacy
    role) acts under the system profile of that role, exactly as
    ``User.effective_permissions`` does."""
    pid = getattr(user, "profile_id", None)
    if pid:
        return pid
    from .. import permissions as perm
    from ..models import Profile
    name = perm.role_to_profile_name(getattr(user, "role", "") or "")
    row = Profile.query.filter_by(name=name).first()
    return row.id if row else None


def _adoms_of(user) -> frozenset[str] | None:
    try:
        return user.allowed_adoms
    except Exception:  # noqa: BLE001 — an unreadable restriction confines to nothing
        return frozenset()


def visibility_clause(user):
    """SQL condition over ``WikiArticle`` — rule above, for lists and counts."""
    if not _can(user, "wiki.view"):
        return false()
    if is_moderator(user):
        return true()
    uid = getattr(user, "id", None)
    a_id = WikiArticle.id

    allowed = _adoms_of(user)
    if allowed is None:
        adom_ok = true()
    else:
        any_adom = exists().where(wiki_article_adoms.c.article_id == a_id)
        in_set = (exists().where(and_(wiki_article_adoms.c.article_id == a_id,
                                      wiki_article_adoms.c.adom.in_(sorted(allowed))))
                  if allowed else false())
        adom_ok = or_(~any_adom, in_set)

    pid = effective_profile_id(user)
    my_profile = (exists().where(and_(wiki_article_profiles.c.article_id == a_id,
                                      wiki_article_profiles.c.profile_id == pid))
                  if pid else false())
    my_group = exists().where(and_(
        wiki_article_groups.c.article_id == a_id,
        wiki_article_groups.c.group_id.in_(
            select(user_group_members.c.group_id)
            .where(user_group_members.c.user_id == uid))))
    who_ok = or_(WikiArticle.audience_restricted.is_(False), my_profile, my_group)

    readers = and_(WikiArticle.status.in_(READABLE), adom_ok, who_ok)
    if uid is None:
        return readers
    return or_(WikiArticle.author_id == uid, readers)


def visible_query(user, query=None):
    """``query`` (default: every article) narrowed to what ``user`` may read."""
    q = query if query is not None else WikiArticle.query
    return q.filter(visibility_clause(user))


def can_view(user, article: WikiArticle | None) -> bool:
    """Same rule as :func:`visibility_clause`, asked of ONE article by the
    database, so the page and the list can never disagree."""
    if article is None or article.id is None:
        return False
    hit = db.session.execute(
        select(WikiArticle.id).where(and_(WikiArticle.id == article.id,
                                          visibility_clause(user)))).first()
    return hit is not None


def can_write(user) -> bool:
    return _can(user, "wiki.write") or is_moderator(user)


def can_edit(user, article: WikiArticle) -> bool:
    """Everyone who may READ the article and holds ``wiki.write`` edits its
    text (title, description, body, topic, tags) — reading is the gate, so
    nobody edits what they cannot see. Moderators edit everything."""
    if is_moderator(user):
        return True
    return can_write(user) and can_view(user, article)


def can_manage(user, article: WikiArticle) -> bool:
    """Who changes WHO CAN READ an article, archives it or deletes it: its
    author (still holding ``wiki.write``) and the moderators. Another editor
    could otherwise open a restricted article to the whole console."""
    if is_moderator(user):
        return True
    return (_can(user, "wiki.write") and article.author_id is not None
            and article.author_id == getattr(user, "id", None))


def assignable_adoms(user, registry_keys) -> list[str]:
    """ADOMs ``user`` may publish to: their own set (all for an unconfined
    user or a moderator). Global is "no ADOM", not a key."""
    keys = [k for k in registry_keys if k != "global"]
    allowed = None if is_moderator(user) else _adoms_of(user)
    if allowed is None:
        return keys
    return [k for k in keys if k in allowed]
