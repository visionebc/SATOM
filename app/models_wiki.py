"""Operations › Wiki — articles users write for each other.

An article is published to an AUDIENCE made of three filters that must all
hold (services/wiki_access.py is the only place that reads them):

* ADOMs   — ``wiki_article_adoms``; no row = Global (every ADOM).
* Who     — ``audience_restricted`` + ``wiki_article_profiles`` +
            ``wiki_article_groups``; not restricted = everybody who can see
            those ADOMs. Restricted: a reader matches when their profile is
            listed OR they belong to a listed group (none left = nobody).
* Status  — ``draft`` (author only), ``published``, ``archived``.

Groups are the Wiki's own (``wiki_groups``): a SATOM profile is a bundle of
permissions, one per user, so it cannot say "the network team" across
profiles. A group can.

Every save of the body keeps a ``WikiRevision``; the article row holds the
current text so lists and search never join the history.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db

STATUSES = ("draft", "published", "archived")

wiki_article_adoms = db.Table(
    "wiki_article_adoms",
    db.Column("article_id", db.Integer,
              db.ForeignKey("wiki_articles.id", ondelete="CASCADE"), primary_key=True),
    db.Column("adom", db.String(32), primary_key=True),
)

wiki_article_profiles = db.Table(
    "wiki_article_profiles",
    db.Column("article_id", db.Integer,
              db.ForeignKey("wiki_articles.id", ondelete="CASCADE"), primary_key=True),
    db.Column("profile_id", db.Integer,
              db.ForeignKey("profiles.id", ondelete="CASCADE"), primary_key=True),
)

wiki_article_groups = db.Table(
    "wiki_article_groups",
    db.Column("article_id", db.Integer,
              db.ForeignKey("wiki_articles.id", ondelete="CASCADE"), primary_key=True),
    db.Column("group_id", db.Integer,
              db.ForeignKey("wiki_groups.id", ondelete="CASCADE"), primary_key=True),
)

wiki_article_tags = db.Table(
    "wiki_article_tags",
    db.Column("article_id", db.Integer,
              db.ForeignKey("wiki_articles.id", ondelete="CASCADE"), primary_key=True),
    db.Column("tag_id", db.Integer,
              db.ForeignKey("wiki_tags.id", ondelete="CASCADE"), primary_key=True),
)

wiki_group_members = db.Table(
    "wiki_group_members",
    db.Column("group_id", db.Integer,
              db.ForeignKey("wiki_groups.id", ondelete="CASCADE"), primary_key=True),
    db.Column("user_id", db.Integer,
              db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
)


class WikiGroup(db.Model):
    __tablename__ = "wiki_groups"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    members = db.relationship("User", secondary=wiki_group_members, lazy="select",
                              order_by="User.username")

    def __repr__(self) -> str:
        return "<WikiGroup %r>" % self.name


class WikiTopic(db.Model):
    """One node of the topic tree. An article sits in at most one topic."""
    __tablename__ = "wiki_topics"
    __table_args__ = (db.UniqueConstraint("parent_id", "name", name="uq_wiki_topic_name"),)

    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("wiki_topics.id", ondelete="CASCADE"),
                          nullable=True, index=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    parent = db.relationship("WikiTopic", remote_side=[id], backref="children")

    @property
    def path(self) -> list["WikiTopic"]:
        """Root first. A cycle cannot be stored (services/wiki.py refuses
        it), but a hand-edited row must not loop forever here."""
        out, node, seen = [], self, set()
        while node is not None and node.id not in seen:
            seen.add(node.id)
            out.append(node)
            node = node.parent
        return list(reversed(out))

    @property
    def label(self) -> str:
        return " › ".join(t.name for t in self.path)

    def __repr__(self) -> str:
        return "<WikiTopic %r>" % self.name


class WikiTag(db.Model):
    __tablename__ = "wiki_tags"

    id = db.Column(db.Integer, primary_key=True)
    #: Normalised by services/wiki.normalise_tag — compare names, never labels.
    name = db.Column(db.String(40), unique=True, nullable=False)


class WikiArticle(db.Model):
    __tablename__ = "wiki_articles"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="draft", index=True)
    topic_id = db.Column(db.Integer, db.ForeignKey("wiki_topics.id", ondelete="SET NULL"),
                         nullable=True, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                          nullable=True, index=True)
    #: True when the author picked profiles and/or groups. Kept apart from the
    #: rows on purpose: a deleted profile drops its row, and "no row" must not
    #: turn a restricted article into everybody's (services/wiki_access.py).
    audience_restricted = db.Column(db.Boolean, nullable=False, default=False)
    revision = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    published_at = db.Column(db.DateTime, nullable=True)

    topic =db.relationship("WikiTopic")
    author = db.relationship("User")
    tags = db.relationship(WikiTag, secondary=wiki_article_tags, lazy="select",
                           order_by=WikiTag.name)
    profiles = db.relationship("Profile", secondary=wiki_article_profiles, lazy="select")
    groups = db.relationship(WikiGroup, secondary=wiki_article_groups, lazy="select",
                             order_by=WikiGroup.name)

    @property
    def adoms(self) -> list[str]:
        rows = db.session.execute(
            db.select(wiki_article_adoms.c.adom)
            .where(wiki_article_adoms.c.article_id == self.id)).scalars().all()
        return sorted(rows)

    def __repr__(self) -> str:
        return "<WikiArticle %s %r>" % (self.id, self.slug)


class WikiRevision(db.Model):
    __tablename__ = "wiki_revisions"
    __table_args__ = (db.UniqueConstraint("article_id", "number", name="uq_wiki_revision"),)

    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey("wiki_articles.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    number = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    note = db.Column(db.String(200), nullable=False, default="")
    edited_by = db.Column(db.String(64), nullable=False, default="")
    edited_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
