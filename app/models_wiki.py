"""Operations › Wiki — articles users write for each other.

An article is published to an AUDIENCE made of three filters that must all
hold (services/wiki_access.py is the only place that reads them):

* ADOMs   — ``wiki_article_adoms``; no row = Global (every ADOM).
* Who     — ``audience_restricted`` + ``wiki_article_profiles`` +
            ``wiki_article_groups``; not restricted = everybody who can see
            those ADOMs. Restricted: a reader matches when their profile is
            listed OR they belong to a listed group (none left = nobody).
* Status  — ``draft`` (author only), ``published``, ``archived``.

Groups are Administrator › Access › Groups (``user_groups``, the same groups
Python Studio apps are shared with): a SATOM profile is a bundle of
permissions, one per user, so it cannot say "the network team" across
profiles. A group can. Until 2026-10-20 the Wiki kept groups of its own
(``wiki_groups``); migration wiki04 merged them into ``user_groups``.

Editing writes a shared, autosaved DRAFT; readers keep the released text
until someone publishes, and every publication is a new numbered version
(``WikiRevision``). The article row holds the released text so lists and
search never join the history.
"""
from __future__ import annotations

from datetime import datetime

from .extensions import db
from .models_studio import UserGroup, user_group_members  # noqa: F401 -- re-exported

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
              db.ForeignKey("user_groups.id", ondelete="CASCADE"), primary_key=True),
)

wiki_article_tags = db.Table(
    "wiki_article_tags",
    db.Column("article_id", db.Integer,
              db.ForeignKey("wiki_articles.id", ondelete="CASCADE"), primary_key=True),
    db.Column("tag_id", db.Integer,
              db.ForeignKey("wiki_tags.id", ondelete="CASCADE"), primary_key=True),
)

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
    #: One or two plain-text sentences shown under the title in lists and
    #: searched with everything else (``summary`` in the schema).
    summary = db.Column(db.String(300), nullable=False, default="", server_default="")
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
    #: Number of the last RELEASED version (0 = never published). A version
    #: is made only by publishing (services/wiki.publish).
    revision = db.Column(db.Integer, nullable=False, default=0)
    #: The shared working draft of a published article, autosaved by
    #: whoever edits it: validated form values as JSON (services/wiki.
    #: save_draft). Readers keep seeing the released fields above until it
    #: is published. A never-published article is its own draft (None here).
    draft_data = db.Column(db.Text, nullable=True)
    #: Bumped by every draft save; an editor whose page holds an older
    #: number gets a conflict instead of overwriting someone else's text.
    draft_rev = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    draft_saved_at = db.Column(db.DateTime, nullable=True)
    draft_user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                              nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    published_at = db.Column(db.DateTime, nullable=True)

    topic = db.relationship("WikiTopic")
    author = db.relationship("User", foreign_keys=[author_id])
    draft_user = db.relationship("User", foreign_keys=[draft_user_id])
    tags = db.relationship(WikiTag, secondary=wiki_article_tags, lazy="select",
                           order_by=WikiTag.name)
    profiles = db.relationship("Profile", secondary=wiki_article_profiles, lazy="select")
    groups = db.relationship(UserGroup, secondary=wiki_article_groups, lazy="select",
                             order_by=UserGroup.name)

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
    summary = db.Column(db.String(300), nullable=False, default="", server_default="")
    body = db.Column(db.Text, nullable=False, default="")
    note = db.Column(db.String(200), nullable=False, default="")
    edited_by = db.Column(db.String(64), nullable=False, default="")
    edited_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class WikiComment(db.Model):
    """A comment under an article; ``parent_id`` makes it a reply. Markdown,
    rendered by services/wiki_markdown.py like the article. A deleted
    comment that has replies keeps its row (``deleted``, body emptied) so the
    thread under it still reads; one without replies is removed."""
    __tablename__ = "wiki_comments"

    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey("wiki_articles.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("wiki_comments.id", ondelete="CASCADE"),
                          nullable=True, index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                          nullable=True, index=True)
    body = db.Column(db.Text, nullable=False, default="")
    deleted = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    edited_at = db.Column(db.DateTime, nullable=True)

    author = db.relationship("User")


#: What a subscription follows. ``ref``: the article id, the topic id, the
#: normalised tag, the ADOM key ("global" = articles published to Global),
#: or "" for ``all``.
SUBSCRIPTION_KINDS = ("article", "topic", "tag", "adom", "all")


class WikiSubscription(db.Model):
    """One user following one thing. Notices go to the bell; ``email`` adds
    a mail to the user's recovery address. Who receives a notice is decided
    when it is sent AND when the bell shows it (services/wiki_social.py):
    following never lets anyone read an article they could not open."""
    __tablename__ = "wiki_subscriptions"
    __table_args__ = (db.UniqueConstraint("user_id", "kind", "ref", name="uq_wiki_subscription"),)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False)
    ref = db.Column(db.String(64), nullable=False, default="", server_default="")
    email = db.Column(db.Boolean, nullable=False, default=False, server_default=db.false())
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship("User")


class WikiConfluenceTarget(db.Model):
    """A Confluence connection articles are published through (services/
    wiki_confluence.py; Settings › Integrations › Confluence). The space and
    the parent page are chosen at each publication (``WikiConfluenceLink``).
    One way: SATOM writes the page, Confluence never writes back, and an
    edit made in Confluence is replaced by the next publication. The credential is not here: ``wiki.confluence.secret.<id>``
    (Fernet) or the vault, like every SATOM secret."""
    __tablename__ = "wiki_confluence_targets"

    FLAVORS = ("cloud", "datacenter")
    AUTHS = ("basic", "bearer")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    #: ``cloud`` = REST API v2 under https://<site>.atlassian.net/wiki;
    #: ``datacenter`` = Server / Data Center REST API (/rest/api/content).
    flavor = db.Column(db.String(16), nullable=False, default="cloud")
    base_url = db.Column(db.String(500), nullable=False, default="")
    #: Unused since wiki07 (the space and parent are picked per publication);
    #: kept so a downgrade finds its columns.
    space_key = db.Column(db.String(64), nullable=False, default="")
    parent_page_id = db.Column(db.String(32), nullable=False, default="", server_default="")
    #: ``basic`` = e-mail + API token (Cloud) or user + password;
    #: ``bearer`` = a personal access token (Data Center).
    auth = db.Column(db.String(16), nullable=False, default="basic")
    username = db.Column(db.String(255), nullable=False, default="", server_default="")
    verify_tls = db.Column(db.Boolean, nullable=False, default=True, server_default=db.true())
    enabled = db.Column(db.Boolean, nullable=False, default=True, server_default=db.true())
    created_by = db.Column(db.String(64), nullable=False, default="", server_default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class WikiConfluenceLink(db.Model):
    """Which Confluence page an article was published to, and which version
    it holds: one per article, connection and space. The page id is what
    later publications to that space update."""
    __tablename__ = "wiki_confluence_links"
    __table_args__ = (db.UniqueConstraint("article_id", "target_id", "space_key",
                                          name="uq_wiki_confluence_link_space"),)

    id = db.Column(db.Integer, primary_key=True)
    article_id = db.Column(db.Integer, db.ForeignKey("wiki_articles.id", ondelete="CASCADE"),
                           nullable=False, index=True)
    target_id = db.Column(db.Integer,
                          db.ForeignKey("wiki_confluence_targets.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    #: The space the page was created in, and the page it was created under
    #: ('' = the space's top level). The page may have moved since.
    space_key = db.Column(db.String(64), nullable=False, default="", server_default="")
    parent_page_id = db.Column(db.String(32), nullable=False, default="", server_default="")
    page_id = db.Column(db.String(32), nullable=False)
    page_url = db.Column(db.String(1000), nullable=False, default="")
    published_revision = db.Column(db.Integer, nullable=False, default=0)
    published_at = db.Column(db.DateTime, nullable=True)
    published_by = db.Column(db.String(64), nullable=False, default="", server_default="")

    target = db.relationship(WikiConfluenceTarget)
