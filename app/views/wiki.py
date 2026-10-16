# app/views/wiki.py
"""Operations › Wiki — articles users write for each other.

Every route that names an article asks services/wiki_access.py first and
answers 404 for an article the user may not read: a 403 would confirm that
an article with that id exists. Lists, counters and the tag autocomplete go
through :func:`wiki_access.visible_query`, so a restricted article never
lends its title, its tags or its count to anything a reader sees.

Writes: ``wiki.write`` to create and to edit one's own articles,
``wiki.moderate`` for everybody's, for the topic tree and for the Wiki
groups. Every write is audited.
"""
from __future__ import annotations

from flask import (Blueprint, abort, flash, g, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import or_

from ..auth.decorators import require_permission
from ..branding import PRODUCTS
from ..extensions import db
from ..models import Profile, User
from ..models_wiki import (STATUSES, WikiArticle, WikiGroup, WikiRevision, WikiTag,
                           WikiTopic, wiki_article_adoms, wiki_article_tags)
from ..services import wiki, wiki_access
from ..services import wiki_markdown as wmd
from ..services.audit import log_action

bp = Blueprint("wiki", __name__, url_prefix="/wiki")

PER_PAGE = 25


def _adom_keys() -> list[str]:
    return [k for k in PRODUCTS.keys() if k != "global"]


def _adom_names() -> dict[str, str]:
    return {k: PRODUCTS[k].get("name", k) for k in _adom_keys()}


def _current_adom() -> str:
    key = getattr(g, "product", "") or "global"
    return key if key in _adom_keys() else "global"


def _article_or_404(article_id: int) -> WikiArticle:
    art = db.session.get(WikiArticle, article_id)
    if art is None or not wiki_access.can_view(current_user, art):
        abort(404)
    return art


def _like(text: str) -> str:
    """``%text%`` for ILIKE with ``%`` / ``_`` / ``\\`` taken literally."""
    esc = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + esc + "%"


def _form_dict() -> dict:
    f = request.form
    return {"title": f.get("title", ""), "body": f.get("body", ""),
            "status": f.get("status", "draft"), "topic_id": f.get("topic_id") or None,
            "tags": f.get("tags", ""), "note": f.get("note", ""),
            "adoms": f.getlist("adoms"), "profiles": f.getlist("profiles"),
            "groups": f.getlist("groups")}


def _editor_context(article=None, form=None) -> dict:
    return {"article": article, "form": form,
            "topics": wiki.topic_tree(),
            "adoms": [(k, n) for k, n in _adom_names().items()
                      if k in wiki_access.assignable_adoms(current_user, _adom_keys())],
            "profiles": Profile.query.order_by(Profile.name).all(),
            "groups": WikiGroup.query.order_by(WikiGroup.name).all(),
            "statuses": STATUSES,
            "default_adom": _current_adom()}


# ── reading ──────────────────────────────────────────────────────────────────

@bp.route("/")
@login_required
@require_permission("wiki.view")
def index():
    """The article list: filters are applied in SQL, after visibility."""
    q = wiki_access.visible_query(current_user)
    args = request.args
    text = (args.get("q") or "").strip()[:200]
    if text:
        pat = _like(text)
        q = q.filter(or_(WikiArticle.title.ilike(pat, escape="\\"),
                         WikiArticle.body.ilike(pat, escape="\\")))
    topic_id = args.get("topic", type=int)
    topic = db.session.get(WikiTopic, topic_id) if topic_id else None
    if topic is not None:
        q = q.filter(WikiArticle.topic_id.in_(wiki.descendant_ids(topic.id)))
    tag = wiki.normalise_tag(args.get("tag"))
    if tag:
        q = q.filter(WikiArticle.tags.any(WikiTag.name == tag))
    # ADOM filter. Default: in a device ADOM "this ADOM + Global", in the
    # Global ADOM every ADOM. ``all`` lifts it, ``global`` = Global articles
    # only, a key = that ADOM's articles + Global ones.
    adom = (args.get("adom") or "").strip().lower()
    if adom not in _adom_keys() and adom not in ("all", "global"):
        adom = _current_adom() if _current_adom() != "global" else "all"
    any_adom = db.exists().where(wiki_article_adoms.c.article_id == WikiArticle.id)
    if adom == "global":
        q = q.filter(~any_adom)
    elif adom != "all":
        q = q.filter(or_(~any_adom, db.exists().where(
            (wiki_article_adoms.c.article_id == WikiArticle.id)
            & (wiki_article_adoms.c.adom == adom))))
    status = args.get("status") or ""
    if status in STATUSES:
        q = q.filter(WikiArticle.status == status)
    elif not args.get("archived"):
        q = q.filter(WikiArticle.status != "archived")
    if args.get("mine"):
        q = q.filter(WikiArticle.author_id == current_user.id)

    page = max(1, args.get("page", 1, type=int))
    pagination = (q.order_by(WikiArticle.updated_at.desc(), WikiArticle.id.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    tag_counts = _tag_counts()
    return render_template(
        "wiki/index.html", pagination=pagination, articles=pagination.items,
        topics=wiki.topic_tree(), topic=topic, tag=tag, text=text, adom=adom,
        status=status, mine=bool(args.get("mine")), archived=bool(args.get("archived")),
        adom_names=_adom_names(), current_adom=_current_adom(), tag_counts=tag_counts,
        may_write=wiki_access.can_write(current_user),
        may_moderate=wiki_access.is_moderator(current_user),
        excerpt=wmd.plain_excerpt, page_url=_page_url)


def _page_url(number: int) -> str:
    args = request.args.to_dict()
    args["page"] = number
    return url_for("wiki.index", **args)


def _tag_counts(limit: int = 40) -> list[tuple[str, int]]:
    """Tags of the articles the user can read, most used first."""
    visible = wiki_access.visible_query(current_user).with_entities(WikiArticle.id)
    rows = (db.session.query(WikiTag.name, db.func.count(wiki_article_tags.c.article_id))
            .join(wiki_article_tags, wiki_article_tags.c.tag_id == WikiTag.id)
            .filter(wiki_article_tags.c.article_id.in_(visible))
            .group_by(WikiTag.name)
            .order_by(db.func.count(wiki_article_tags.c.article_id).desc(), WikiTag.name)
            .limit(limit).all())
    return [(n, c) for n, c in rows]


@bp.route("/a/<int:article_id>")
@bp.route("/a/<int:article_id>/<slug>")
@login_required
@require_permission("wiki.view")
def article(article_id, slug=None):
    art = _article_or_404(article_id)
    return render_template(
        "wiki/article.html", article=art, html=wmd.render(art.body),
        adom_names=_adom_names(),
        may_edit=wiki_access.can_edit(current_user, art),
        may_moderate=wiki_access.is_moderator(current_user))


@bp.route("/a/<int:article_id>/history")
@login_required
@require_permission("wiki.view")
def history(article_id):
    art = _article_or_404(article_id)
    revs = (WikiRevision.query.filter_by(article_id=art.id)
            .order_by(WikiRevision.number.desc()).all())
    return render_template("wiki/history.html", article=art, revisions=revs)


@bp.route("/a/<int:article_id>/rev/<int:number>")
@login_required
@require_permission("wiki.view")
def revision(article_id, number):
    art = _article_or_404(article_id)
    rev = WikiRevision.query.filter_by(article_id=art.id, number=number).first_or_404()
    return render_template("wiki/revision.html", article=art, rev=rev,
                           html=wmd.render(rev.body))


@bp.route("/api/tags")
@login_required
@require_permission("wiki.view")
def api_tags():
    """Autocomplete: tags of readable articles only (a tag on a restricted
    article is information about it)."""
    prefix = wiki.normalise_tag(request.args.get("q"))
    names = [n for n, _c in _tag_counts(limit=200) if n.startswith(prefix)]
    return jsonify(ok=True, tags=names[:20])


@bp.route("/api/preview", methods=["POST"])
@login_required
@require_permission("wiki.view")
def api_preview():
    if not wiki_access.can_write(current_user):
        abort(403)
    body = str((request.get_json(silent=True) or {}).get("body") or "")[: wiki.MAX_BODY]
    return jsonify(ok=True, html=str(wmd.render(body)))


# ── writing ──────────────────────────────────────────────────────────────────

@bp.route("/new", methods=["GET", "POST"])
@login_required
@require_permission("wiki.view")
def new():
    if not wiki_access.can_write(current_user):
        abort(403)
    if request.method == "POST":
        form = _form_dict()
        try:
            art = wiki.save_article(current_user, form, adom_keys=_adom_keys())
        except wiki.WikiError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
            return render_template("wiki/edit.html", **_editor_context(form=form)), 400
        log_action("wiki.article.create", target=art.slug,
                   extra={"article_id": art.id, "status": art.status,
                          "adoms": art.adoms, "restricted": art.audience_restricted})
        flash("Article saved.", "success")
        return redirect(url_for("wiki.article", article_id=art.id, slug=art.slug))
    return render_template("wiki/edit.html", **_editor_context())


@bp.route("/a/<int:article_id>/edit", methods=["GET", "POST"])
@login_required
@require_permission("wiki.view")
def edit(article_id):
    art = _article_or_404(article_id)
    if not wiki_access.can_edit(current_user, art):
        abort(403)
    if request.method == "POST":
        form = _form_dict()
        try:
            wiki.save_article(current_user, form, art, adom_keys=_adom_keys())
        except wiki.WikiError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
            return render_template("wiki/edit.html",
                                   **_editor_context(article=art, form=form)), 400
        log_action("wiki.article.update", target=art.slug,
                   extra={"article_id": art.id, "revision": art.revision,
                          "status": art.status, "adoms": art.adoms,
                          "restricted": art.audience_restricted})
        flash("Article saved.", "success")
        return redirect(url_for("wiki.article", article_id=art.id, slug=art.slug))
    return render_template("wiki/edit.html", **_editor_context(article=art))


@bp.route("/a/<int:article_id>/delete", methods=["POST"])
@login_required
@require_permission("wiki.view")
def delete(article_id):
    art = _article_or_404(article_id)
    if not wiki_access.can_edit(current_user, art):
        abort(403)
    slug, aid = art.slug, art.id
    wiki.delete_article(art)
    log_action("wiki.article.delete", target=slug, extra={"article_id": aid})
    flash("Article deleted.", "success")
    return redirect(url_for("wiki.index"))


# ── moderation: topics and groups ────────────────────────────────────────────

@bp.route("/topics", methods=["GET", "POST"])
@login_required
@require_permission("wiki.moderate")
def topics():
    if request.method == "POST":
        tid = request.form.get("topic_id", type=int)
        topic = db.session.get(WikiTopic, tid) if tid else None
        try:
            topic = wiki.save_topic(request.form.to_dict(), topic)
        except wiki.WikiError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
            return redirect(url_for("wiki.topics"))
        log_action("wiki.topic.save", target=topic.label, extra={"topic_id": topic.id})
        flash("Topic saved.", "success")
        return redirect(url_for("wiki.topics"))
    counts = dict(db.session.query(WikiArticle.topic_id, db.func.count(WikiArticle.id))
                  .group_by(WikiArticle.topic_id).all())
    return render_template("wiki/topics.html", tree=wiki.topic_tree(), counts=counts)


@bp.route("/topics/<int:topic_id>/delete", methods=["POST"])
@login_required
@require_permission("wiki.moderate")
def topic_delete(topic_id):
    topic = db.session.get(WikiTopic, topic_id) or abort(404)
    label = topic.label
    wiki.delete_topic(topic)
    log_action("wiki.topic.delete", target=label, extra={"topic_id": topic_id})
    flash("Topic deleted; its articles are kept without a topic.", "success")
    return redirect(url_for("wiki.topics"))


@bp.route("/groups", methods=["GET", "POST"])
@bp.route("/groups/<int:group_id>", methods=["GET", "POST"])
@login_required
@require_permission("wiki.moderate")
def groups(group_id=None):
    group = (db.session.get(WikiGroup, group_id) or abort(404)) if group_id else None
    if request.method == "POST":
        form = {"name": request.form.get("name", ""),
                "description": request.form.get("description", ""),
                "members": request.form.getlist("members")}
        try:
            group = wiki.save_group(form, group)
        except wiki.WikiError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
            return redirect(url_for("wiki.groups", group_id=group_id) if group_id
                            else url_for("wiki.groups"))
        log_action("wiki.group.save", target=group.name,
                   extra={"group_id": group.id,
                          "members": [u.username for u in group.members]})
        flash("Group saved.", "success")
        return redirect(url_for("wiki.groups"))
    return render_template("wiki/groups.html", group=group,
                           groups=WikiGroup.query.order_by(WikiGroup.name).all(),
                           users=User.query.order_by(User.username).all())


@bp.route("/groups/<int:group_id>/delete", methods=["POST"])
@login_required
@require_permission("wiki.moderate")
def group_delete(group_id):
    group = db.session.get(WikiGroup, group_id) or abort(404)
    name = group.name
    wiki.delete_group(group)
    log_action("wiki.group.delete", target=name, extra={"group_id": group_id})
    flash("Group deleted. Articles that named it stay restricted.", "success")
    return redirect(url_for("wiki.groups"))
