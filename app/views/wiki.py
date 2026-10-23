# app/views/wiki.py
"""Operations › Wiki — articles users write for each other.

Every route that names an article asks services/wiki_access.py first and
answers 404 for an article the user may not read: a 403 would confirm that
an article with that id exists. Lists, counters and the tag autocomplete go
through :func:`wiki_access.visible_query`, so a restricted article never
lends its title, its tags or its count to anything a reader sees.

Writes: ``wiki.write`` to create, and to edit every article one can READ
(services/wiki_access.can_edit); the audience, archiving and deleting stay
with the author and ``wiki.moderate`` (can_manage), as does the topic tree.
Groups are Administrator › Access › Groups (views/user_groups.py). Editing autosaves a shared draft; publishing makes a
new version. Creating, publishing, discarding, archiving and deleting are
audited (an autosave is not).
"""
from __future__ import annotations

from flask import (Blueprint, Response, abort, flash, g, jsonify, redirect,
                   render_template, request, url_for)
from flask_login import current_user, login_required
from sqlalchemy import or_

from ..auth.decorators import require_permission
from ..branding import PRODUCTS
from ..extensions import db
from ..models import Profile
from ..models_wiki import (STATUSES, UserGroup, WikiArticle, WikiComment,
                           WikiConfluenceLink, WikiConfluenceTarget, WikiRevision, WikiTag,
                           WikiTopic, wiki_article_adoms, wiki_article_tags)
from ..services import wiki, wiki_access, wiki_confluence, wiki_export, wiki_social
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


def _form_dict() -> dict:
    f = request.form
    return {"title": f.get("title", ""), "summary": f.get("summary", ""),
            "body": f.get("body", ""),
            "status": f.get("status", "draft"), "topic_id": f.get("topic_id") or None,
            "tags": f.get("tags", ""), "note": f.get("note", ""),
            "adoms": f.getlist("adoms"), "profiles": f.getlist("profiles"),
            "groups": f.getlist("groups")}


def _editor_context(article=None, form=None) -> dict:
    """Names wiki/_editor_fields.html reads. For an existing article with
    no posted ``form`` the fields show its pending draft, or else the
    released text."""
    if article is not None and form is None:
        form = wiki.form_from_values(wiki.draft_values(article))
    return {"article": article, "form": form,
            "topics": wiki.topic_tree(),
            "adoms": [(k, n) for k, n in _adom_names().items()
                      if k in wiki_access.assignable_adoms(current_user, _adom_keys())],
            "profiles": Profile.query.order_by(Profile.name).all(),
            "groups": UserGroup.query.order_by(UserGroup.name).all(),
            "may_set_audience": article is None or wiki_access.can_manage(current_user, article),
            "draft_rev": article.draft_rev if article is not None else 0,
            "has_draft": bool(article is not None and wiki.has_draft(article)),
            "default_adom": _current_adom(),
            "default_topic": None}


# ── reading ──────────────────────────────────────────────────────────────────

def _filtered(args):
    """The list's query and filters from ``args`` — the page and its ZIP
    export use the same function, so the export holds what the list shows."""
    q = wiki_access.visible_query(current_user)
    text = (args.get("q") or "").strip()[:200]
    found = wiki.search_clause(text)
    if found is not None:
        q = q.filter(found)
    topic_id = args.get("topic", type=int)
    topic = db.session.get(WikiTopic, topic_id) if topic_id else None
    if topic is not None:
        q = q.filter(WikiArticle.topic_id.in_(wiki.descendant_ids(topic.id)))
    tag = wiki.normalise_tag(args.get("tag"))
    if tag:
        q = q.filter(WikiArticle.tags.any(WikiTag.name == tag))
    # ADOM filter: one checkbox per active ADOM plus Global. An article is
    # listed when it is Global and Global is ticked, or names a ticked ADOM.
    # Default: in a device ADOM "that ADOM + Global", in the Global ADOM all.
    # The old ``adom=`` links (all / global / a key) still work.
    choices = ["global"] + _adom_keys()
    picked = [k for k in args.getlist("adoms") if k in choices]
    if not picked:
        legacy = (args.get("adom") or "").strip().lower()
        if legacy == "all":
            picked = list(choices)
        elif legacy == "global":
            picked = ["global"]
        elif legacy in _adom_keys():
            picked = [legacy, "global"]
        else:
            cur = _current_adom()
            picked = list(choices) if cur == "global" else [cur, "global"]
    if set(picked) != set(choices):
        any_adom = db.exists().where(wiki_article_adoms.c.article_id == WikiArticle.id)
        conds = [~any_adom] if "global" in picked else []
        keys = [k for k in picked if k != "global"]
        if keys:
            conds.append(db.exists().where(
                (wiki_article_adoms.c.article_id == WikiArticle.id)
                & (wiki_article_adoms.c.adom.in_(keys))))
        q = q.filter(or_(*conds))
    status = args.get("status") or ""
    if status in STATUSES:
        q = q.filter(WikiArticle.status == status)
    elif not args.get("archived"):
        q = q.filter(WikiArticle.status != "archived")
    if args.get("mine"):
        q = q.filter(WikiArticle.author_id == current_user.id)

    return q, {"text": text, "topic": topic, "tag": tag, "picked": picked, "status": status}


@bp.route("/")
@login_required
@require_permission("wiki.view")
def index():
    """The article list: filters are applied in SQL, after visibility."""
    q, f = _filtered(request.args)
    topic, tag = f["topic"], f["tag"]
    args = request.args
    page = max(1, args.get("page", 1, type=int))
    pagination = (q.order_by(WikiArticle.updated_at.desc(), WikiArticle.id.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    return render_template(
        "wiki/index.html", pagination=pagination, articles=pagination.items,
        topic=topic, tag=tag, text=f["text"], picked=f["picked"],
        adom_choices=[("global", "Global")] + list(_adom_names().items()),
        status=f["status"], mine=bool(args.get("mine")), archived=bool(args.get("archived")),
        adom_names=_adom_names(), current_adom=_current_adom(),
        excerpt=wmd.plain_excerpt, page_url=_page_url, has_draft=wiki.has_draft,
        zip_args=dict({k: v for k, v in args.to_dict(flat=False).items()
                       if k not in ("page", "format", "adom")}, adoms=f["picked"]),
        follow_topic=wiki_social.subscription(current_user, "topic", topic.id) if topic else None,
        follow_tag=wiki_social.subscription(current_user, "tag", tag) if tag else None,
        follow_scope=wiki_social.scope_follows(current_user),
        follows=wiki_social.article_follows(current_user, [a.id for a in pagination.items]),
        cf_pages=wiki_confluence.link_counts([a.id for a in pagination.items]),
        **_confluence_ready(),
        **_nav_context(topic_id=topic.id if topic else None, tag=tag))


def _page_url(number: int) -> str:
    # flat=False: the ADOM filter is a repeated ``adoms`` argument; a flat
    # dict kept only the first ticked ADOM on page 2 and after.
    args = request.args.to_dict(flat=False)
    args["page"] = number
    return url_for("wiki.index", **args)


def _nav_context(*, topic_id=None, tag="") -> dict:
    """What the Wiki's left menu needs: the topic tree with the number of
    readable, non-archived articles under each node, the tags in use, and
    the editor choices for the "New article" dialog. Counted after
    visibility, so a restricted article never shows up as a number."""
    visible = (wiki_access.visible_query(current_user)
               .filter(WikiArticle.status != "archived"))
    counts = dict(visible.with_entities(WikiArticle.topic_id, db.func.count(WikiArticle.id))
                  .order_by(None).group_by(WikiArticle.topic_id).all())
    may_write = wiki_access.can_write(current_user)
    active = db.session.get(WikiTopic, topic_id) if topic_id else None
    ctx = {"nav_topics": wiki.topic_nav(counts), "nav_topic_id": topic_id,
           # The branch holding the current topic opens; the rest stay folded.
           "nav_open_ids": [t.id for t in active.path] if active else [],
           "nav_total": sum(counts.values()), "nav_untopiced": int(counts.get(None, 0)),
           "nav_tag": tag, "tag_counts": _tag_counts(),
           "may_write": may_write,
           "may_moderate": wiki_access.is_moderator(current_user)}
    if may_write:
        ctx["new_editor"] = _editor_context()
        ctx["new_editor"]["default_topic"] = topic_id
    return ctx


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
        may_manage=wiki_access.can_manage(current_user, art),
        has_draft=wiki.has_draft(art),
        comments=wiki_social.thread(art),
        may_comment=wiki_social.can_comment(current_user, art),
        may_change=lambda c: wiki_social.can_change_comment(current_user, c),
        may_delete=lambda c: wiki_social.can_delete_comment(current_user, c, art),
        watching=wiki_social.subscription(current_user, "article", art.id),
        cf_count=len(wiki_confluence.links(art)),
        **_confluence_ready(),
        **_nav_context(topic_id=art.topic_id))


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

def _wants_json() -> bool:
    return request.accept_mimetypes.best == "application/json"


def _write(art, *, may_set_audience: bool):
    """POST of the editor (page or dialog). ``action=draft`` saves the
    shared draft (the editor autosaves this way), ``action=publish``
    releases it as a new version. JSON for the editor's script, a redirect
    or the re-rendered page otherwise."""
    form = _form_dict()
    action = request.form.get("action", "draft")
    base_rev = request.form.get("draft_rev") if art is not None else None
    try:
        if action == "publish":
            before = art.revision if art is not None else 0
            art = wiki.publish(current_user, form, art, adom_keys=_adom_keys(),
                               base_rev=base_rev, may_set_audience=may_set_audience,
                               note=form.get("note", ""))
            created = art.revision != before
            if created:
                log_action("wiki.article.publish", target=art.slug,
                           extra={"article_id": art.id, "version": art.revision,
                                  "adoms": art.adoms, "restricted": art.audience_restricted})
                wiki_social.notify_published(art, current_user, first=before == 0)
        else:
            first = art is None
            art = wiki.save_draft(current_user, form, art, adom_keys=_adom_keys(),
                                  base_rev=base_rev, may_set_audience=may_set_audience)
            if first:
                log_action("wiki.article.create", target=art.slug,
                           extra={"article_id": art.id, "status": art.status})
    except wiki.WikiConflict as exc:
        db.session.rollback()
        if _wants_json():
            return jsonify(ok=False, conflict=True, error=str(exc)), 409
        flash(str(exc), "danger")
        return render_template("wiki/edit.html", **_editor_context(article=art, form=form)), 409
    except wiki.WikiError as exc:
        db.session.rollback()
        if _wants_json():
            return jsonify(ok=False, error=str(exc)), 400
        flash(str(exc), "danger")
        return render_template("wiki/edit.html", **_editor_context(article=art, form=form)), 400

    url = url_for("wiki.article", article_id=art.id, slug=art.slug)
    edit_url = url_for("wiki.edit", article_id=art.id)
    if action == "publish":
        msg = ("Version %d published." % art.revision) if created else "Nothing changed: no new version."
        flash(msg, "success" if created else "info")
        if _wants_json():
            return jsonify(ok=True, id=art.id, url=url, revision=art.revision, published=created)
        return redirect(url)
    saved = art.draft_saved_at.strftime("%H:%M:%S") if art.draft_saved_at else ""
    if _wants_json():
        return jsonify(ok=True, id=art.id, url=url, edit_url=edit_url,
                       draft_rev=art.draft_rev, saved_at=saved)
    flash("Draft saved.", "success")
    return redirect(edit_url)


@bp.route("/new", methods=["GET", "POST"])
@login_required
@require_permission("wiki.view")
def new():
    if not wiki_access.can_write(current_user):
        abort(403)
    if request.method == "POST":
        return _write(None, may_set_audience=True)
    return render_template("wiki/edit.html", **_editor_context())


@bp.route("/a/<int:article_id>/edit", methods=["GET", "POST"])
@login_required
@require_permission("wiki.view")
def edit(article_id):
    art = _article_or_404(article_id)
    if not wiki_access.can_edit(current_user, art):
        abort(403)
    if request.method == "POST":
        return _write(art, may_set_audience=wiki_access.can_manage(current_user, art))
    return render_template("wiki/edit.html", **_editor_context(article=art))


@bp.route("/a/<int:article_id>/discard", methods=["POST"])
@login_required
@require_permission("wiki.view")
def discard(article_id):
    """Drop a published article's unpublished changes."""
    art = _article_or_404(article_id)
    if not wiki_access.can_edit(current_user, art):
        abort(403)
    if wiki.has_draft(art):
        wiki.discard_draft(art)
        log_action("wiki.draft.discard", target=art.slug, extra={"article_id": art.id})
        flash("Unpublished changes discarded.", "success")
    return redirect(url_for("wiki.article", article_id=art.id, slug=art.slug))


@bp.route("/a/<int:article_id>/status", methods=["POST"])
@login_required
@require_permission("wiki.view")
def set_status(article_id):
    """Archive or restore — the author and the moderators."""
    art = _article_or_404(article_id)
    if not wiki_access.can_manage(current_user, art):
        abort(403)
    status = request.form.get("status", "")
    try:
        wiki.set_status(art, status)
    except wiki.WikiError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        log_action("wiki.article.status", target=art.slug,
                   extra={"article_id": art.id, "status": status})
        flash("Article archived." if status == "archived" else "Article restored.", "success")
    return redirect(url_for("wiki.article", article_id=art.id, slug=art.slug))


@bp.route("/a/<int:article_id>/delete", methods=["POST"])
@login_required
@require_permission("wiki.view")
def delete(article_id):
    art = _article_or_404(article_id)
    if not wiki_access.can_manage(current_user, art):
        abort(403)
    slug, aid = art.slug, art.id
    pages = [l.page_url for l in wiki_confluence.links(art)]
    wiki.delete_article(art)
    wiki_social.forget_article(aid)
    log_action("wiki.article.delete", target=slug,
               extra={"article_id": aid, "confluence_pages_left": pages})
    flash("Article deleted." + (" Its Confluence pages were not deleted: %s"
                                % ", ".join(pages) if pages else ""), "success")
    return redirect(url_for("wiki.index"))


# ── moderation: topics ────────────────────────────────────────────

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
    ids = wiki.descendant_ids(topic.id)
    wiki.delete_topic(topic)
    wiki_social.forget_topics(ids)
    log_action("wiki.topic.delete", target=label, extra={"topic_id": topic_id})
    flash("Topic deleted; its articles are kept without a topic.", "success")
    return redirect(url_for("wiki.topics"))


@bp.route("/groups")
@bp.route("/groups/<int:group_id>")
@login_required
@require_permission("wiki.view")
def groups(group_id=None):
    """The Wiki's groups are Administrator › Access › Groups since wiki04;
    old links land there (which asks for user management itself)."""
    return redirect(url_for("user_groups.index"))


# ── comments ─────────────────────────────────────────────────────────────────

def _comment_or_404(art: WikiArticle, comment_id: int) -> WikiComment:
    c = db.session.get(WikiComment, comment_id)
    if c is None or c.article_id != art.id:
        abort(404)
    return c


def _back(art, anchor=""):
    return redirect(url_for("wiki.article", article_id=art.id, slug=art.slug) + anchor)


@bp.route("/a/<int:article_id>/comments", methods=["POST"])
@login_required
@require_permission("wiki.view")
def comment_add(article_id):
    art = _article_or_404(article_id)
    if not wiki_social.can_comment(current_user, art):
        abort(403)
    try:
        c = wiki_social.add_comment(current_user, art, request.form.get("body"),
                                    request.form.get("parent_id") or None)
    except wiki_social.SocialError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return _back(art, "#comments")
    log_action("wiki.comment.add", target=art.slug,
               extra={"article_id": art.id, "comment_id": c.id, "reply_to": c.parent_id})
    wiki_social.notify_comment(art, c, current_user)
    return _back(art, "#c%d" % c.id)


@bp.route("/a/<int:article_id>/comments/<int:comment_id>/edit", methods=["POST"])
@login_required
@require_permission("wiki.view")
def comment_edit(article_id, comment_id):
    art = _article_or_404(article_id)
    c = _comment_or_404(art, comment_id)
    if not wiki_social.can_change_comment(current_user, c):
        abort(403)
    try:
        wiki_social.edit_comment(current_user, c, request.form.get("body"))
    except wiki_social.SocialError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        log_action("wiki.comment.edit", target=art.slug,
                   extra={"article_id": art.id, "comment_id": c.id})
    return _back(art, "#c%d" % c.id)


@bp.route("/a/<int:article_id>/comments/<int:comment_id>/delete", methods=["POST"])
@login_required
@require_permission("wiki.view")
def comment_delete(article_id, comment_id):
    art = _article_or_404(article_id)
    c = _comment_or_404(art, comment_id)
    if not wiki_social.can_delete_comment(current_user, c, art):
        abort(403)
    author = c.author.username if c.author else ""
    wiki_social.delete_comment(c)
    log_action("wiki.comment.delete", target=art.slug,
               extra={"article_id": art.id, "comment_id": comment_id, "author": author})
    flash("Comment deleted.", "success")
    return _back(art, "#comments")


# ── following ────────────────────────────────────────────────────────────────

def _safe_next(default: str) -> str:
    nxt = request.form.get("next") or ""
    return nxt if nxt.startswith("/wiki/") and not nxt.startswith("//") else default


@bp.route("/subscribe", methods=["POST"])
@login_required
@require_permission("wiki.view")
def subscribe():
    """Follow or stop following an article, a topic, a tag, an ADOM or
    everything (``kind`` + ``ref``); ``email`` adds a mail."""
    kind = request.form.get("kind", "")
    on = request.form.get("on", "1") == "1"
    try:
        wiki_social.set_subscription(current_user, kind, request.form.get("ref"), on=on,
                                     email=request.form.get("email") == "1")
    except wiki_social.SocialError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        flash("Following." if on else "No longer following.", "success")
    return redirect(_safe_next(url_for("wiki.subscriptions")))


@bp.route("/subscribe/scope", methods=["POST"])
@login_required
@require_permission("wiki.view")
def subscribe_scope():
    """The Follow menu above the article list: follow exactly the ticked
    ones among Everything, Global and the ADOMs."""
    try:
        added, removed = wiki_social.set_scope_follows(current_user,
                                                       request.form.getlist("scope"))
    except wiki_social.SocialError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        flash("Following updated." if added or removed else "Nothing changed.", "success")
    return redirect(_safe_next(url_for("wiki.index")))


@bp.route("/subscriptions")
@login_required
@require_permission("wiki.view")
def subscriptions():
    return render_template(
        "wiki/subscriptions.html", subs=wiki_social.my_subscriptions(current_user),
        topics=wiki.topic_tree(), adom_choices=[("global", "Global")] + list(_adom_names().items()),
        has_mail=bool((getattr(current_user, "recovery_email", "") or "").strip()),
        **_nav_context())


# ── export ───────────────────────────────────────────────────────────────────

_MIME = {"md": "text/markdown; charset=utf-8", "pdf": "application/pdf",
         "zip": "application/zip"}


def _download(data, name: str, kind: str) -> Response:
    resp = Response(data, mimetype=_MIME[kind])
    resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % name
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def _source_url(art) -> str:
    from ..services.link_host import external_url
    return external_url("wiki.article", article_id=art.id, slug=art.slug)


@bp.route("/a/<int:article_id>/export.<fmt>")
@login_required
@require_permission("wiki.view")
def export(article_id, fmt):
    """One released version (``?rev=N``, default the current one) as
    Markdown or PDF. Readers export what they can read; drafts never."""
    if fmt not in ("md", "pdf"):
        abort(404)
    art = _article_or_404(article_id)
    try:
        rev = wiki_export.version_of(art, request.args.get("rev", type=int))
    except wiki_export.ExportError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("wiki.article", article_id=art.id, slug=art.slug))
    if fmt == "md":
        data = wiki_export.markdown_document(art, rev, adom_names=_adom_names(),
                                             source_url=_source_url(art))
    else:
        data = wiki_export.pdf_document(art, rev, adom_names=_adom_names(),
                                        exported_by=current_user.username,
                                        source_url=_source_url(art))
    log_action("wiki.export", target=art.slug,
               extra={"article_id": art.id, "version": rev.number, "format": fmt})
    return _download(data, wiki_export.filename(art, rev, fmt), fmt)


@bp.route("/export.zip")
@login_required
@require_permission("wiki.view")
def export_zip():
    """The list as filtered on the page (same arguments), one Markdown or PDF
    file per released article."""
    fmt = request.args.get("format", "md")
    if fmt not in ("md", "pdf"):
        abort(400)
    q, _f = _filtered(request.args)
    released = q.filter(WikiArticle.revision > 0)
    total = released.order_by(None).count()
    arts = (released.order_by(WikiArticle.title, WikiArticle.id)
            .limit(wiki_export.MAX_ZIP).all())
    data = wiki_export.zip_document(arts, fmt, adom_names=_adom_names(),
                                    exported_by=current_user.username,
                                    url_for_article=_source_url, total=total)
    log_action("wiki.export", target="list",
               extra={"format": "zip-" + fmt, "articles": [a.id for a in arts], "total": total,
                      "filters": request.args.to_dict(flat=False)})
    return _download(data, "satom-wiki-%s.zip" % fmt, "zip")


# ── Confluence ───────────────────────────────────────────────────────────────
#
# The connections are Settings › Integrations › Confluence (views/
# integrations.py). Here: the Confluence button on each article (list and
# article page) opens wiki/_confluence_modal.html, which reads the article's
# state and browses the chosen connection's spaces and pages through the
# JSON feeds below. Every feed asks can_publish first: browsing a space is
# part of publishing, not something any reader may do.

def _confluence_ready() -> dict:
    """Whether the Confluence button may appear at all (an enabled
    connection exists) and who may press it on which article."""
    return {"cf_ready": bool(wiki_confluence.targets(enabled_only=True)),
            "may_publish": lambda a: wiki_confluence.can_publish(current_user, a)}


def _publishable_or_404(article_id: int) -> WikiArticle:
    art = _article_or_404(article_id)
    if not wiki_confluence.can_publish(current_user, art):
        abort(403)
    return art


def _connection_or_404(raw) -> WikiConfluenceTarget:
    t = db.session.get(WikiConfluenceTarget, int(raw) if str(raw or "").isdigit() else 0)
    if t is None or not t.enabled:
        abort(404)
    return t


def _feed_error(exc) -> tuple:
    return jsonify({"ok": False, "error": str(exc)}), 200


@bp.route("/a/<int:article_id>/confluence/state")
@login_required
@require_permission("wiki.view")
def confluence_state(article_id):
    """What the dialog needs before anything is asked of Confluence."""
    art = _publishable_or_404(article_id)
    try:
        findings = wiki_confluence.scan(art)
    except wiki_export.ExportError:
        findings = []
    return jsonify({
        "ok": True, "title": art.title, "revision": art.revision,
        "narrow": wiki_confluence.is_narrow(art),
        "findings": [{"kind": f["kind"], "line": f["line"]} for f in findings],
        "may_override": wiki_access.is_moderator(current_user),
        "connections": [{"id": t.id, "name": t.name}
                        for t in wiki_confluence.targets(enabled_only=True)],
        "links": [{"id": l.id, "connection": l.target_id, "connection_name": l.target.name,
                   "space": l.space_key, "page_id": l.page_id, "page_url": l.page_url,
                   "revision": l.published_revision,
                   "current": l.published_revision == art.revision,
                   "at": l.published_at.strftime("%Y-%m-%d %H:%M") if l.published_at else "",
                   "by": l.published_by,
                   "forget": url_for("wiki.confluence_forget", article_id=art.id,
                                     link_id=l.id)}
                  for l in wiki_confluence.links(art)],
    })


@bp.route("/a/<int:article_id>/confluence/spaces")
@login_required
@require_permission("wiki.view")
def confluence_spaces(article_id):
    _publishable_or_404(article_id)
    t = _connection_or_404(request.args.get("connection"))
    try:
        rows = wiki_confluence.spaces(t)
    except wiki_confluence.ConfluenceError as exc:
        return _feed_error(exc)
    return jsonify({"ok": True, "spaces": rows,
                    "truncated": len(rows) >= wiki_confluence.MAX_SPACES})


@bp.route("/a/<int:article_id>/confluence/pages")
@login_required
@require_permission("wiki.view")
def confluence_pages(article_id):
    """One level of the space's tree (``parent`` = '' for the top level),
    or the pages whose title matches ``q``."""
    _publishable_or_404(article_id)
    t = _connection_or_404(request.args.get("connection"))
    args = request.args
    try:
        if (args.get("q") or "").strip():
            rows = wiki_confluence.search_pages(t, args.get("space"), args.get("q"))
            return jsonify({"ok": True, "search": True, "pages": rows})
        rows = wiki_confluence.pages(t, args.get("space"), args.get("parent", ""))
    except wiki_confluence.ConfluenceError as exc:
        return _feed_error(exc)
    return jsonify({"ok": True, "search": False, "pages": rows})


def _back_from_dialog(art) -> str:
    nxt = request.form.get("next") or ""
    if nxt.startswith("/wiki/") and not nxt.startswith("//"):
        return nxt
    return url_for("wiki.article", article_id=art.id, slug=art.slug)


@bp.route("/a/<int:article_id>/confluence", methods=["POST"])
@login_required
@require_permission("wiki.view")
def confluence_publish(article_id):
    art = _publishable_or_404(article_id)
    t = _connection_or_404(request.form.get("connection") or request.form.get("target_id"))
    back = _back_from_dialog(art)
    override = request.form.get("override_scan") == "1"
    space_key = request.form.get("space", "")
    parent = request.form.get("parent", "")
    try:
        link, created = wiki_confluence.publish(
            t, art, current_user, space_key=space_key, parent_page_id=parent,
            acknowledged=request.form.get("acknowledge") == "1",
            override_scan=override, source_url=_source_url(art))
    except wiki_confluence.ConfluenceError as exc:
        db.session.rollback()
        log_action("wiki.confluence.refused", target=art.slug,
                   extra={"article_id": art.id, "connection": t.name,
                          "space": str(space_key)[:64], "reason": str(exc)[:300],
                          "findings": exc.findings})
        flash(str(exc), "danger")
        return redirect(back)
    log_action("wiki.confluence.publish", target=art.slug,
               extra={"article_id": art.id, "connection": t.name, "space": link.space_key,
                      "parent_page_id": link.parent_page_id, "page_id": link.page_id,
                      "version": link.published_revision, "created": created,
                      "scan_overridden": override and bool(wiki_confluence.scan(art))})
    flash(("“%s” published to the %s space as a new page." if created
           else "“%s” updated in the %s space.") % (art.title, link.space_key), "success")
    return redirect(back)


@bp.route("/a/<int:article_id>/confluence/<int:link_id>/forget", methods=["POST"])
@login_required
@require_permission("wiki.view")
def confluence_forget(article_id, link_id):
    """SATOM stops updating that page; the page itself stays in Confluence."""
    art = _article_or_404(article_id)
    if not wiki_access.can_manage(current_user, art):
        abort(403)
    link = db.session.get(WikiConfluenceLink, link_id)
    if link is None or link.article_id != art.id:
        abort(404)
    url = link.page_url
    db.session.delete(link)
    db.session.commit()
    log_action("wiki.confluence.forget", target=art.slug,
               extra={"article_id": art.id, "page_url": url})
    flash("SATOM no longer updates that page. It is still in Confluence.", "success")
    return redirect(_back_from_dialog(art))


@bp.route("/confluence")
@bp.route("/confluence/<int:target_id>")
@login_required
@require_permission("wiki.view")
def confluence_targets(target_id=None):
    """The connections moved to Settings › Integrations › Confluence."""
    return redirect(url_for("integrations.index", confluence=target_id) + "#confluence"
                    if target_id else url_for("integrations.index") + "#confluence")
