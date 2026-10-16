# app/views/wiki.py
"""Operations › Wiki — articles users write for each other.

Every route that names an article asks services/wiki_access.py first and
answers 404 for an article the user may not read: a 403 would confirm that
an article with that id exists. Lists, counters and the tag autocomplete go
through :func:`wiki_access.visible_query`, so a restricted article never
lends its title, its tags or its count to anything a reader sees.

Writes: ``wiki.write`` to create, and to edit every article one can READ
(services/wiki_access.can_edit); the audience, archiving and deleting stay
with the author and ``wiki.moderate`` (can_manage), as do the topic tree
and the Wiki groups. Editing autosaves a shared draft; publishing makes a
new version. Creating, publishing, discarding, archiving and deleting are
audited (an autosave is not).
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
            "groups": WikiGroup.query.order_by(WikiGroup.name).all(),
            "may_set_audience": article is None or wiki_access.can_manage(current_user, article),
            "draft_rev": article.draft_rev if article is not None else 0,
            "has_draft": bool(article is not None and wiki.has_draft(article)),
            "default_adom": _current_adom(),
            "default_topic": None}


# ── reading ──────────────────────────────────────────────────────────────────

@bp.route("/")
@login_required
@require_permission("wiki.view")
def index():
    """The article list: filters are applied in SQL, after visibility."""
    q = wiki_access.visible_query(current_user)
    args = request.args
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

    page = max(1, args.get("page", 1, type=int))
    pagination = (q.order_by(WikiArticle.updated_at.desc(), WikiArticle.id.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    return render_template(
        "wiki/index.html", pagination=pagination, articles=pagination.items,
        topic=topic, tag=tag, text=text, picked=picked,
        adom_choices=[("global", "Global")] + list(_adom_names().items()),
        status=status, mine=bool(args.get("mine")), archived=bool(args.get("archived")),
        adom_names=_adom_names(), current_adom=_current_adom(),
        excerpt=wmd.plain_excerpt, page_url=_page_url, has_draft=wiki.has_draft,
        **_nav_context(topic_id=topic.id if topic else None, tag=tag))


def _page_url(number: int) -> str:
    args = request.args.to_dict()
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
