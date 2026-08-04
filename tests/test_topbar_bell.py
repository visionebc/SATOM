"""The topbar bell's unread bubble must stay pinned to the bell glyph.

Nothing *fails* when this regresses. The page renders, the count is right, the
dropdown opens -- only the geometry is wrong, so no test and no health check
notices. It was reported by a human looking at the screen.

The defect: Bootstrap's ``.top-0 .start-100 .translate-middle`` anchor an
absolutely positioned child to the button's *padded hit area*. The topbar
button is 34x28 while the bell glyph is 14x16, so the bubble landed against
the topbar's top edge -- ~14px clear of the bell, and 1px inside the user
menu. Measured, not guessed: badge y 2.36..17.64 vs glyph y 16..32.

Two halves hold the fix, and each is guarded here:

  1. ``.fw-topbar-btn`` declares its own box. The search button is a direct
     flex child of ``.fw-topbar-actions`` (so it is blockified), while the
     bell sits inside ``.dropdown`` and reverts to ``display:inline`` -- two
     buttons in one toolbar with different hit areas.
  2. The bubble is positioned by ``.fw-notif-badge`` in the stylesheet, which
     the theme controls, instead of by Bootstrap utilities it does not.
"""
import io
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE_HTML = os.path.join(ROOT, "app", "templates", "base.html")
CSS = os.path.join(ROOT, "app", "static", "css", "fortiweb.css")

BADGE_CLASS = "fw-notif-badge"


def _read(path):
    return io.open(path, encoding="utf-8").read()


def _bell_block(src):
    """The markup between the bell anchor and its closing tag."""
    start = src.index('id="fwNotifBell"')
    end = src.index("</a>", start)
    return src[start:end]


def _css_rule(src, selector):
    """Body of the first `selector { ... }` rule, or None."""
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", src)
    return m.group(1) if m else None


# --------------------------------------------------------------- the markup

def test_bubble_is_not_anchored_to_the_padded_hit_area():
    block = _bell_block(_read(BASE_HTML))
    for util in ("translate-middle", "start-100", "top-0"):
        assert util not in block, (
            "%s anchors the bubble to the button's padding box, not to the "
            "bell glyph -- that is the bug this guard exists for" % util
        )


def test_bubble_uses_the_dedicated_class():
    assert BADGE_CLASS in _bell_block(_read(BASE_HTML))


# ---------------------------------------------------------------- the poller

def test_the_poller_queries_the_class_it_creates():
    """A selector/className mismatch appends a SECOND bubble every poll.

    ``updateBell`` looks the bubble up before deciding whether to create one.
    If the lookup and the creation disagree, the lookup never finds the
    server-rendered bubble and the page grows a new one every 30 seconds.
    """
    src = _read(BASE_HTML)
    created = re.search(r"badge\.className\s*=\s*'([^']+)'", src)
    queried = re.search(r"bell\.querySelector\('\.([\w-]+)'\)", src)
    assert created and queried, "updateBell no longer creates/queries a bubble"
    assert created.group(1).split() == [queried.group(1)], (
        "the poller creates .%s but looks up .%s -- it will append a duplicate "
        "bubble on every poll" % (created.group(1), queried.group(1))
    )


def test_the_poller_does_not_inline_the_bubble_geometry():
    """Geometry belongs to the stylesheet, which the theme engine owns."""
    src = _read(BASE_HTML)
    tail = src[src.index("function updateBell"):]
    tail = tail[: tail.index("function poll")]
    assert "badge.style" not in tail


# ------------------------------------------------------------- the stylesheet

def test_the_stylesheet_positions_the_bubble():
    body = _css_rule(_read(CSS), ".%s" % BADGE_CLASS)
    assert body is not None, ".%s is not defined" % BADGE_CLASS
    assert "position: absolute" in body
    # Pinned by both axes, or it falls back to its static position.
    assert "top:" in body and "right:" in body


@pytest.mark.parametrize("prop", ["display", "align-items", "position"])
def test_the_topbar_button_declares_its_own_box(prop):
    """Without this the bell reverts to display:inline inside .dropdown."""
    body = _css_rule(_read(CSS), ".fw-topbar-btn")
    assert body is not None
    assert prop + ":" in body, (
        ".fw-topbar-btn must declare %s -- nested in .dropdown it is not a "
        "flex item and would fall back to display:inline, giving a hit area "
        "that neither matches the glyph nor the sibling search button" % prop
    )


def test_the_bubble_is_defined_once():
    """One definition, two consumers (template + poller). Two would drift."""
    assert _read(CSS).count(".%s {" % BADGE_CLASS) == 1


# ------------------------------------------------------------------ rendered

def test_rendered_page_carries_the_dedicated_class(app, client):
    """End-to-end: an unread notification renders the themed bubble."""
    from app import db
    from app.models import User
    from app.models_notifications import Notification

    with app.app_context():
        uid = User.query.order_by(User.id).first().id
        db.session.add(Notification(user_id=uid, title="guard fixture"))
        db.session.commit()

    with client.session_transaction() as sess:
        sess["_user_id"] = str(uid)
        sess["_fresh"] = True

    html = client.get("/", follow_redirects=True).get_data(as_text=True)
    assert 'class="%s"' % BADGE_CLASS in html
    assert "translate-middle badge" not in html
