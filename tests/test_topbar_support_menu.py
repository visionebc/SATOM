"""The support controls live in the TOOLS menu, not in the user menu.

Moved 2026-09-14 at the user's request: "Report a problem", "Release Notes"
and "Bug Reports" used to hang off the username dropdown; they now sit in the
``bi-tools`` dropdown. The move must NOT relax the per-profile gates — the
inbox link stays behind ``user_manage`` and Release Notes stays scoped to the
products that ship the modal.

These guards assert on the *targets* (``#bugReportModal``, ``#releaseNotesModal``,
``/reports``), never on the labels: the labels are translatable and would make
the guard pass or fail by locale instead of by placement.
"""
import pytest


@pytest.fixture()
def app():
    from app import create_app
    from app.models import db, User

    class _Cfg:
        TESTING = True
        SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        WTF_CSRF_ENABLED = False
        RATELIMIT_ENABLED = False
        SECRET_KEY = "test"

    app = create_app(_Cfg)
    with app.app_context():
        db.create_all()
        for name, role in [("alice", "readonly"), ("adm", "admin")]:
            u = User(username=name, role=role)
            u.set_password("pw")
            db.session.add(u)
        db.session.commit()
        yield app
        db.session.remove()
        db.drop_all()


def _login(client, username, product="fortiweb"):
    client.post("/auth/login",
                data={"username": username, "password": "pw"},
                follow_redirects=True)
    return client.post("/product/select",
                       data={"product": product},
                       follow_redirects=True)


def _slice(html: str, start_marker: str) -> str:
    """The rendered markup of one dropdown: from its anchor to its </ul>.

    Slicing matters — "Bug Reports" and /reports also appear in the sidebar,
    so a whole-page assertion could never tell the two menus apart.
    """
    i = html.index(start_marker)
    j = html.index("</ul>", i)
    return html[i:j]


def _tools_menu(html: str) -> str:
    return _slice(html, "bi bi-tools")


def _user_menu(html: str) -> str:
    return _slice(html, "dropdown fw-user-menu")


def test_admin_finds_all_three_in_the_tools_menu(app):
    c = app.test_client()
    html = _login(c, "adm").get_data(as_text=True)
    tools = _tools_menu(html)
    assert 'data-bs-target="#bugReportModal"' in tools
    assert 'data-bs-target="#releaseNotesModal"' in tools
    assert 'href="/reports' in tools


def test_the_user_menu_no_longer_carries_them(app):
    c = app.test_client()
    html = _login(c, "adm").get_data(as_text=True)
    menu = _user_menu(html)
    assert "#bugReportModal" not in menu
    assert "#releaseNotesModal" not in menu
    assert "/reports" not in menu
    # …and it keeps what it is for.
    assert "/auth/profile" in menu
    assert "/auth/logout" in menu


def test_inbox_link_stays_behind_user_manage(app):
    """A read-only profile may REPORT a problem but must not see the inbox."""
    c = app.test_client()
    html = _login(c, "alice").get_data(as_text=True)
    tools = _tools_menu(html)
    assert 'data-bs-target="#bugReportModal"' in tools
    assert 'href="/reports' not in tools


def test_release_notes_stays_product_scoped(app):
    """'global' does not include the modal, so it must not offer the item."""
    c = app.test_client()
    html = _login(c, "adm", product="global").get_data(as_text=True)
    tools = _tools_menu(html)
    assert 'data-bs-target="#releaseNotesModal"' not in tools
    assert 'id="releaseNotesModal"' not in html  # the modal itself is absent
    # The ungated one still travels with the menu.
    assert 'data-bs-target="#bugReportModal"' in tools


def test_open_report_badge_moved_with_the_link(app):
    """The count badge belongs to the inbox link — wherever that link lives."""
    from app.models import User
    from app.services import bug_reports as svc
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        svc.create_report(alice, "t", "b", None, None)
    c = app.test_client()
    html = _login(c, "adm").get_data(as_text=True)
    assert 'badge rounded-pill bg-danger ms-1">1</span>' in _tools_menu(html)
