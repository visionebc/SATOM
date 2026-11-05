"""Sign-in is SATOM's. Inside SATOM, every request reaching this app was
already authenticated by SATOM (login, 2FA, profile, ADOM gate); these routes
only send the browser to SATOM's own pages."""
from flask import Blueprint, redirect, request

bp = Blueprint("auth", __name__)


def _satom(path: str) -> str:
    return request.environ.get("satom.root", "") + path


@bp.route("/login", methods=["GET", "POST"])
def login():
    return redirect(_satom("/auth/login?next=%s" % (request.script_root + "/")))


@bp.route("/logout", methods=["POST"])
def logout():
    return redirect(_satom("/auth/logout"))


@bp.route("/account", methods=["GET", "POST"])
def account():
    return redirect(_satom("/auth/profile"))
