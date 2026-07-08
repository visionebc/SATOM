"""Versioned, token-authenticated third-party API (``/api/v1``).

Separate from the internal ``app.api`` blueprint (which is session-authed and
serves the frontend). This one is CSRF-exempt (tokens carry no CSRF) and every
view authenticates via :func:`app.api_v1.auth.token_required`.
"""
from flask import Blueprint

from ..extensions import csrf
# Importing the model registers ``api_tokens`` on the metadata so the app
# factory's ``db.create_all()`` provisions the table (Postgres, no migration).
from .. import models_api_token  # noqa: F401

bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")

# Token auth replaces CSRF for this surface.
csrf.exempt(bp)

from . import routes  # noqa: E402,F401
