"""WSGI entry point — used by gunicorn and direct `python wsgi.py` runs."""
from __future__ import annotations

import os

# Load the .env that sits NEXT TO THIS FILE — never "whatever the current
# directory happens to be". A bare load_dotenv() searches upward from the CWD,
# so `runuser -u satom -- python -m app.cli_sentinel ...` (runuser moves to the
# user's home first) loads nothing and the app falls back to SQLite: an empty
# database that answers every query successfully. For the response runner that
# is a tick which finds no TTL to expire and reports a clean pass while a real
# block stays on a firewall.
#
# systemd's EnvironmentFile still wins — load_dotenv does not override
# variables already present in the environment.
try:
    from pathlib import Path as _Path

    from dotenv import load_dotenv  # type: ignore[import]
    load_dotenv(_Path(__file__).resolve().with_name(".env"))
except ImportError:
    pass

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        debug=False,
    )
