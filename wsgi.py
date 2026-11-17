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
#
# `python -m app.<module>` that imports this file (app.cli_sentinel) has
# ALREADY imported app.config, which filled what was missing (a random
# FERNET_KEY / SECRET_KEY) and froze the config classes on the SQLite fallback.
# load_dotenv() never overrides, so those invented values would shadow the
# file. Drop them first and re-evaluate the config after loading.
try:
    import importlib as _importlib
    import sys as _sys
    from pathlib import Path as _Path

    from dotenv import load_dotenv  # type: ignore[import]
    _cfg = _sys.modules.get("app.config")
    for _var in tuple(getattr(_cfg, "INVENTED_ENV", ())):
        os.environ.pop(_var, None)
    load_dotenv(_Path(__file__).resolve().with_name(".env"))
    if _cfg is not None:
        _cfg.INVENTED_ENV.clear()
        _importlib.reload(_cfg)
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
