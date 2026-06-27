"""WSGI entry point — used by gunicorn and direct `python wsgi.py` runs."""
from __future__ import annotations

import os

# Load .env if python-dotenv is available (optional dev convenience)
try:
    from dotenv import load_dotenv  # type: ignore[import]
    load_dotenv()
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
