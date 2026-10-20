"""Per-blueprint request body limits.

The application-wide ``MAX_CONTENT_LENGTH`` is sized for the largest upload
SATOM takes (firmware images, backup bundles). A blueprint whose requests are
small forms refuses anything bigger BEFORE a view parses it, so ``get_json``
never builds a few hundred megabytes of objects in a web worker.
"""
from __future__ import annotations

from flask import jsonify, request


def refuse_larger_than(limit: int):
    """A 413 response when the request body is larger than *limit*, else None.

    A declared ``Content-Length`` is checked at once; a body without one
    (chunked) is bounded by setting the request's own limit, which Werkzeug
    enforces while reading."""
    n = request.content_length
    if n is not None and n > limit:
        return jsonify({"ok": False, "error": "the request is larger than %d KiB"
                        % (limit // 1024)}), 413
    try:
        request.max_content_length = limit
    except AttributeError:  # Flask < 3.1: the app-wide limit applies
        pass
    return None
