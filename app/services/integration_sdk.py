"""``satom_sdk`` — the tiny surface a user hook is allowed to see.

The author writes ``data/integrations/<slug>/hook.py`` and starts it with::

    from satom_sdk import ctx

    ticket = ctx.http.post(
        "https://crm.example.com/api/crq",
        headers={"Authorization": "Bearer " + ctx.secret("CRM_TOKEN")},
        json={"summary": ctx.payload["title"], "risk": ctx.payload["risk"]},
    ).json()
    ctx.log("opened CRQ %s" % ticket["id"])
    ctx.result(True, {"crq_id": ticket["id"]})

WHY IT IS CALLED ``satom_sdk`` AND NOT ``app.services.integration_sdk``
    In the repo this file lives at ``app/services/integration_sdk.py`` (so it is
    version-controlled, linted and covered like the rest of the product). At run
    time ``hook_runner`` COPIES it into the hook's private working directory as
    ``satom_sdk.py``. That is the whole import path the child gets: its own temp
    dir plus the stdlib and the venv's site-packages. ``/opt/satom`` is never on
    ``sys.path``, so ``import app.models`` fails — a hook cannot reach the ORM,
    the Fernet key, the appliance credentials or the session table. Shipping the
    SDK by copy rather than by putting the app dir on the path is the difference
    between a sandbox and a suggestion.

DESIGN NOTES
    * ``ctx.http`` FORCES a timeout on every single request. A hook that hangs
      on somebody else's CRM would otherwise hold a runner slot open until the
      whole-process timeout fires — same outage, later, with less information.
      An explicit ``timeout=`` is honoured but clamped to what is left of the
      hook's own budget: you cannot ask for 300 s inside a 30 s hook.
    * ``ctx.result`` writes ONE JSON line to a dedicated file descriptor the
      runner opened and inherited to the child. It is deliberately NOT parsed
      out of stdout: a hook that prints ``{"ok": true}`` — or pipes a CRM
      response that happens to contain it — must not be able to fake its own
      outcome. stdout is a log, and only a log.
    * stdlib only. ``urllib`` instead of ``requests`` so the SDK works in any
      venv and so no library's own "no timeout by default" becomes our problem.

This module is import-safe with no environment at all (that is how the repo's
import test exercises it): you get an inert context whose ``result()`` is a
no-op and whose ``payload`` is empty.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

__all__ = ["ctx", "Context", "HookHttpError", "HttpResponse"]

# The ``requests``-style API keeps a keyword called ``json``, which shadows the
# module inside those methods. Alias it once so the shadowing stays harmless.
_jsonlib = json

# Bytes of a response body ``ctx.http`` will read. A hostile or broken endpoint
# that streams forever must not fill the node's disk through a status file.
MAX_BODY_BYTES = 2 * 1024 * 1024
DEFAULT_HTTP_TIMEOUT = 10.0
MAX_HTTP_TIMEOUT = 120.0
ALLOWED_SCHEMES = ("http", "https")


class HookHttpError(RuntimeError):
    """Transport-level failure (DNS, connect, TLS, timeout). An HTTP *status*
    is not an error — it comes back on the response, like ``requests``."""


class HttpResponse:
    __slots__ = ("status", "url", "headers", "content")

    def __init__(self, status: int, url: str, headers: dict, content: bytes):
        self.status = int(status)
        self.url = url
        self.headers = headers
        self.content = content

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 400

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self) -> Any:
        return json.loads(self.text or "null")

    def __repr__(self) -> str:
        return "<HttpResponse %d %s>" % (self.status, self.url)


class HttpClient:
    """A deliberately small HTTP client where the timeout is not optional."""

    def __init__(self, remaining) -> None:
        self._remaining = remaining  # callable -> seconds left in the budget

    def _effective_timeout(self, timeout: Any) -> float:
        try:
            want = float(timeout) if timeout is not None else DEFAULT_HTTP_TIMEOUT
        except (TypeError, ValueError):
            want = DEFAULT_HTTP_TIMEOUT
        want = max(0.1, min(MAX_HTTP_TIMEOUT, want))
        try:
            left = float(self._remaining())
        except Exception:  # noqa: BLE001 — no budget known → keep the ask
            return want
        if left <= 0:
            return 0.1
        # Never wait past the hook's own deadline: a clean "timed out talking to
        # the CRM" beats being SIGKILLed mid-request with no message at all.
        return max(0.1, min(want, left))

    def request(self, method: str, url: str, *, headers: dict | None = None,
                json: Any = None, data: Any = None,
                timeout: float | None = None) -> HttpResponse:
        parsed = urllib.parse.urlparse(url or "")
        if parsed.scheme not in ALLOWED_SCHEMES:
            # file:// and ftp:// are urllib features, not features of this SDK:
            # ctx.http is for reaching YOUR systems, not for reading this node.
            raise HookHttpError("only http/https URLs are allowed (got %r)" % url)

        body: bytes | None = None
        hdrs = {"User-Agent": "SATOM-integration-hook/1",
                "Accept": "application/json, */*"}
        for k, v in (headers or {}).items():
            hdrs[str(k)] = str(v)
        if json is not None:
            body = _jsonlib.dumps(json).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        elif data is not None:
            if isinstance(data, (dict, list)):
                body = urllib.parse.urlencode(data, doseq=True).encode("utf-8")
                hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, bytes):
                body = data
            else:
                body = str(data).encode("utf-8")

        req = urllib.request.Request(url, data=body, headers=hdrs,
                                     method=(method or "GET").upper())
        eff = self._effective_timeout(timeout)
        try:
            with urllib.request.urlopen(req, timeout=eff) as resp:
                content = resp.read(MAX_BODY_BYTES)
                return HttpResponse(getattr(resp, "status", 0) or resp.getcode(),
                                    resp.geturl(), dict(resp.headers or {}), content)
        except urllib.error.HTTPError as exc:  # 4xx/5xx: a result, not a crash
            try:
                content = exc.read(MAX_BODY_BYTES)
            except Exception:  # noqa: BLE001
                content = b""
            return HttpResponse(exc.code, url, dict(exc.headers or {}), content)
        except Exception as exc:  # noqa: BLE001 — URLError, socket.timeout, ssl…
            raise HookHttpError("%s %s failed after %.1fs: %s"
                                % (req.method, url, eff, exc)) from exc

    def get(self, url: str, **kw: Any) -> HttpResponse:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw: Any) -> HttpResponse:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw: Any) -> HttpResponse:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw: Any) -> HttpResponse:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw: Any) -> HttpResponse:
        return self.request("DELETE", url, **kw)


class Context:
    """What a hook gets. Everything else is deliberately not reachable."""

    def __init__(self, *, event: str = "", payload: dict | None = None,
                 slug: str = "", request_id: str = "",
                 secrets: list | None = None, timeout: float = 0.0,
                 result_fd: int | None = None, result_path: str | None = None,
                 started: float | None = None) -> None:
        self.event = event
        self.payload = payload if isinstance(payload, dict) else {}
        self.slug = slug
        self.request_id = request_id
        self.timeout = float(timeout or 0)
        self._declared = list(secrets or [])
        self._result_fd = result_fd
        self._result_path = result_path
        self._started = started if started is not None else time.monotonic()
        self._done = False
        self.http = HttpClient(self.remaining)

    # -- budget -------------------------------------------------------------
    def remaining(self) -> float:
        """Seconds left before the runner kills this hook's process group."""
        if not self.timeout:
            return MAX_HTTP_TIMEOUT
        return max(0.0, self.timeout - (time.monotonic() - self._started))

    # -- secrets ------------------------------------------------------------
    def secret(self, name: str) -> str:
        """One DECLARED credential, by name.

        The runner injected exactly the names listed in ``meta.json`` and
        nothing else, so an undeclared name is not merely unreadable here — it
        was never in this process's environment to begin with. The explicit
        error exists so the author sees "declare it in meta.json" instead of an
        empty string that silently sends an unauthenticated request.
        """
        key = str(name or "").strip().upper()
        val = os.environ.get("SATOM_SECRET_" + key)
        if val is None:
            raise KeyError(
                "secret %r was not declared by this hook — add it to the "
                "hook's 'secrets' list (declared: %s)"
                % (key, ", ".join(self._declared) or "none"))
        return val

    @property
    def secrets(self) -> list:
        """The names this hook declared (values are not enumerable)."""
        return list(self._declared)

    # -- logging ------------------------------------------------------------
    def log(self, msg: Any) -> None:
        """Append a line to the captured, truncated, redacted hook log.

        Goes to stdout (stderr is merged into it by the runner) so ordering with
        plain ``print()`` and with a traceback is preserved in the status file
        the UI renders.
        """
        try:
            line = "[hook %s] %s" % (self.slug or "?", msg)
        except Exception:  # noqa: BLE001
            line = "[hook] <unprintable log message>"
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

    # -- the one and only result channel ------------------------------------
    def result(self, ok: bool, data: Any = None) -> None:
        """Report the outcome. First call wins; a second call raises.

        This does NOT go through stdout. It is one JSON line on a descriptor the
        runner owns, which is why a hook that prints JSON-shaped text cannot
        forge it.

        Not calling ``result()`` at all is legal: exit 0 means ``ok`` with
        ``data = null``, a non-zero exit means ``failed``.
        """
        if self._done:
            raise RuntimeError("ctx.result() was already called for this run")
        payload = json.dumps({"ok": bool(ok), "data": data},
                             default=str).encode("utf-8") + b"\n"
        self._done = True
        if self._result_fd is not None:
            try:
                os.write(self._result_fd, payload)
                return
            except OSError:
                pass
        if self._result_path:
            try:
                with open(self._result_path, "ab") as fh:
                    fh.write(payload)
            except OSError:
                pass
        # No channel (module imported outside a run) → deliberately a no-op.


def _build_context() -> Context:
    """Assemble ``ctx`` from the environment the runner handed us. Never raises:
    importing the SDK outside a run yields an inert context."""
    ctx_path = os.environ.get("SATOM_HOOK_CTX", "")
    meta: dict = {}
    if ctx_path:
        try:
            with open(ctx_path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                meta = loaded
        except Exception:  # noqa: BLE001
            meta = {}
    fd = None
    raw_fd = os.environ.get("SATOM_RESULT_FD", "")
    if raw_fd.isdigit():
        fd = int(raw_fd)
    return Context(
        event=str(meta.get("event") or os.environ.get("SATOM_HOOK_EVENT", "")),
        payload=meta.get("payload") if isinstance(meta.get("payload"), dict) else {},
        slug=str(meta.get("slug") or os.environ.get("SATOM_HOOK_SLUG", "")),
        request_id=str(meta.get("request_id")
                       or os.environ.get("SATOM_HOOK_REQUEST_ID", "")),
        secrets=meta.get("secrets") or [],
        timeout=meta.get("timeout") or os.environ.get("SATOM_HOOK_TIMEOUT") or 0,
        result_fd=fd,
        result_path=os.environ.get("SATOM_RESULT_FILE") or None,
    )


ctx = _build_context()
