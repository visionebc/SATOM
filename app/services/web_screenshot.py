"""Screenshot of a web page for Monitoring › Service checks.

Operator request 2026-11-17: "monitoring of a web page with its screenshot" —
the base is the Power Panel's Web Monitor (Playwright + /usr/bin/chromium,
1366×768, full page). SATOM takes the same picture WITHOUT a new Python
dependency: the Chromium binary's own headless mode
(``--headless=new --screenshot``), wrapped in bubblewrap.

Why the sandbox: the page is whatever the operator typed, rendered from the
management network. bwrap gives the browser a read-only root, private /tmp and
/run, no access to SATOM's data or secrets, and its own process session that
dies with the caller; only the output directory is writable. Chromium's own
namespace sandbox cannot start inside an unprivileged LXC, so it runs with
``--no-sandbox`` INSIDE bwrap — the boundary is bwrap's.

What it does not do: authorise the URL. The caller does that (net_guard) before
calling :func:`capture`; sub-resources the page pulls are the page's business,
exactly as in an operator's own browser. The cloud metadata name is refused at
the resolver all the same (``--host-resolver-rules``).

No browser on the node → :func:`capture` says so and the check still runs; the
page shows how to add one (Debian/Ubuntu ``apt install chromium``).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time

#: Same viewport as the Power Panel's Web Monitor.
WIDTH, HEIGHT = 1366, 768
#: Candidates, most specific first.
BROWSERS = ("chromium", "chromium-browser", "google-chrome-stable", "google-chrome",
            "chrome-headless-shell", "headless_shell")
#: Never resolvable from the screenshot browser (cloud instance metadata).
RESOLVER_RULES = ("MAP metadata.google.internal ~NOTFOUND, "
                  "MAP metadata ~NOTFOUND, MAP instance-data ~NOTFOUND")
#: Hard ceiling on one capture, whatever the check's timeout says.
MAX_SECONDS = 45
#: A PNG larger than this is not kept (a runaway page).
MAX_BYTES = 8 * 1024 * 1024
INSTALL_HINT = ("no Chromium on this node: screenshots are off. "
                "Debian/Ubuntu: apt install chromium · RHEL (EPEL): dnf install chromium · "
                "SLES/openSUSE: zypper install chromium")


def find_browser() -> str | None:
    for name in BROWSERS:
        path = shutil.which(name)
        if path:
            return path
    return None


def available() -> dict:
    """``{"ok": bool, "browser": path|None, "sandbox": bool, "hint": str}``."""
    b = find_browser()
    sb = shutil.which("bwrap") is not None
    hint = "" if (b and sb) else (INSTALL_HINT if not b else
                                  "bubblewrap (bwrap) is missing: screenshots are off")
    return {"ok": bool(b and sb), "browser": b, "sandbox": sb, "hint": hint}


def command(browser: str, url: str, out_dir: str, out_name: str, *,
            verify_tls: bool, budget_ms: int) -> list[str]:
    """The bwrap + Chromium argv (separate so the tests can pin it)."""
    argv = [
        "bwrap",
        "--unshare-all", "--share-net",          # its own namespaces, but the network
        "--die-with-parent", "--new-session",
        "--clearenv",
        "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "HOME", "/tmp/home",
        "--setenv", "LANG", "C.UTF-8",
        "--ro-bind", "/", "/",                    # read-only system: libraries, fonts, certs
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--tmpfs", "/run",
        "--tmpfs", "/var/tmp",
        "--dir", "/tmp/home",
        # The ONLY writable path that persists. Under the tmpfs /tmp: the root
        # is read-only, so bwrap cannot create the target anywhere else.
        "--bind", out_dir, "/tmp/out",
        "--chdir", "/tmp",
        browser,
        "--headless=new", "--no-sandbox", "--disable-gpu",
        "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
        "--disable-extensions", "--disable-sync", "--disable-background-networking",
        "--mute-audio", "--hide-scrollbars", "--incognito",
        "--user-data-dir=/tmp/profile",
        "--window-size=%d,%d" % (WIDTH, HEIGHT),
        "--virtual-time-budget=%d" % budget_ms,
        "--host-resolver-rules=%s" % RESOLVER_RULES,
        "--screenshot=/tmp/out/%s" % out_name,
    ]
    if not verify_tls:
        argv.append("--ignore-certificate-errors")
    argv.append(url)
    return argv


def capture(url: str, out_dir: str, *, verify_tls: bool = True,
            timeout: float = 20.0) -> dict:
    """Take the screenshot into ``out_dir``.

    Returns ``{"ok", "file", "bytes", "took_ms", "error"}`` — ``file`` is the
    name inside ``out_dir``. Never raises for a page that misbehaves.
    """
    av = available()
    if not av["ok"]:
        return {"ok": False, "file": "", "bytes": 0, "took_ms": 0, "error": av["hint"]}
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "file": "", "bytes": 0, "took_ms": 0,
                "error": "only http:// and https:// pages can be photographed"}
    os.makedirs(out_dir, exist_ok=True)
    name = "shot-%d.png" % int(time.time() * 1000)
    limit = max(5.0, min(float(timeout) + 10.0, MAX_SECONDS))
    budget_ms = int(max(2.0, min(float(timeout), 15.0)) * 1000)
    argv = command(av["browser"], url, out_dir, name, verify_tls=verify_tls,
                   budget_ms=budget_ms)
    started = time.monotonic()
    err = ""
    with tempfile.TemporaryFile() as log:
        try:
            proc = subprocess.Popen(argv, stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                                    start_new_session=True)
            try:
                rc = proc.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
                rc, err = -9, "the page did not finish rendering within %d s" % int(limit)
        except OSError as exc:
            rc, err = -1, "could not start the browser: %s" % exc
        log.seek(0)
        tail = log.read()[-600:].decode("utf-8", "replace")
    took = int((time.monotonic() - started) * 1000)
    path = os.path.join(out_dir, name)
    size = os.path.getsize(path) if os.path.exists(path) else 0
    if size and size <= MAX_BYTES:
        return {"ok": True, "file": name, "bytes": size, "took_ms": took, "error": ""}
    if size > MAX_BYTES:
        os.remove(path)
        err = "the screenshot was larger than %d MiB and was dropped" % (MAX_BYTES // 1048576)
    if not err:
        last = [ln for ln in tail.splitlines() if ln.strip()][-1:] or ["no output"]
        err = "the browser exited %s without a picture (%s)" % (rc, last[0][:200])
    return {"ok": False, "file": "", "bytes": 0, "took_ms": took, "error": err}
