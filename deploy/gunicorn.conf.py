"""gunicorn settings of the SATOM web console and API (satom.service).

Until 4.4.0 the console ran ``--workers 4`` SYNC workers: four requests at a
time for the whole node, console and API together. A request waiting on a
slow appliance, a streaming advisor reply or a long report held one of the
four for its whole length; the fifth caller -- an operator opening a page --
queued behind them, and anything past nginx's 120 s became a 504 while its
worker kept going for up to 600 s.

``gthread`` serves each worker's requests from a thread pool: the work is
I/O-bound (Postgres, devices, Redis), so threads wait concurrently instead of
in line. 4 workers x 8 threads = 32 requests in flight. ``timeout`` is the
worker heartbeat under gthread, not a per-request limit; it is still kept
above the advisor's provider timeout (advisor_providers.DEFAULT_TIMEOUT,
tests/test_advisor_stream.py) so the ordering the 600 s protected holds.

nginx keeps the API from taking all 32 (``limit_conn satom_api_total`` in the
vhost, [SATOM-API-LIMITS]): the console always has the rest.

Every value can be set in /opt/satom/.env (EnvironmentFile of the unit).
"""
import os


def _int(name, default):
    try:
        return max(1, int(os.environ.get(name) or default))
    except ValueError:
        return default


bind = os.environ.get("SATOM_WEB_BIND", "127.0.0.1:8000")
worker_class = "gthread"
workers = _int("SATOM_WEB_WORKERS", 4)
threads = _int("SATOM_WEB_THREADS", 8)
timeout = _int("SATOM_WEB_TIMEOUT", 240)
graceful_timeout = 30
keepalive = 5
backlog = 2048
# Recycle a worker now and then: a slow leak in one long-lived process must
# not grow until the OOM killer picks the node's most important process.
max_requests = 4000
max_requests_jitter = 400
accesslog = os.environ.get("SATOM_WEB_ACCESS_LOG", "/var/log/satom/access.log")
errorlog = os.environ.get("SATOM_WEB_ERROR_LOG", "/var/log/satom/error.log")
