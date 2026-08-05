import os
import threading

import httpx
from typing import Optional

# Cap on the TCP/TLS connect leg. A request's total budget stays `timeout`,
# but connecting to a dead/absent box must fail FAST: without this cap every
# request to an unplugged appliance burns the full budget, and a long sync
# (hundreds of requests) "flies" for hours instead of erroring in seconds.
_MAX_CONNECT_S = 10.0

# Per-appliance concurrency gate. A FortiWeb-VM's management plane tolerates
# only a handful of parallel REST calls before it slows or refuses; with many
# gunicorn threads + the scheduler sidecar all talking to the same box, the
# device (not the manager) is the bottleneck. Cap concurrent in-flight requests
# PER HOST, per process (workers multiply this, so keep it small).
_HOST_CONCURRENCY = max(1, int(os.environ.get("FORTINET_HOST_CONCURRENCY", "4")))
_host_sems: dict = {}
_host_sems_lock = threading.Lock()


def _host_semaphore(host_key: str) -> threading.BoundedSemaphore:
    with _host_sems_lock:
        sem = _host_sems.get(host_key)
        if sem is None:
            sem = _host_sems[host_key] = threading.BoundedSemaphore(_HOST_CONCURRENCY)
        return sem


class BaseClient:
    def __init__(self, host: str, port: int = 443, verify_ssl: bool = True, timeout: float = 30.0):
        self.base_url = f"https://{host}:{port}"
        self._verify = verify_ssl
        self._timeout = httpx.Timeout(timeout, connect=min(_MAX_CONNECT_S, timeout))
        self._sem = _host_semaphore(f"{host}:{port}")

    def _verify_target(self):
        """What to hand httpx as ``verify=`` for this appliance.

        ``verify_ssl=False`` stays exactly that — the operator turned checking
        off and this is not the place to overrule them. ``verify_ssl=True``
        means "validate", and until 2026-08-05 that validated against the
        PUBLIC root store only, which no privately-signed appliance can ever
        satisfy. That is why every device in this fleet ended up with
        verification disabled. It now validates against the fleet trust store:
        the public roots PLUS the CAs the operator imported
        (services/trust_store), so a company-signed device can be verified
        without disabling TLS checking for the whole fleet.

        A trust store that cannot be read falls back to the public roots —
        never to ``False``. Silently dropping verification because a query
        failed is the one outcome nobody would notice."""
        if not self._verify:
            return False
        try:
            from ..services import trust_store
            return trust_store.verify_param()
        except Exception:  # noqa: BLE001
            return True

    def _request(self, method: str, path: str, **kwargs):
        url = self.base_url.rstrip('/') + '/' + path.lstrip('/')
        verify = self._verify_target()
        with self._sem:
            with httpx.Client(verify=verify, timeout=self._timeout) as client:
                resp = client.request(method, url, **kwargs)
        return resp
