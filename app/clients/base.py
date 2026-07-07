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

    def _request(self, method: str, path: str, **kwargs):
        url = self.base_url.rstrip('/') + '/' + path.lstrip('/')
        with self._sem:
            with httpx.Client(verify=self._verify, timeout=self._timeout) as client:
                resp = client.request(method, url, **kwargs)
        return resp
