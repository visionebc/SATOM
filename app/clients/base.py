import httpx
from typing import Optional


class BaseClient:
    def __init__(self, host: str, port: int = 443, verify_ssl: bool = True, timeout: float = 30.0):
        self.base_url = f"https://{host}:{port}"
        self._verify = verify_ssl
        self._timeout = timeout

    def _request(self, method: str, path: str, **kwargs):
        url = self.base_url.rstrip('/') + '/' + path.lstrip('/')
        with httpx.Client(verify=self._verify, timeout=self._timeout) as client:
            resp = client.request(method, url, **kwargs)
        return resp
