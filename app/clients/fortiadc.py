from .base import BaseClient


class FortiADCClient(BaseClient):
    def __init__(self, appliance):
        """
        appliance: Appliance model instance with attributes:
            host, port, verify_ssl, username, password (decrypted)
        """
        super().__init__(appliance.host, appliance.port, appliance.verify_ssl)
        self._username = appliance.username
        self._password = appliance.password
        self._token = None

    def login(self):
        resp = self._request(
            'POST',
            '/api/user/login',
            json={"username": self._username, "password": self._password},
        )
        resp.raise_for_status()
        self._token = resp.json().get('token', '')

    def _headers(self):
        if not self._token:
            self.login()
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    def list_virtual_servers(self):
        return self._request('GET', '/api/load_balance_virtual_server', headers=self._headers()).json()

    def list_pools(self):
        return self._request('GET', '/api/load_balance_pool', headers=self._headers()).json()

    def status_check(self):
        return self._request('GET', '/api/system/status', headers=self._headers()).json()

    def api_call(self, method: str, path: str, data=None):
        return self._request(method, path, headers=self._headers(), json=data)
