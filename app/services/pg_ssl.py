"""Apply the operator-selected node-to-node Postgres SSL policy (minimum TLS
protocol + cipher list) and record it.

The *enforcement* (``hostssl`` + ``clientcert=verify-ca`` in ``pg_hba`` and the
standby's ``sslmode=verify-ca``) is set up once during Phase-3 rollout; this
module handles the part the operator tunes at runtime from the UI: the minimum
TLS version and the cipher string. It runs ``ALTER SYSTEM`` as the ``postgres``
OS user (the web process is root on this node) and reloads Postgres. Inputs are
validated strictly (fixed protocol set + a conservative cipher charset) BEFORE
they ever reach a shell, so a UI value can't inject SQL or shell.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from datetime import datetime, timezone

from . import self_update as su
from . import settings_store as ss

_PROTOCOLS = ("TLSv1.2", "TLSv1.3")
# OpenSSL cipher strings: letters/digits and : + ! - _ , @ = space. No shell/SQL metachars.
_CIPHER_RE = re.compile(r"^[A-Za-z0-9:+!_,@=\- ]{1,255}$")


def _psql_as_postgres(sql: str) -> None:
    with tempfile.NamedTemporaryFile("w", suffix=".sql", dir="/tmp", delete=False) as f:
        f.write(sql)
        path = f.name
    import os
    os.chmod(path, 0o644)
    try:
        r = subprocess.run(["su", "postgres", "-c", "psql -v ON_ERROR_STOP=1 -f %s" % path],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout)[-400:])
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def apply_policy(min_protocol: str, ciphers: str, by: str = "admin") -> dict:
    """Validate + apply ssl_min_protocol_version / ssl_ciphers on the LOCAL
    Postgres, then persist the merged policy. Raises ValueError on bad input."""
    if min_protocol not in _PROTOCOLS:
        raise ValueError("min_protocol must be one of %s" % (_PROTOCOLS,))
    ciphers = (ciphers or "").strip()
    if ciphers and not _CIPHER_RE.match(ciphers):
        raise ValueError("cipher string contains disallowed characters")

    stmts = ["ALTER SYSTEM SET ssl_min_protocol_version = '%s';" % min_protocol]
    if ciphers:
        stmts.append("ALTER SYSTEM SET ssl_ciphers = '%s';" % ciphers)
    stmts.append("SELECT pg_reload_conf();")
    _psql_as_postgres("\n".join(stmts) + "\n")

    pol = ss.get_json("security.pg_ssl", {}) or {}
    pol.update({
        "min_protocol": min_protocol,
        "ciphers": ciphers or pol.get("ciphers"),
        "policy_updated_at": datetime.now(timezone.utc).isoformat(),
        "policy_updated_by": by,
        "applied_on": su.this_node_name(),
    })
    # only the primary can WRITE the replicated setting; standby is read-only
    try:
        ss.set_json("security.pg_ssl", pol)
    except Exception:
        pass
    return {"min_protocol": min_protocol, "ciphers": ciphers,
            "node": su.this_node_name(), "role": su.node_role()}
