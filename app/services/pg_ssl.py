"""Apply the operator-selected node-to-node Postgres SSL policy (minimum TLS
protocol + cipher list) and record it.

The *enforcement* (``hostssl`` + ``clientcert=verify-ca`` in ``pg_hba`` and the
standby's ``sslmode=verify-ca``) is set up once during Phase-3 rollout; this
module handles the part the operator tunes at runtime from the UI: the minimum
TLS version and the cipher string. ``ALTER SYSTEM`` has to run as the
``postgres`` OS user. The web process normally runs as the unprivileged service
account, which cannot ``su`` without a password, so the change is handed to the
root updater queue (``kind: pg_ssl``, applied by deploy/self_update_runner.py,
which re-validates both values). Only a web process that really is root (a
legacy root unit) applies it directly. Inputs are validated strictly (fixed
protocol set + a conservative cipher charset) BEFORE they ever reach a shell,
so a UI value can't inject SQL or shell.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import uuid
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


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _enqueue(min_protocol: str, ciphers: str, by: str) -> str:
    """Hand the change to the root updater queue. Returns the request id."""
    su.REQ_DIR.mkdir(parents=True, exist_ok=True)
    su.STATUS_DIR.mkdir(parents=True, exist_ok=True)
    uid = datetime.utcnow().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
    node, role = su.this_node_name(), su.node_role()
    req = {"id": uid, "kind": "pg_ssl", "min_protocol": min_protocol,
           "ciphers": ciphers, "requested_by": by,
           "requested_at": datetime.utcnow().isoformat() + "Z",
           "node": node, "role": role, "origin": "settings-node-tls"}
    (su.STATUS_DIR / (uid + ".json")).write_text(json.dumps({
        "id": uid, "state": "queued", "steps": [], "kind": "pg_ssl",
        "target": min_protocol, "requested_by": by, "node": node, "role": role,
        "origin": "settings-node-tls",
        "updated_at": datetime.utcnow().isoformat() + "Z"}))
    tmp = su.REQ_DIR / ("." + uid + ".tmp")
    tmp.write_text(json.dumps(req))
    tmp.rename(su.REQ_DIR / (uid + ".json"))
    return uid


def apply_policy(min_protocol: str, ciphers: str, by: str = "admin") -> dict:
    """Validate + apply ssl_min_protocol_version / ssl_ciphers on the LOCAL
    Postgres, then persist the merged policy. Raises ValueError on bad input.

    The result carries ``queued`` (the updater request id) when the change was
    handed to the root runner instead of applied in-process."""
    if min_protocol not in _PROTOCOLS:
        raise ValueError("min_protocol must be one of %s" % (_PROTOCOLS,))
    ciphers = (ciphers or "").strip()
    if ciphers and not _CIPHER_RE.match(ciphers):
        raise ValueError("cipher string contains disallowed characters")

    queued = None
    if _is_root():
        stmts = ["ALTER SYSTEM SET ssl_min_protocol_version = '%s';" % min_protocol]
        if ciphers:
            stmts.append("ALTER SYSTEM SET ssl_ciphers = '%s';" % ciphers)
        stmts.append("SELECT pg_reload_conf();")
        _psql_as_postgres("\n".join(stmts) + "\n")
    else:
        from .. import runtime
        if runtime.is_container_runtime():
            # No root updater drains the queue in a container: a queued
            # request would sit "queued" forever while the page said applied.
            raise ValueError("Postgres SSL tuning is not available in the "
                             "container runtime; set it on the database service.")
        queued = _enqueue(min_protocol, ciphers, by)

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
            "node": su.this_node_name(), "role": su.node_role(),
            "queued": queued}
