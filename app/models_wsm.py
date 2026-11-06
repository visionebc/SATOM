"""Web Server Manager (Linux ADOM): credentials, audit, scripts, schedules.

A managed server is a Plugin Studio ``server`` connection (host, port, the
pinned host key, Allow writes): one record for the Web Server Manager, the
old Web hosts apps and hostguard alike. What this module adds is WHO talks to
that server:

* :class:`WsmCredential` -- an SSH account on one server (password, or key
  with an optional passphrase), how it becomes root (``sudo`` with its own
  password, ``sudo`` NOPASSWD, or not at all) and whether SATOM keeps the
  secret (service credential) or asks for it at every operation. The secret
  itself never lives in a column: it is in the vault, or Fernet-encrypted in
  ``app_settings`` (services.prefixed_secret), under ``wsm.cred.<id>.*``.
* :class:`WsmAudit` -- one row per operation with the three identities
  (SATOM user, SSH user, effective Linux user), sudo or not, the credential
  and the session id.
* :class:`WsmScript`, :class:`WsmSchedule`, :class:`WsmRun` -- the script
  library, the jobs SATOM itself runs on a schedule (with a stored service
  credential; a revoked or expired one parks them as "pending
  authentication"), and the record of every script / package run.
"""
from __future__ import annotations

import json
from datetime import datetime

from .extensions import db


def _loads(raw, default):
    try:
        v = json.loads(raw or "")
    except (TypeError, ValueError):
        return default
    return v if isinstance(v, type(default)) else default


class WsmCredential(db.Model):
    __tablename__ = "wsm_credentials"

    AUTH_TYPES = ("password", "key", "agent")
    ESCALATIONS = ("none", "sudo", "sudo_nopasswd")
    SUDO_PASSWORD = ("same", "ask")
    RUN_AS = ("self", "auto", "root")
    STATUSES = ("active", "disabled", "revoked")
    MODULES = ("files", "sites", "certs", "security", "scripts", "cron", "packages",
               "services", "logs", "users", "ssh")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    #: the server: a Plugin Studio connection of kind "server"
    connection_slug = db.Column(db.String(48), nullable=False, index=True)
    #: SATOM user who added it; a non-shared credential is theirs alone
    owner = db.Column(db.String(64), nullable=False, default="")
    #: a service credential other operators of the server may use
    shared = db.Column(db.Boolean, nullable=False, default=False)
    ssh_user = db.Column(db.String(64), nullable=False, default="")
    #: password | key | agent (the satom-webctl key of the connection)
    auth_type = db.Column(db.String(16), nullable=False, default="password")
    #: none | sudo (with a password) | sudo_nopasswd (a NOPASSWD rule exists)
    escalation = db.Column(db.String(16), nullable=False, default="none")
    #: for "sudo": same = the SSH password; ask = asked at every operation
    sudo_password = db.Column(db.String(8), nullable=False, default="same")
    #: False = on demand: the secret is asked at every operation, never kept
    store_secret = db.Column(db.Boolean, nullable=False, default=True)
    #: self | auto (as the account, then sudo when refused) | root (always sudo)
    run_as = db.Column(db.String(8), nullable=False, default="auto")
    #: modules this credential may be used for ([] = all)
    modules_json = db.Column(db.Text, nullable=False, default="[]")
    status = db.Column(db.String(12), nullable=False, default="active")
    expires_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    revoked_by = db.Column(db.String(64), nullable=False, default="")

    __table_args__ = (db.UniqueConstraint("connection_slug", "name", name="uq_wsm_cred_name"),)

    @property
    def modules(self) -> list:
        return [m for m in _loads(self.modules_json, []) if m in self.MODULES]

    @property
    def expired(self) -> bool:
        return bool(self.expires_at and self.expires_at <= datetime.utcnow())

    @property
    def state(self) -> str:
        """active | disabled | revoked | expired -- what the UI shows."""
        if self.status != "active":
            return self.status
        return "expired" if self.expired else "active"

    @property
    def can_escalate(self) -> bool:
        return self.escalation in ("sudo", "sudo_nopasswd") and self.auth_type != "agent"


class WsmAudit(db.Model):
    __tablename__ = "wsm_audit"

    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    app_user = db.Column(db.String(64), nullable=False, default="")
    ssh_user = db.Column(db.String(64), nullable=False, default="")
    effective_user = db.Column(db.String(64), nullable=False, default="")
    effective_uid = db.Column(db.Integer, nullable=True)
    connection_slug = db.Column(db.String(48), nullable=False, default="", index=True)
    host = db.Column(db.String(255), nullable=False, default="")
    module = db.Column(db.String(16), nullable=False, default="")
    op = db.Column(db.String(32), nullable=False, default="")
    target = db.Column(db.String(500), nullable=False, default="")
    ok = db.Column(db.Boolean, nullable=False, default=False)
    error = db.Column(db.String(32), nullable=False, default="")
    detail = db.Column(db.String(600), nullable=False, default="")
    exit_code = db.Column(db.Integer, nullable=True)
    sudo = db.Column(db.Boolean, nullable=False, default=False)
    credential_id = db.Column(db.Integer, nullable=True)
    credential_name = db.Column(db.String(64), nullable=False, default="")
    #: interactive | service | schedule | agent
    auth_mode = db.Column(db.String(12), nullable=False, default="")
    session_id = db.Column(db.String(32), nullable=False, default="")
    ms = db.Column(db.Integer, nullable=True)
    ip = db.Column(db.String(45), nullable=False, default="")


class WsmScript(db.Model):
    __tablename__ = "wsm_scripts"

    INTERPRETERS = ("bash", "sh", "python", "php", "perl", "custom")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False, default="")
    interpreter = db.Column(db.String(12), nullable=False, default="bash")
    content = db.Column(db.Text, nullable=False, default="")
    #: default arguments, one per line in the UI
    args_json = db.Column(db.Text, nullable=False, default="[]")
    cwd = db.Column(db.String(1024), nullable=False, default="")
    timeout = db.Column(db.Integer, nullable=False, default=300)
    owner = db.Column(db.String(64), nullable=False, default="")
    #: a template other operators can see and run
    shared = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @property
    def args(self) -> list:
        return [a for a in _loads(self.args_json, []) if isinstance(a, str)]


class WsmSchedule(db.Model):
    """A script SATOM runs on a server on a schedule, with a stored credential.
    Not a host crontab line (that lives on the server and runs as its owner,
    Cron Jobs page): this one SATOM starts, so revoking its credential stops it."""
    __tablename__ = "wsm_schedules"

    STATES = ("ok", "failed", "pending_auth", "never")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    connection_slug = db.Column(db.String(48), nullable=False, index=True)
    credential_id = db.Column(db.Integer, nullable=True)
    script_id = db.Column(db.Integer, nullable=True)
    run_as = db.Column(db.String(8), nullable=False, default="self")
    #: five-field cron expression, evaluated in UTC
    cron = db.Column(db.String(120), nullable=False, default="0 2 * * *")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    state = db.Column(db.String(16), nullable=False, default="never")
    state_detail = db.Column(db.String(500), nullable=False, default="")
    notified_state = db.Column(db.String(16), nullable=False, default="")
    last_run_at = db.Column(db.DateTime, nullable=True)
    last_exit = db.Column(db.Integer, nullable=True)
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class WsmRun(db.Model):
    __tablename__ = "wsm_runs"

    id = db.Column(db.Integer, primary_key=True)
    #: script | package | schedule | certbot
    kind = db.Column(db.String(12), nullable=False, default="script")
    title = db.Column(db.String(300), nullable=False, default="")
    connection_slug = db.Column(db.String(48), nullable=False, default="", index=True)
    script_id = db.Column(db.Integer, nullable=True)
    schedule_id = db.Column(db.Integer, nullable=True)
    credential_id = db.Column(db.Integer, nullable=True)
    by = db.Column(db.String(64), nullable=False, default="")
    ssh_user = db.Column(db.String(64), nullable=False, default="")
    effective_user = db.Column(db.String(64), nullable=False, default="")
    sudo = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(12), nullable=False, default="running")
    exit_code = db.Column(db.Integer, nullable=True)
    stdout = db.Column(db.Text, nullable=False, default="")
    stderr = db.Column(db.Text, nullable=False, default="")
    #: what was run: interpreter, cwd, arguments (never a secret)
    meta_json = db.Column(db.Text, nullable=False, default="{}")
    job_id = db.Column(db.String(64), nullable=False, default="")
    started_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    @property
    def meta(self) -> dict:
        return _loads(self.meta_json, {})
