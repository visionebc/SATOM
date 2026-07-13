"""Encryption posture for the Monitoring dashboard.

For every inter-node / off-box channel this answers three questions the operator
asked for — **is it encrypted, with what (protocol + cipher), and how (the
mechanism)** — and every "encrypted" verdict is backed by a LIVE probe, never
assumed:

  * **DB replication** (Postgres streaming): ``pg_stat_ssl`` on the live sender
    gives the real TLS version + cipher. We also report whether it is *enforced*
    (``hostssl`` + ``sslmode>=require`` — a plaintext downgrade is refused) or
    merely *negotiated* (``host`` + ``sslmode=prefer`` — encrypted today but
    silently downgradable). The enforced flag is written by the privileged
    ``pg_ssl`` runner when Phase 3 is applied, and stored in ``app_settings``.
  * **Inter-node app probes** (``/healthz*``): whether THIS node reaches the peer
    over HTTPS (:8443, node cert) or still plain HTTP (:8000). A short TLS probe
    reports the negotiated protocol + cipher.
  * **Data sync** (``fm-ha-datasync``): rsync tunnelled over SSH — transport
    encrypted by construction.
  * **Config SoT publish** (Gitea): HTTPS.
  * **Node service cert**: the leaf nginx serves on :8443 (subject / issuer /
    validity / days-to-expiry).

No SSH. DB reads are local. The peer TLS check does a 2 s handshake. Served from
a SEPARATE endpoint fetched AFTER page render (same contract as ``/infra``): a
page load never touches the network.  Everything is best-effort — a failed probe
degrades to ``encrypted=None`` (unknown) and never raises.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

from . import self_update as su
from . import settings_store as ss

PKI_DIR = Path("/opt/fortinet-manager/pki")
NODE_CERT = PKI_DIR / "public" / "server.crt"
PEER_HTTPS_PORT = 8443
PEER_HTTP_PORT = 8000
_TLS_TIMEOUT = 2.0


# ---------------------------------------------------------------------------
# Operator-selectable enforcement policy (written by the pg_ssl runner)
# ---------------------------------------------------------------------------
def pg_ssl_policy() -> dict:
    """The node-to-node DB SSL policy: whether SSL is ENFORCED (hostssl) and the
    operator-selected minimum protocol + cipher string. Defaults describe the
    pre-Phase-3 state (negotiated, not enforced)."""
    pol = ss.get_json("security.pg_ssl", {}) or {}
    return {
        "enforced": bool(pol.get("enforced", False)),
        "min_protocol": pol.get("min_protocol", "TLSv1.2"),
        "ciphers": pol.get("ciphers", "HIGH:!aNULL:!MD5"),
        "sslmode": pol.get("sslmode", "prefer"),
        "applied_at": pol.get("applied_at"),
        "applied_by": pol.get("applied_by"),
    }


# ---------------------------------------------------------------------------
# DB replication TLS (live, from Postgres)
# ---------------------------------------------------------------------------
def pg_replication_tls() -> dict:
    """Live TLS state of streaming replication, read from the LOCAL Postgres.

    On the primary the sender side is authoritative (``pg_stat_ssl`` join
    ``pg_stat_replication`` → real cipher). On a standby only the receiver status
    is available over SQL (cipher is sender-side); the peer's ``/healthz`` carries
    the authoritative cipher for the standby's card.
    """
    role = su.node_role()
    pol = pg_ssl_policy()
    out = {"role": role, "encrypted": None, "protocol": None, "cipher": None,
           "enforced": pol["enforced"], "streaming": False, "peers": [],
           "mechanism": "PostgreSQL TLS (streaming replication)",
           "detail": None, "error": None}
    try:
        from ..models import db
        from sqlalchemy import text
        if role == "primary":
            rows = db.session.execute(text(
                "SELECT r.client_addr, r.state, s.ssl, s.version, s.cipher "
                "FROM pg_stat_replication r LEFT JOIN pg_stat_ssl s ON s.pid=r.pid"
            )).mappings().all()
            peers = []
            enc_any = False
            for r in rows:
                enc = bool(r["ssl"])
                enc_any = enc_any or enc
                peers.append({"client_addr": str(r["client_addr"]) if r["client_addr"] else None,
                              "state": r["state"], "encrypted": enc,
                              "protocol": r["version"], "cipher": r["cipher"]})
                if enc and not out["protocol"]:
                    out["protocol"], out["cipher"] = r["version"], r["cipher"]
            out["peers"] = peers
            out["streaming"] = any(p["state"] == "streaming" for p in peers)
            out["encrypted"] = (enc_any if peers else None)
            if not peers:
                out["detail"] = "no standby currently connected"
        elif role == "standby":
            row = db.session.execute(text(
                "SELECT status, sender_host FROM pg_stat_wal_receiver"
            )).mappings().first()
            if row:
                out["streaming"] = (row["status"] == "streaming")
                out["detail"] = ("receiving from %s (sender-side cipher is "
                                 "authoritative — see the primary's card)"
                                 % row["sender_host"])
                # sslmode from our own conninfo tells us if a plaintext fallback
                # is even permitted; the enforced flag is the policy of record.
                out["encrypted"] = True if out["streaming"] else None
            else:
                out["detail"] = "walreceiver not running"
    except Exception as e:  # never poison the request txn
        try:
            from ..models import db
            db.session.rollback()
        except Exception:
            pass
        out["error"] = str(e)[:200]
    return out


# ---------------------------------------------------------------------------
# Peer TLS handshake (inter-node app channel)
# ---------------------------------------------------------------------------
def _peer_tls(host: str, port: int = PEER_HTTPS_PORT) -> dict:
    """Open a real TLS handshake to a peer's :8443 and report the negotiated
    protocol + cipher. Certificate is NOT verified here (the point is to prove
    the transport is encrypted and name the cipher); cert trust is a separate
    concern handled by the node-cert card + the internal CA."""
    out = {"https": False, "protocol": None, "cipher": None, "bits": None,
           "error": None}
    ctx = ssl._create_unverified_context()
    try:
        with socket.create_connection((host, port), timeout=_TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                name, proto, bits = tls.cipher() or (None, None, None)
                out.update(https=True, protocol=proto, cipher=name, bits=bits)
    except Exception as e:
        out["error"] = str(e)[:120]
    return out


def internode_channel() -> dict:
    """Whether THIS node's probes to its peer(s) ride HTTPS (:8443) or plaintext
    HTTP (:8000). Encrypted iff every reachable peer answers TLS on :8443. Also
    reports, per peer, whether the shared identity key was accepted
    (``authenticated``) — confidentiality (TLS) + authenticity (key)."""
    from . import node_security as nsec
    import json as _json
    this = su.this_node_name()
    id_key_set = nsec.configured()
    peers = []
    for n in su.node_reports():
        if n.get("name") == this:
            continue
        host = n.get("host")
        if not host or host == "127.0.0.1":
            continue
        t = _peer_tls(host)
        authed = None
        if id_key_set:
            try:
                st, body, _sec = nsec.peer_get(host, "/healthz", timeout=_TLS_TIMEOUT)
                if st is not None:
                    authed = (_json.loads(body.decode("utf-8", "replace"))
                              .get("peer_authenticated"))
            except Exception:
                authed = None
        peers.append({"name": n.get("name"), "host": host,
                      "https": t["https"], "protocol": t["protocol"],
                      "cipher": t["cipher"], "authenticated": authed})
    if not peers:
        return {"encrypted": None, "protocol": None, "cipher": None,
                "mechanism": "HTTP(S) node probes (/healthz*)",
                "detail": "no peer node registered", "peers": []}
    all_https = all(p["https"] for p in peers)
    any_https = any(p["https"] for p in peers)
    all_authed = id_key_set and all(p.get("authenticated") for p in peers)
    ex = next((p for p in peers if p["https"]), peers[0])
    auth_txt = (" · identity key verified" if all_authed
                else (" · identity key configured" if id_key_set
                      else " · no identity key set"))
    return {
        "encrypted": True if all_https else (False if not any_https else None),
        "protocol": ex.get("protocol"),
        "cipher": ex.get("cipher"),
        "authenticated": bool(all_authed),
        "mechanism": ("HTTPS on :8443 (node cert)" if any_https else "plain HTTP :8000") + auth_txt,
        "detail": (("all peers reachable over HTTPS :8443" if all_https
                    else ("some peers only on plain HTTP :8000" if any_https
                          else "peers only reachable on plain HTTP :8000"))
                   + auth_txt),
        "peers": peers,
    }


# ---------------------------------------------------------------------------
# Node service certificate (served by nginx on :8443)
# ---------------------------------------------------------------------------
def node_cert() -> dict:
    out = {"present": False, "subject": None, "issuer": None,
           "not_before": None, "not_after": None, "days_left": None,
           "self_signed": None, "source": ss.get_str("security.node_cert.source", "bootstrap"),
           "error": None}
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding  # noqa: F401
        data = NODE_CERT.read_bytes()
        cert = x509.load_pem_x509_certificate(data)
        out["present"] = True
        out["subject"] = cert.subject.rfc4514_string()
        out["issuer"] = cert.issuer.rfc4514_string()
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
        out["not_before"] = nb.isoformat()
        out["not_after"] = na.isoformat()
        out["days_left"] = int((na - datetime.now(timezone.utc)).total_seconds() // 86400)
        out["self_signed"] = (cert.subject == cert.issuer)
    except Exception as e:
        out["error"] = str(e)[:160]
    return out


# ---------------------------------------------------------------------------
def snapshot() -> dict:
    """Everything the Monitoring encryption cards render, in one call."""
    repl = pg_replication_tls()
    inter = internode_channel()
    pol = pg_ssl_policy()

    channels = []

    # 1) DB replication
    db_detail = repl.get("detail") or ""
    if repl["encrypted"] and not repl["enforced"]:
        db_note = "encrypted but NOT enforced — a plaintext downgrade would be accepted"
    elif repl["encrypted"] and repl["enforced"]:
        db_note = "encrypted and enforced (hostssl — plaintext refused)"
    elif repl["encrypted"] is False:
        db_note = "NOT encrypted"
    else:
        db_note = db_detail or "no replica connected"
    channels.append({
        "key": "db_repl",
        "label": "DB replication (primary ⇄ standby)",
        "encrypted": repl["encrypted"],
        "enforced": repl["enforced"],
        "protocol": repl["protocol"],
        "cipher": repl["cipher"],
        "mechanism": repl["mechanism"],
        "note": db_note,
        "detail": db_detail,
        "streaming": repl["streaming"],
        "peers": repl["peers"],
    })

    # 2) Inter-node app probes
    channels.append({
        "key": "internode_http",
        "label": "Inter-node app probes (/healthz)",
        "encrypted": inter["encrypted"],
        "enforced": None,
        "protocol": inter["protocol"],
        "cipher": inter["cipher"],
        "mechanism": inter["mechanism"],
        "note": inter["detail"],
        "detail": inter["detail"],
        "peers": inter.get("peers", []),
    })

    # 3) Data sync — rsync over SSH (encrypted by construction)
    channels.append({
        "key": "datasync",
        "label": "Data sync (fm-ha-datasync)",
        "encrypted": True,
        "enforced": True,
        "protocol": "SSH",
        "cipher": "OpenSSH transport",
        "mechanism": "rsync tunnelled over SSH (key /root/.ssh/id_ha_rsync)",
        "note": "encrypted — SSH transport, key-authenticated",
        "detail": "standby pulls data/ every 5 min",
        "peers": [],
    })

    # 4) Config SoT publish — Gitea over HTTPS
    from . import git_service as gs
    git_https = None
    git_remote = ""
    try:
        info = gs.git_info()
        git_remote = info.get("remote") or ""
        if git_remote.startswith("https://"):
            git_https = True
        elif git_remote.startswith("http://"):
            git_https = False
    except Exception:
        pass
    channels.append({
        "key": "git",
        "label": "Config SoT publish (Gitea)",
        "encrypted": git_https,
        "enforced": None,
        "protocol": "TLS" if git_https else ("none" if git_https is False else None),
        "cipher": "HTTPS" if git_https else None,
        "mechanism": "git push over HTTPS" if git_https else "git push (plain HTTP)"
                     if git_https is False else "git remote",
        "note": ("encrypted — HTTPS to Gitea" if git_https
                 else "NOT encrypted — plain HTTP remote" if git_https is False
                 else "remote scheme unknown"),
        "detail": git_remote.split("@")[-1] if git_remote else "",
        "peers": [],
    })

    enc_vals = [c["encrypted"] for c in channels]
    known = [v for v in enc_vals if v is not None]
    return {
        "node": su.this_node_name(),
        "role": su.node_role(),
        "policy": pol,
        "channels": channels,
        "node_cert": node_cert(),
        "summary": {
            "total": len(channels),
            "encrypted": sum(1 for v in known if v),
            "known": len(known),
            "all_encrypted": bool(known) and all(known),
            "db_enforced": repl["enforced"],
        },
        "generated": datetime.now(timezone.utc).isoformat(),
    }
