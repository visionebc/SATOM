"""The border blocklist — a list SATOM publishes, never a write it performs.

What this is
------------
A set of source addresses, each with a mandatory expiry, rendered as one
address per line so a FortiGate (or anything else) can consume it as an
external threat feed. The operator pre-creates the deny policy that references
the feed; SATOM only decides what is *in* it. That is the same rule that
already governs FortiWeb — *Sentinel never binds its own enforcement point
during an incident* — carried across to a device this engine has no client for
and deliberately never got one.

Why a list and not an API call
------------------------------
Requested that way, and it is the better half of the trade:

* no write credential for the firewall exists anywhere in this product;
* one file serves N FortiGates and N VDOMs with no per-device integration;
* the artefact is text, so the audit trail is a diff rather than a log line.

The property this GIVES UP, stated rather than buried
-----------------------------------------------------
``block_ip`` on FortiWeb uses ``action=block-period``: **the appliance expires
the block on its own, and that expiry survives Sentinel being dead.** A feed
has no such device-side timer. The obvious implementation — a job that
rewrites a file every few minutes — moves the TTL onto SATOM staying alive,
and if SATOM dies every block silently becomes permanent.

So the feed is **rendered from the database on every request**, filtered by
``expires_at``, and the file on disk plus the git mirror are an *audit copy*
rather than the source. Consequences, both deliberate:

* a stopped publisher cannot serve an expired entry — there is no cached file
  in the serving path to go stale;
* what remains of the regression is honest and unavoidable: if SATOM is
  unreachable the FortiGate keeps its last successful fetch, so entries freeze
  rather than expire. :func:`render` therefore stamps ``generated_at`` and
  ``stale_after`` into the header of every response, and :func:`feed_state`
  reports staleness to the console — an operator can see a frozen feed instead
  of inferring it.

The veto is upstream, and it is not optional
--------------------------------------------
Nothing reaches this list without passing :func:`edge.blockable`. FortiWeb
reports the CDN's address when a policy does not read ``X-Forwarded-For`` and
the true client's when it does, and nothing in the attack log distinguishes
them. Listing the first kind removes every client behind a shared egress.
That check lives in :mod:`edge` and is called by the caller, not re-implemented
here — one gate, one place, one test.

What this module refuses on its own
-----------------------------------
Three things the border veto cannot answer, checked here every time:

1. addresses that are not public unicast (loopback, RFC1918, link-local,
   multicast, reserved) — blocking those at a border is either a no-op or an
   outage of the operator's own management path;
2. anything inside ``sentinel.protect_cidrs``;
3. **anything at all, when ``protect_cidrs`` contains a line that does not
   parse.** An unreadable never-block list is not an empty one. The permissive
   reading of a broken protection list is "protect nothing", which is exactly
   backwards, and it is silent. This mirrors the access gate, which answers
   503 rather than serving when it cannot evaluate its own policy.

Capacity is refused, never evicted
----------------------------------
At ``feed_max_entries`` a new entry is REFUSED. Evicting the oldest to make
room would silently unblock an address that is still inside its TTL, and the
only telemetry would be traffic resuming.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

from ...models import db
from ...models_sentinel import SentinelBlockEntry
from . import config

#: Hard ceiling on any TTL, whatever the settings say. A blocklist entry is a
#: denial of service to one address; a year-long one authored from a single
#: correlated burst is indistinguishable from a permanent ban nobody decided
#: to make. 30 days is long enough for a sustained campaign and short enough
#: that an unattended installation drains itself.
MAX_TTL_HOURS = 720

#: Verdicts returned by :func:`add`.
OK = "listed"
EXTENDED = "extended"
REFUSED = "refused"

_TOKEN_KEY = "feed_token"


# --------------------------------------------------------------------------- #
#  Address policy                                                               #
# --------------------------------------------------------------------------- #
def parse(value: str):
    """The address, or ``None``. Single hosts only — no CIDR, on purpose.

    A prefix in a border blocklist is a different decision with a different
    blast radius (``/24`` is 256 customers, ``/16`` is a small ISP), and this
    engine derives its entries from evidence about ONE address. Widening that
    to a network is an operator's judgement call and there is nowhere in this
    pipeline it could be justified from.
    """
    try:
        return ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None


def not_listable(ip_obj) -> str:
    """Why this address must never be listed, or ``""`` if it may be.

    Returns a REASON, not a boolean. Every refusal here sends an operator
    somewhere different — a private address means the correlation read the
    wrong field, a protected CIDR means someone tried to block their own
    monitoring, and an unreadable protection list means the policy itself
    cannot be evaluated. A shared ``False`` would collapse the three.
    """
    if ip_obj is None:
        return "the address does not parse"
    # (3) first: with an unreadable never-block list, no answer below is safe.
    bad = config.protect_errors()
    if bad:
        return ("the never-block list has unparseable line(s) "
                f"({', '.join(bad[:3])}) — refusing to list anything until "
                "protect_cidrs can be evaluated")
    # ``is_global`` alone is NOT enough, and the gap is not theoretical:
    # ``ipaddress.ip_address("224.0.0.1").is_global`` is **True**, because
    # is_global asks "is this outside the private ranges", not "is this a
    # host somebody could have connected from". Multicast, reserved space and
    # the unspecified address all pass it. A guard that claims to exclude them
    # and does not is worse than no guard, because the claim is what the next
    # reader relies on. Each class is named rather than folded into one
    # expression so a future edit cannot drop one silently.
    for flag, label in (("is_multicast", "a multicast address"),
                        ("is_reserved", "reserved address space"),
                        ("is_loopback", "a loopback address"),
                        ("is_link_local", "a link-local address"),
                        ("is_unspecified", "the unspecified address")):
        if getattr(ip_obj, flag, False):
            return (f"{label} — not a public unicast host, so blocking it at a "
                    "border is a no-op at best and cuts the operator's own "
                    "path at worst")
    if not ip_obj.is_global:
        return ("not a public unicast address — blocking it at a border is a "
                "no-op at best and cuts the operator's own path at worst")
    for net in config.protected_networks():
        if ip_obj.version == net.version and ip_obj in net:
            return f"inside a protected network ({net})"
    return ""


# --------------------------------------------------------------------------- #
#  Reading                                                                      #
# --------------------------------------------------------------------------- #
def _now() -> datetime:
    return datetime.utcnow()


def live_entries(now: datetime = None) -> list:
    """Entries a feed may carry RIGHT NOW — active and not past their expiry.

    The expiry is applied in the query rather than trusted from ``status``,
    because ``status`` is only accurate as far as the last time something ran
    :func:`expire_due`. Reading the timestamp makes a stopped expiry job a
    cosmetic problem (rows that still say ``active``) instead of a security
    one (addresses served past their TTL).
    """
    now = now or _now()
    return (SentinelBlockEntry.query
            .filter(SentinelBlockEntry.status == SentinelBlockEntry.ACTIVE,
                    SentinelBlockEntry.expires_at > now)
            .order_by(SentinelBlockEntry.created_at.desc()).all())


def all_entries(limit: int = 500) -> list:
    return (SentinelBlockEntry.query
            .order_by(SentinelBlockEntry.created_at.desc()).limit(limit).all())


def find_active(ip: str, now: datetime = None):
    """A row this address can be EXTENDED into, or ``None``.

    Filtered by the clock, not only by ``status``, and the difference is an
    audit-trail defect rather than a cosmetic one: a row whose expiry has
    passed but which nothing has flipped yet is still ``active``. Extending
    that row would revive a lapsed block while keeping the ORIGINAL
    ``created_at``, ``created_by`` and border verdict — so a new listing would
    be documented by evidence gathered for a previous one. A fresh row is
    written instead, and the stale one is excluded from the feed by the same
    timestamp filter that excluded it before.
    """
    now = now or _now()
    return (SentinelBlockEntry.query
            .filter(SentinelBlockEntry.ip == str(ip),
                    SentinelBlockEntry.status == SentinelBlockEntry.ACTIVE,
                    SentinelBlockEntry.expires_at > now)
            .first())


def capacity() -> int:
    return max(1, min(int(config.get("feed_max_entries") or 500), 10000))


def default_ttl_hours() -> int:
    return max(1, min(int(config.get("feed_ttl_hours") or 24), MAX_TTL_HOURS))


# --------------------------------------------------------------------------- #
#  Writing                                                                      #
# --------------------------------------------------------------------------- #
def add(ip: str, *, hours: int = 0, reason: str = "", actor: str = "",
        incident_id: int = 0, appliance_id: int = 0, source: str = "manual",
        edge: dict = None, override: bool = False,
        override_reason: str = "") -> dict:
    """Put one address on the list, or explain precisely why not.

    ``edge`` is the border corroboration result for this address. It is passed
    IN rather than looked up here so that the identical verdict which scored
    the incident is the verdict that gates the listing; recomputing it would
    let a list entry rest on a different answer from a second query seconds
    later — and the second query is the one nobody saw.

    ``override`` is the operator's escape hatch and it is RECORDED, not
    silent. A person who types an address and confirms it may be a shared
    egress has made a decision this engine is not entitled to make for them;
    a person who did that six weeks ago and forgot needs the row to say so.
    """
    ip_obj = parse(ip)
    why = not_listable(ip_obj)
    if why:
        return {"ok": False, "status": REFUSED, "reason": why, "entry": None}

    from . import edge as edge_mod
    allowed, verdict_text = edge_mod.blockable(edge or {})
    if not allowed and not override:
        return {"ok": False, "status": REFUSED,
                "reason": verdict_text, "entry": None,
                "overridable": True}
    if not allowed and override and not (override_reason or "").strip():
        # An override with no stated reason is an override nobody can review.
        return {"ok": False, "status": REFUSED,
                "reason": "an override needs a written reason — it is the "
                          "only record of why the border veto was set aside",
                "entry": None, "overridable": True}

    hours = int(hours or 0) or default_ttl_hours()
    hours = max(1, min(hours, MAX_TTL_HOURS))
    now = _now()
    expires = now + timedelta(hours=hours)

    existing = find_active(str(ip_obj), now)
    if existing is not None:
        # Never SHORTEN a live entry from an automated path: a fresh burst
        # arriving with the default TTL must not cut short a longer block an
        # operator set deliberately.
        if expires > (existing.expires_at or now):
            existing.expires_at = expires
            existing.detail = (f"extended to {hours}h by {actor or 'system'}: "
                               f"{reason}")[:600]
            db.session.commit()
            return {"ok": True, "status": EXTENDED, "entry": existing,
                    "reason": f"already listed; expiry extended to {expires}"}
        return {"ok": True, "status": EXTENDED, "entry": existing,
                "reason": "already listed with a longer or equal expiry — "
                          "left alone"}

    if len(live_entries(now)) >= capacity():
        return {"ok": False, "status": REFUSED, "entry": None,
                "reason": (f"the feed is at its {capacity()}-entry ceiling. "
                           "Nothing is evicted to make room: dropping the "
                           "oldest live entry would unblock an address that "
                           "is still inside its TTL, and the only sign would "
                           "be traffic resuming. Release an entry or raise "
                           "the ceiling.")}

    row = SentinelBlockEntry(
        ip=str(ip_obj), status=SentinelBlockEntry.ACTIVE,
        incident_id=incident_id or None, appliance_id=appliance_id or None,
        reason=(reason or "")[:600], source=(source or "manual")[:24],
        created_by=(actor or "system")[:80], created_at=now,
        expires_at=expires,
        edge_verdict=(edge or {}).get("verdict") or "",
        edge_scope=((edge or {}).get("scope") or "")[:300],
        edge_hits=int((edge or {}).get("hits") or 0),
        override_by=((actor or "system")[:80] if (not allowed and override)
                     else ""),
        override_reason=(override_reason or "")[:400] if not allowed else "",
        detail=verdict_text[:600])
    db.session.add(row)
    db.session.commit()
    return {"ok": True, "status": OK, "entry": row, "reason": verdict_text}


def release(entry_id: int, *, actor: str = "", reason: str = "") -> dict:
    """The release point. Takes one address off the feed immediately.

    Not a delete. The row stays, released, with who and why — a blocklist
    whose false positives vanish without trace cannot be reviewed for the
    pattern that produced them, and "why was this customer blocked last
    Tuesday" is the question that actually gets asked.
    """
    row = SentinelBlockEntry.query.get(int(entry_id or 0))
    if row is None:
        return {"ok": False, "reason": "no such entry"}
    if row.status != SentinelBlockEntry.ACTIVE:
        return {"ok": False, "reason": f"entry is already {row.status}"}
    row.status = SentinelBlockEntry.RELEASED
    row.released_at = _now()
    row.released_by = (actor or "system")[:80]
    row.release_reason = (reason or "")[:400]
    db.session.commit()
    return {"ok": True, "entry": row,
            "reason": f"{row.ip} released — it leaves the feed on the next "
                      "fetch by the border"}


def expire_due(now: datetime = None) -> list:
    """Flip rows whose TTL has passed to ``expired``.

    Housekeeping only. :func:`live_entries` already filters by timestamp, so a
    run that never happens costs accurate bookkeeping, never an address served
    past its expiry. That ordering is the point: the safety property must not
    depend on a timer.
    """
    now = now or _now()
    rows = (SentinelBlockEntry.query
            .filter(SentinelBlockEntry.status == SentinelBlockEntry.ACTIVE,
                    SentinelBlockEntry.expires_at <= now).all())
    for row in rows:
        row.status = SentinelBlockEntry.EXPIRED
    if rows:
        db.session.commit()
    return rows


# --------------------------------------------------------------------------- #
#  Rendering                                                                    #
# --------------------------------------------------------------------------- #
def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def render(now: datetime = None) -> str:
    """The feed body, built from the database at the moment it is asked for.

    The header is not decoration. A consumer that keeps its last successful
    fetch — which is what every threat-feed connector does — cannot tell a
    current list from a frozen one, and a frozen list is a permanent block.
    ``generated_at`` and ``stale_after`` make that visible in the artefact
    itself, so it survives being copied, mailed or committed away from this
    product.
    """
    now = now or _now()
    rows = live_entries(now)
    stale = now + timedelta(minutes=stale_minutes())
    head = [
        "# SATOM Sentinel — border blocklist",
        "#",
        "# Entries are source addresses corroborated at the border and still",
        "# inside their TTL. This file is REGENERATED on every fetch; a cached",
        "# copy is not an expiring list.",
        f"# generated_at: {_stamp(now)}",
        f"# stale_after:  {_stamp(stale)}",
        f"# entries:      {len(rows)}",
        "#",
        "# If generated_at is older than stale_after, SATOM is not answering",
        "# and these entries are FROZEN, not current: they will not expire on",
        "# their own while this copy is the one being enforced.",
        "#",
    ]
    body = [row.ip for row in rows]
    return "\n".join(head + body) + "\n"


def stale_minutes() -> int:
    return max(1, min(int(config.get("feed_stale_minutes") or 30), 1440))


def feed_state(now: datetime = None) -> dict:
    """Everything the console needs to say whether the feed is trustworthy."""
    now = now or _now()
    rows = live_entries(now)
    nxt = min((r.expires_at for r in rows if r.expires_at), default=None)
    mirror = _mirror_state()
    return {
        "enabled": bool(config.get("feed_enabled")),
        "has_token": bool(current_token()),
        "live": len(rows),
        "capacity": capacity(),
        "full": len(rows) >= capacity(),
        "ttl_hours": default_ttl_hours(),
        "stale_minutes": stale_minutes(),
        "next_expiry": _stamp(nxt) if nxt else "",
        "protect_errors": config.protect_errors(),
        "require_edge": bool(config.get("edge_require")),
        "mirror": mirror,
    }


# --------------------------------------------------------------------------- #
#  Token                                                                        #
# --------------------------------------------------------------------------- #
def current_token() -> str:
    return str(config.get(_TOKEN_KEY) or "").strip()


def rotate_token() -> str:
    """A new feed token. Rotating BREAKS every configured connector on purpose.

    There is no grace period and no second valid token. A feed URL is a
    credential pasted into a firewall by a person; a rotation that silently
    keeps the old one working is a rotation that did not revoke anything, and
    the operator would have no way to find out which connectors still hold it.
    """
    token = secrets.token_urlsafe(32)
    config.set_value(_TOKEN_KEY, token)
    return token


def token_matches(candidate: str) -> bool:
    """Constant-time comparison, and an unset token matches NOTHING.

    ``secrets.compare_digest("", "")`` is **True** — so an installation that
    never configured a token would serve the fleet's blocklist to any
    anonymous request that also omitted it. The emptiness check below is the
    guard; the comparison is not.

    There is deliberately **ONE** such check. An earlier version also rejected
    an empty *candidate*, which read as defence in depth and was the opposite:
    the two branches covered each other, so deleting the decisive one changed
    no observable behaviour and no test could see it. A redundant guard is a
    guard that cannot be verified, and an unverifiable guard on the only
    authentication an unauthenticated endpoint has is worse than none —
    because it is the one people will trust. (Found by mutation, 2026-08-23.)
    """
    want = current_token()
    if not want:
        return False
    return secrets.compare_digest(want, str(candidate or ""))


def feed_url(base: str = "") -> str:
    token = current_token()
    if not token:
        return ""
    return f"{base.rstrip('/')}/sentinel/feed/{token}/blocklist.txt"


# --------------------------------------------------------------------------- #
#  Git mirror                                                                   #
# --------------------------------------------------------------------------- #
#: The mirror is a SEPARATE repository and there is no default.
#:
#: It is emphatically NOT ``satom-dev/satom``. That repository is mirrored to
#: Gitea-prod and to GitHub by ``sync_prod.py``, so a blocklist committed into
#: it would publish which addresses attacked which customer, to the public,
#: on the next release — an operational disclosure produced by an audit
#: feature. The mirror also stays out of ``data/``: the standby's
#: ``satom-ha-datasync`` runs ``rsync --delete`` over that tree and would wipe
#: a working copy mid-commit.
MIRROR_DIR = "/var/lib/satom-blocklist"
MIRROR_FILE = "blocklist.txt"
_SECRET_RE = re.compile(r"://[^/@\s]*:[^/@\s]*@")


def _redact(text: str, token: str = "") -> str:
    out = _SECRET_RE.sub("://***:***@", str(text or ""))
    if token:
        out = out.replace(token, "***")
    return out


def _mirror_cfg() -> dict:
    return {
        "remote": str(config.get("feed_git_remote") or "").strip(),
        "branch": str(config.get("feed_git_branch") or "main").strip() or "main",
        "token": str(config.get("feed_git_token") or "").strip(),
        "auto": bool(config.get("feed_git_auto")),
    }


def _mirror_state() -> dict:
    cfg = _mirror_cfg()
    path = Path(MIRROR_DIR)
    head = ""
    last = ""
    if (path / ".git").exists():
        head = _git_out(path, "log", "-1", "--format=%h %cI %s")
        last = _git_out(path, "log", "-1", "--format=%cI", "--", MIRROR_FILE)
    return {"configured": bool(cfg["remote"]), "auto": cfg["auto"],
            "branch": cfg["branch"], "dir": MIRROR_DIR,
            "remote": _redact(cfg["remote"]),
            "cloned": bool((path / ".git").exists()),
            "head": head, "last_commit": last}


def _git_out(cwd: Path, *args: str) -> str:
    try:
        res = subprocess.run(("git", *args), cwd=str(cwd), timeout=60,
                             capture_output=True, text=True)
        return res.stdout.strip() if res.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _authed(remote: str, token: str) -> str:
    if not token or not remote.startswith(("http://", "https://")):
        return remote
    scheme, rest = remote.split("://", 1)
    if "@" in rest.split("/", 1)[0]:
        return remote
    return f"{scheme}://satom:{token}@{rest}"


def mirror_push(text: str, message: str) -> dict:
    """Write the rendered list into the mirror repo and push it.

    Best effort by contract: this is the AUDIT copy. A mirror that cannot
    reach its remote must never stop an address being listed or released —
    the feed itself is served from the database and is unaffected. Every
    failure is returned as text for the page to show, and every returned
    string is redacted.
    """
    cfg = _mirror_cfg()
    if not cfg["remote"]:
        return {"ok": False, "log": "no mirror remote configured"}
    root = Path(MIRROR_DIR)
    lines: list[str] = []
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")

    def run(*args: str) -> int:
        try:
            res = subprocess.run(("git", *args), cwd=str(root), env=env,
                                 timeout=180, capture_output=True, text=True)
        except (OSError, subprocess.SubprocessError) as exc:
            lines.append(_redact(f"$ git {' '.join(args)}\n{exc}", cfg["token"]))
            return 1
        lines.append(_redact(
            f"$ git {' '.join(args)}\n{res.stdout}{res.stderr}".strip(),
            cfg["token"]))
        return res.returncode

    authed = _authed(cfg["remote"], cfg["token"])
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "log": f"cannot create {MIRROR_DIR}: {exc}"}
    if not (root / ".git").exists():
        run("init", "-q")
        run("remote", "add", "origin", authed)
    else:
        run("remote", "set-url", "origin", authed)
    run("config", "user.email", "sentinel@satom.local")
    run("config", "user.name", "SATOM Sentinel")
    (root / MIRROR_FILE).write_text(text, encoding="utf-8")
    run("add", MIRROR_FILE)
    run("commit", "-m", message)
    rc = run("push", "origin", f"HEAD:{cfg['branch']}")
    return {"ok": rc == 0, "log": "\n\n".join(lines)}


def publish(actor: str = "system", *, force: bool = False) -> dict:
    """Expire what is due, render, and mirror if the mirror is configured.

    Ordering matters: expiry runs BEFORE the render so the committed artefact
    matches what the feed serves at that instant. Rendering first would commit
    a list one sweep out of date and make the git history disagree with the
    endpoint for no reason anyone could later reconstruct.
    """
    expired = expire_due()
    text = render()
    cfg = _mirror_cfg()
    out = {"expired": [r.ip for r in expired], "entries": len(live_entries()),
           "mirrored": False, "log": ""}
    if cfg["remote"] and (cfg["auto"] or force):
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        res = mirror_push(text, f"blocklist: {out['entries']} entr(y/ies) "
                                f"[{digest}] by {actor}")
        out["mirrored"] = bool(res.get("ok"))
        out["log"] = res.get("log", "")
    return out
