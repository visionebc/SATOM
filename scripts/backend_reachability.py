#!/usr/bin/env python3
"""Which backends does THIS FortiWeb fail to reach, for the policies listed in a file?

    ./venv/bin/python scripts/backend_reachability.py --appliance fortiweb13 fortiweb.txt

``fortiweb.txt`` is one SERVER POLICY name per line; blank lines and ``#``
comments are ignored. A line may name the appliance explicitly as
``appliance:policy`` when one file spans several boxes.

THE VANTAGE IS THE APPLIANCE, NEVER THIS NODE
    The question "can the FortiWeb reach its backend" has exactly one honest
    answer-giver: the FortiWeb. So the verdict comes from the runtime monitor
    ``/api/v2.0/policy/policystatus.detail`` — the appliance's OWN health-check
    result per pool member. A TCP connect from this host would answer a
    different question (can SATOM reach it) and would quietly disagree with the
    box whenever the two sit on different networks, which is the entire reason
    the backend is unreachable in the first place.

``N/A`` IS NOT ``UP``
    ``healthCheckStatus`` is ``enable`` (UP), ``disable`` (DOWN) or ``N/A`` —
    and ``N/A`` means the pool has NO health check, so the appliance is not
    testing that backend at all. It is reported ``unknown``, never reachable and
    never down. Folding "we did not test" into either column is how a report
    like this manufactures a false all-clear. Pass ``--ssh`` to resolve those
    with a real ``execute ping`` FROM the appliance.

WHAT THE CONFIG SAYS IS CROSS-CHECKED AGAINST WHAT THE RUNTIME SHOWS
    Pool membership is read from the cmdb as well. A member that is configured
    but absent from the runtime table is its own finding — a shorter runtime
    list reads as "fewer backends to worry about", which is the opposite of what
    it means.

Exit codes: 0 = no backend is down · 1 = at least one is down · 2 = usage/fatal.
"""
import sys

sys.dont_write_bytecode = True  # keep root-owned __pycache__ out of /opt/satom

import argparse
import json
import os

SATOM = os.environ.get("SATOM_HOME", "/opt/satom")
sys.path.insert(0, SATOM)

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    sys.exit("run me with %s/venv/bin/python" % SATOM)

load_dotenv(os.path.join(SATOM, ".env"))

from app import create_app                                    # noqa: E402
from app.models import Appliance                              # noqa: E402
from app.clients.fortiweb import FortiWebClient               # noqa: E402
from app.services import backend_probe as bp                  # noqa: E402


# --------------------------------------------------------------------------- #
#  Input                                                                        #
# --------------------------------------------------------------------------- #
def read_list(path, default_appliance):
    """``fortiweb.txt`` -> ``[(appliance, policy), ...]`` preserving order.

    Duplicates are dropped rather than probed twice: the same policy listed
    twice would print the same backend twice and inflate the counts.
    """
    out, seen = [], set()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            appl, policy = default_appliance, line
            if ":" in line:
                left, right = line.split(":", 1)
                left, right = left.strip(), right.strip()
                if left and right:
                    appl, policy = left, right
            if not appl:
                sys.exit("line %d: %r names no appliance and --appliance was "
                         "not given" % (n, line))
            key = (appl, policy)
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def load_appliance(name):
    ap = Appliance.query.filter_by(name=name).first()
    if ap is None:
        sys.exit("no appliance named %r is registered in SATOM" % name)
    if (ap.kind or "").lower() != "fortiweb":
        sys.exit("%r is a %s, and this report reads FortiWeb server policies"
                 % (name, ap.kind))
    return ap


# --------------------------------------------------------------------------- #
#  The appliance's own verdict                                                  #
# --------------------------------------------------------------------------- #
#: enable = the health check passes · disable = it fails · N/A = there is none.
#: 7.6.8 emits "N/A" with a SLASH -- verified live against fortiweb13 with the
#: pool's health check removed. The dash and bare spellings stay because the
#: value is undocumented and has no reason to be stable. The lookup default is
#: "unknown" and must remain so: an unrecognised verdict is a verdict we do not
#: have, and folding it into "up" is how this report would manufacture an
#: all-clear for a backend nobody is testing.
_HC = {"enable": "up", "disable": "down",
       "n/a": "unknown", "n-a": "unknown", "na": "unknown"}


def runtime_health(client, policy):
    """``policystatus.detail`` -> ``({(addr, port): row}, error)``."""
    rows, err = client.policy_health(policy)
    if err:
        return {}, err
    index = {}
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        addr = str(r.get("ipDomainName") or "").strip()
        try:
            port = int(r.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        index[(addr, port)] = r
    return index, None


def match(index, addr, port):
    """Runtime row for a configured member, or ``None``.

    An ``http-https-adaptive`` pool yields two configured rows (http and https
    port) per member while the runtime reports the port it actually serves, so
    an exact miss falls back to the address when that address is unambiguous.
    Ambiguity is left unmatched on purpose — guessing which of two rows belongs
    to which port would attach a verdict to the wrong backend.
    """
    hit = index.get((addr, port))
    if hit is not None:
        return hit
    same = [v for (a, _p), v in index.items() if a == addr]
    return same[0] if len(same) == 1 else None


def verdict_for(row, index):
    """One configured member -> ``(state, detail)``.

    ``state`` is ``up`` | ``down`` | ``unknown`` | ``admin-disabled`` | ``error``.
    """
    if row.get("error"):
        return "error", row["error"]
    if not row.get("enabled", True):
        return "admin-disabled", ("the member is administratively disabled in "
                                  "the pool — the appliance is not using it")
    addr, port = row.get("address") or "", row.get("port") or 0
    live = match(index, addr, port)
    if live is None:
        return "unknown", ("configured in the pool but absent from the runtime "
                           "table — the appliance is not reporting on it")
    raw = str(live.get("healthCheckStatus") or "").strip().lower()
    state = _HC.get(raw, "unknown")
    if state == "up":
        rtt = live.get("server_rtt")
        return "up", "health check passes%s" % (", %s ms rtt" % rtt if rtt else "")
    if state == "down":
        return "down", "the appliance's health check FAILS for this member"
    return "unknown", ("the pool has no health check (%s) — the appliance is "
                       "not testing this backend" % (raw or "unset"))


# --------------------------------------------------------------------------- #
#  Optional second vantage: execute ping, FROM the appliance                    #
# --------------------------------------------------------------------------- #
def resolve_unknowns(appliance, rows):
    """Ping every ``unknown`` address from the box itself. Never downgrades.

    Only ``unknown`` rows are touched: where the appliance already published a
    health-check verdict, that verdict is better evidence than ICMP — a backend
    can answer ping with its web service dead, and plenty of hosts drop ICMP
    while serving perfectly.
    """
    todo = sorted({r["address"] for r in rows
                   if r["state"] == "unknown" and r.get("address")})
    if not todo:
        return
    from app.services import ssh_ops
    try:
        sess = ssh_ops.FortiWebReadonlySSH(appliance, timeout=20.0).connect()
    except Exception as exc:  # noqa: BLE001
        for r in rows:
            if r["state"] == "unknown":
                r["detail"] += " | no SSH vantage: %s" % exc
        return
    seen = {}
    try:
        for addr in todo:
            try:
                out = sess.run_probe("execute ping %s"
                                     % bp.assert_probe_target(addr))
                seen[addr] = bp.parse_ping(out)
            except Exception as exc:  # noqa: BLE001
                seen[addr] = {"verdict": "cli error", "detail": str(exc)}
    finally:
        try:
            sess.close()
        except Exception:  # noqa: BLE001
            pass
    for r in rows:
        if r["state"] != "unknown":
            continue
        res = seen.get(r.get("address"))
        if not res:
            continue
        # 'no answer' / 'cli error' / 'unresolved' stay unknown: a probe that
        # failed, rendered as an outage, is a manufactured false alarm.
        if res["verdict"] == "alive":
            r["state"] = "up"
        elif res["verdict"] == "no reply":
            r["state"] = "down"
        r["detail"] = "ping from the appliance: %s (%s)" % (res["verdict"],
                                                            res["detail"])


# --------------------------------------------------------------------------- #
#  Report                                                                       #
# --------------------------------------------------------------------------- #
_ORDER = ["down", "unknown", "error", "admin-disabled", "up"]
_TITLE = {
    "down":     "NOT REACHED — the appliance's health check fails",
    "unknown":  "NOT TESTED — no verdict available (this is not an all-clear)",
    "error":    "COULD NOT READ",
    "admin-disabled": "DISABLED IN THE POOL (not an outage)",
    "up":       "reached",
}


def render(appliance_rows, show_up):
    total = 0
    buckets = {k: [] for k in _ORDER}
    for name, host, rows in appliance_rows:
        for r in rows:
            total += 1
            buckets[r["state"]].append((name, host, r))
    for state in _ORDER:
        rows = buckets[state]
        if not rows or (state == "up" and not show_up):
            continue
        print("\n%s  (%d)" % (_TITLE[state], len(rows)))
        print("-" * 78)
        for name, _host, r in rows:
            where = "%s:%s" % (r["address"] or "?", r["port"] or "?")
            print("  %-14s %-22s %-24s %s"
                  % (name, r["policy"], where, r["detail"]))
    counts = {k: len(v) for k, v in buckets.items()}
    print("\n%d backends | %d not reached | %d not tested | %d errors | "
          "%d disabled | %d reached"
          % (total, counts["down"], counts["unknown"], counts["error"],
             counts["admin-disabled"], counts["up"]))
    return counts


def main():
    ap = argparse.ArgumentParser(
        description="Backends a FortiWeb cannot reach, for the server policies "
                    "listed in a file.")
    ap.add_argument("file", help="one server-policy name per line "
                                 "(or appliance:policy)")
    ap.add_argument("--appliance", "-a", default="",
                    help="SATOM appliance name for lines that do not carry one")
    ap.add_argument("--ssh", action="store_true",
                    help="resolve 'not tested' rows with execute ping from the "
                         "appliance (needs the stored admin credential)")
    ap.add_argument("--all", action="store_true",
                    help="also list the backends that ARE reached")
    ap.add_argument("--json", action="store_true", help="machine-readable")
    ap.add_argument("--timeout", type=float, default=25.0)
    args = ap.parse_args()

    app = create_app()
    with app.app_context():
        try:
            wanted = read_list(args.file, args.appliance.strip())
        except OSError as exc:
            sys.exit("cannot read %s: %s" % (args.file, exc))
        if not wanted:
            sys.exit("%s lists no policies" % args.file)

        by_appliance = {}
        for appl, policy in wanted:
            by_appliance.setdefault(appl, []).append(policy)

        out = []
        for name, policies in by_appliance.items():
            appliance = load_appliance(name)
            client = FortiWebClient(appliance, timeout=args.timeout)
            # Config side: read the pools back FROM THE BOX, never from a plan.
            try:
                targets = bp.dst_pool_targets(client, policies)
            except bp.ProbeRefused as exc:
                targets = [{"policy": p, "pool": "", "address": "", "port": 0,
                            "enabled": True, "error": str(exc)}
                           for p in policies]
            cache = {}
            rows = []
            for t in targets:
                pol = t.get("policy") or ""
                if pol not in cache:
                    cache[pol] = runtime_health(client, pol)
                index, err = cache[pol]
                if err and not t.get("error"):
                    t = dict(t, error="the appliance refused the runtime read: "
                                      "%s" % err)
                state, detail = verdict_for(t, index)
                rows.append({"appliance": name, "policy": pol,
                             "pool": t.get("pool") or "",
                             "address": t.get("address") or "",
                             "port": t.get("port") or 0,
                             "state": state, "detail": detail})
            if args.ssh:
                resolve_unknowns(appliance, rows)
            out.append((name, appliance.host, rows))

        if args.json:
            payload = [{"appliance": n, "host": h, "backends": r}
                       for n, h, r in out]
            print(json.dumps(payload, indent=2))
            down = sum(1 for _n, _h, r in out
                       for x in r if x["state"] == "down")
        else:
            for n, h, r in out:
                print("%s (%s) — %d policies, %d backends"
                      % (n, h, len({x['policy'] for x in r}), len(r)))
            counts = render(out, args.all)
            down = counts["down"]
        return 1 if down else 0


if __name__ == "__main__":
    sys.exit(main())
