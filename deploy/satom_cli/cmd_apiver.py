"""``get api versions`` / ``get api preflight`` — the firmware-line matrix.

STDLIB ONLY, like every module in this package: it reads
``data/api_matrix/<product>.json`` off the disk and never imports the app. That
is not a shortcut — the whole point of this CLI is to answer on a node whose
database is down, and "which fields does this firmware take?" is exactly the
question you have when a write just failed.

The consequence is stated rather than hidden: the file is a SNAPSHOT of the
evidence, so a matrix that has never been rebuilt reports what was true at its
``built_at``, and both commands print that timestamp.
"""
import json
import os
import re

from .render import Result

MATRIX_DIR = "data/api_matrix"
PRODUCTS = ("fortiweb", "fortiadc", "fortianalyzer", "fortiauthenticator")


def _matrix_path(ctx, product):
    return os.path.join(str(ctx.app_dir), MATRIX_DIR, "%s.json" % product)


def _load(ctx, product):
    try:
        with open(_matrix_path(ctx, product)) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _known_products(ctx):
    out = []
    for p in PRODUCTS:
        if os.path.exists(_matrix_path(ctx, p)):
            out.append(p)
    return out


def _resolve(doc, token):
    """``token`` -> (line, how). Accepts a firmware line or an appliance name.

    An appliance name is resolved through the matrix's own witness list, which
    records the firmware SATOM measured. Resolving it any other way would mean
    a second source for "what does this box run", and the two would drift.
    """
    lines = doc.get("lines") or {}
    if token in lines:
        return token, "line"
    for w in doc.get("witnesses") or []:
        if w.get("name") == token:
            line = w.get("line") or ""
            return (line, "appliance %s runs %s" % (token, w.get("firmware") or line or "?")) \
                if line else ("", "appliance %s has no known firmware" % token)
    return "", ""


# ---------------------------------------------------------------------------
# get api versions
# ---------------------------------------------------------------------------

def api_versions(ctx, args):
    """What firmware lines SATOM has evidence for, and how much."""
    args = list(args)
    product = args[0] if args and args[0] in PRODUCTS else None
    if product is None and args:
        r = Result("bad", "unknown product %r" % args[0], exit_code=2)
        r.lines("known products", ["  " + p for p in PRODUCTS])
        return r

    products = [product] if product else (_known_products(ctx) or ["fortiweb"])
    r = Result("ok", "api versions")
    any_line = False
    for prod in products:
        doc = _load(ctx, prod)
        if doc is None:
            r.rows(prod, [("matrix", "never built — run Rebuild on the API "
                                     "versions page, or sweep an appliance")])
            r.worst("warn")
            continue
        rows = []
        for line in sorted(doc.get("lines") or {}):
            L = doc["lines"][line]
            c = L.get("counts") or {}
            any_line = True
            rows.append((line, "%s | swept %s (ok %s, absent %s) | field evidence: "
                               "%s endpoint(s), %s schema object(s)"
                         % ("in fleet" if L.get("in_fleet") else "NO appliance runs it",
                            c.get("swept", 0), c.get("ok", 0), c.get("absent", 0),
                            c.get("endpoints_with_fields", 0), c.get("schema_objects", 0))))
        if not rows:
            rows = [("(none)", "no firmware line has any evidence")]
            r.worst("warn")
        r.rows("%s — built %s" % (prod, doc.get("built_at") or "?"), rows, keys="plain")
        for note in doc.get("notes") or []:
            r.note("%s: %s excluded — %s"
                   % (prod, note.get("device", "?"), note.get("skipped", "")))
        # A line nobody runs is not a bug, but it IS the reason a preflight
        # against it rests on archived evidence, so it is said out loud.
        for line in sorted(doc.get("lines") or {}):
            if not doc["lines"][line].get("in_fleet"):
                r.note("%s %s: no appliance in the fleet runs this line — its "
                       "evidence is archived, not current" % (prod, line))
    if not any_line:
        r.worst("warn")
    r.note("Compare two lines: the API versions page in each product's API hub.")
    r.set(products=products)
    return r


# ---------------------------------------------------------------------------
# get api preflight
# ---------------------------------------------------------------------------

_USAGE = ["  get api preflight <appliance|line> <object> <field> [<field>...] "
          "[--product <p>]"]


def api_preflight(ctx, args):
    """Would a payload of these fields be understood on that firmware line?

    Answers ``unmeasured`` loudly. The caller's next action is a write to a
    real appliance, so "I have no evidence" must not be reachable from the
    same exit code as "yes".
    """
    args = list(args)
    product = None
    if "--product" in args:
        i = args.index("--product")
        tail = args[i + 1:i + 2]
        if not tail or tail[0] not in PRODUCTS:
            r = Result("bad", "--product needs one of: %s" % ", ".join(PRODUCTS),
                       exit_code=2)
            r.lines("usage", _USAGE)
            return r
        product = tail[0]
        del args[i:i + 2]

    if len(args) < 3:
        r = Result("bad", "preflight needs a target, an object and at least one field",
                   exit_code=2)
        r.lines("usage", _USAGE)
        r.lines("example", ["  get api preflight fortiweb09 admin fortiai old-password"])
        return r

    token, key, fields = args[0], args[1], args[2:]
    candidates = [product] if product else (_known_products(ctx) or list(PRODUCTS))

    doc = line = how = None
    for prod in candidates:
        d = _load(ctx, prod)
        if d is None:
            continue
        ln, hw = _resolve(d, token)
        if hw:
            doc, line, how, product = d, ln, hw, prod
            break

    if doc is None:
        # A token SHAPED like a firmware line is a question about a line SATOM
        # has no evidence for — that is ``unmeasured`` (rc 4), not a usage
        # error (rc 2). Collapsing the two would make \"is 9.0 supported?\" and
        # \"you typed the command wrong\" the same exit code, and the first one
        # is the question somebody asks the week before an upgrade.
        if re.match(r"^\d+\.\d+", token):
            r = Result("warn", "unmeasured — no evidence for line %s" % token,
                       exit_code=4)
            r.lines("what would change this", [
                "  Sweep an appliance running that line (Appliances -> Rediscovery),",
                "  or harvest its field schemas (scripts.build_field_catalog),",
                "  then Rebuild on the API versions page.",
            ])
            r.set(status="unmeasured", line=token)
            return r
        r = Result("bad", "%r is neither a known firmware line nor a known "
                          "appliance" % token, exit_code=2)
        r.lines("why", [
            "  Resolution goes through the matrix's own witness list, so an",
            "  appliance that has never been swept is not resolvable here.",
            "  Name a line (e.g. 7.6) to ask about the line itself.",
        ])
        return r
    if not line:
        r = Result("warn", "unmeasured — %s" % how, exit_code=4)
        r.note("SATOM cannot tell which API surface that appliance serves.")
        return r

    L = (doc.get("lines") or {}).get(line) or {}
    ep = (L.get("endpoints") or {}).get(key)
    obj = (L.get("objects") or {}).get(key)

    r = Result("ok", "preflight %s %s on %s" % (product, key, line))
    r.rows("target", [("resolved", how), ("line", line),
                      ("matrix built", doc.get("built_at") or "?"),
                      ("line in fleet", "yes" if L.get("in_fleet") else
                       "NO — evidence is archived")], keys="plain")

    if ep is None and obj is None:
        r.status = "warn"
        r.rows("verdict", [("status", "unmeasured"),
                           ("reason", "%r was never measured on %s" % (key, line))])
        r._exit = 4
        return r
    if ep is not None and ep.get("verdict") == "absent" and not (obj and obj.get("fields")):
        r.status = "bad"
        r.rows("verdict", [("status", "absent"),
                           ("reason", "%s does not serve %r" % (line, key))])
        return r

    known = set()
    origins = []
    if obj and obj.get("fields"):
        known |= set(obj["fields"])
        origins.append("schema")
    if ep and ep.get("fields"):
        known |= set(ep["fields"])
        origins.append("sweep")
    if not known:
        r.status = "warn"
        r.rows("verdict", [("status", "fields_unknown"),
                           ("reason", "%r exists on %s but answered with an empty "
                                      "collection — nothing is known about its fields"
                            % (key, line))])
        r._exit = 4
        return r

    unknown = [f for f in fields if f not in known]
    ok_fields = [f for f in fields if f in known]
    r.rows("verdict", [
        ("status", "unknown_fields" if unknown else "ok"),
        ("evidence", "+".join(origins)),
        ("known fields on line", str(len(known))),
    ])
    if ok_fields:
        r.lines("understood", ["  " + f for f in ok_fields])
    if unknown:
        r.status = "bad"
        r.lines("NOT present on %s" % line, ["  " + f for f in unknown])
        r.note("Writing these to an appliance on %s is the error this command "
               "exists to catch." % line)
    r.set(status=("unknown_fields" if unknown else "ok"), line=line,
          unknown=unknown, known=ok_fields)
    return r
